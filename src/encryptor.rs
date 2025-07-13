// Encryption
use std::{fs, process};
use std::io;
use std::path::Path;
use num_bigint::{BigUint, ToBigUint};
use num_traits::Num;
use lazy_static::lazy_static;
use rand::{rngs::OsRng, TryRngCore};
use hex;
use cipher::{KeyIvInit, block_padding::Pkcs7, BlockEncryptMut};
use aes::Aes256;
use cbc::Encryptor;

const KEY_SIZE: usize = 32; // 대칭키 크기
const BLOCK_SIZE: usize = 16; // AES Block 크기

// ---
// 1. FieldElement 구조체 및 연산 구현
// ---

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FieldElement {
    pub value: BigUint,
    pub modulus: BigUint,
}

impl FieldElement {
    pub fn new(value: BigUint, modulus: BigUint) -> Self {
        Self { value: value % &modulus, modulus }
    }

    pub fn add(&self, other: &Self) -> Self {
        assert_eq!(self.modulus, other.modulus, "Moduli must match for addition");
        Self::new(&self.value + &other.value, self.modulus.clone())
    }

    pub fn sub(&self, other: &Self) -> Self {
        assert_eq!(self.modulus, other.modulus, "Moduli must match for subtraction");
        let mut result = &self.value + &self.modulus; // 음수 방지
        result = &result - &other.value;
        Self::new(result, self.modulus.clone())
    }

    pub fn mul(&self, other: &Self) -> Self {
        assert_eq!(self.modulus, other.modulus, "Moduli must match for multiplication");
        Self::new(&self.value * &other.value, self.modulus.clone())
    }

    pub fn inverse(&self) -> Option<Self> {
        if self.value == BigUint::from(0u8) {
            return None; // 0은 역원이 없음
        }
        let p_minus_2 = &self.modulus - BigUint::from(2u8);
        Some(Self::new(self.value.modpow(&p_minus_2, &self.modulus), self.modulus.clone()))
    }

    pub fn div(&self, other: &Self) -> Option<Self> {
        if let Some(other_inverse) = other.inverse() {
            Some(self.mul(&other_inverse))
        } else {
            None // 0으로 나누려고 함
        }
    }
}

// ---
// 2. Point 구조체 및 EllipticCurve 구조체 정의
// ---

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Point {
    Coordinates { x: FieldElement, y: FieldElement },
    Identity, // 무한원점 O (Point at Infinity)
}

#[derive(Debug, Clone)]
pub struct EllipticCurve {
    pub p: BigUint, // 유한체의 modulus (소수)
    pub a: FieldElement, // 곡선 계수 A
    pub b: FieldElement, // 곡선 계수 B
    pub g: Point, // 기준점 G
    pub n: BigUint, // G의 위수 (Order)
}

// ---
// 3. EllipticCurve의 연산 구현 (add_points, scalar_multiply)
// ---

impl EllipticCurve {
    pub fn is_on_curve(&self, point: &Point) -> bool {
        match point {
            Point::Identity => true, // 무한원점은 항상 곡선 위에 있다고 간주
            Point::Coordinates { x, y } => {
                let y_squared = y.mul(y);
                let x_cubed = x.mul(x).mul(x);
                let ax = self.a.mul(x);
                let rhs = x_cubed.add(&ax).add(&self.b);
                y_squared == rhs
            }
        }
    }

    pub fn add_points(&self, p: &Point, q: &Point) -> Point {
        match (p, q) {
            (Point::Identity, _) => q.clone(),
            (_, Point::Identity) => p.clone(),

            (Point::Coordinates { x: px, y: py }, Point::Coordinates { x: qx, y: qy })
            if px == qx && py != qy => Point::Identity, // P + (-P) = O

            (Point::Coordinates { x: px, y: py }, Point::Coordinates { x: qx, y: qy })
            if px == qx && py == qy => { // P = Q (2P)
                if py.value == BigUint::from(0u8) {
                    return Point::Identity;
                }

                let three_x_sq = FieldElement::new(BigUint::from(3u8), self.p.clone())
                    .mul(&px.mul(px));
                let numerator = three_x_sq.add(&self.a);
                let two_y = FieldElement::new(BigUint::from(2u8), self.p.clone())
                    .mul(py);
                let slope = numerator.div(&two_y).expect("Inverse of 2y failed in 2P calculation");

                let x3 = slope.mul(&slope).sub(&px).sub(&px);
                let y3 = slope.mul(&px.sub(&x3)).sub(py);
                Point::Coordinates { x: x3, y: y3 }
            },

            (Point::Coordinates { x: px, y: py }, Point::Coordinates { x: qx, y: qy }) => { // P != Q
                let numerator = qy.sub(py);
                let denominator = qx.sub(px);
                let slope = numerator.div(&denominator).expect("Inverse of (x2-x1) failed in P+Q calculation");

                let x3 = slope.mul(&slope).sub(px).sub(qx);
                let y3 = slope.mul(&px.sub(&x3)).sub(py);
                Point::Coordinates { x: x3, y: y3 }
            },
        }
    }

    pub fn scalar_multiply(&self, k: &BigUint, p: &Point) -> Point {
        let mut result = Point::Identity;
        let mut add_point = p.clone();
        let mut k_val = k.clone();

        while k_val > BigUint::from(0u8) {
            if &k_val % BigUint::from(2u8) == BigUint::from(1u8) {
                result = self.add_points(&result, &add_point);
            }
            add_point = self.add_points(&add_point, &add_point);
            k_val /= BigUint::from(2u8);
        }
        result
    }

    pub fn generate_key_pair(&self) -> (BigUint, Point) {
        let mut rng = OsRng;
        let mut private_key_bytes = vec![0u8; ((self.n.bits() + 7) / 8) as usize]; // n의 비트 길이에 맞게 바이트 배열 생성

        let private_key;
        loop {
            rng.try_fill_bytes(&mut private_key_bytes).unwrap();
            let candidate_key = BigUint::from_bytes_be(&private_key_bytes);
            if candidate_key > BigUint::from(0u8) && candidate_key < self.n {
                private_key = candidate_key;
                break;
            }
        }

        let public_key = self.scalar_multiply(&private_key, &self.g);
        (private_key, public_key)
    }

    pub fn ecdh_derive_shared_secret(
        &self,
        private_key: &BigUint,
        other_public_key: &Point,
    ) -> Point {
        self.scalar_multiply(private_key, other_public_key)
    }
}

// ---
// 4. lazy_static! 매크로를 사용하여 ECC 파라미터 전역 상수 정의
// ---

lazy_static! {
    // p (유한체 모듈러스)
    pub static ref P_MODULUS_STR: &'static str = "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F";
    pub static ref P_MODULUS: BigUint = <BigUint as Num>::from_str_radix(*P_MODULUS_STR, 16)
        .expect("Failed to parse P_MODULUS_STR");

    // A (곡선 계수 A)
    pub static ref A_VALUE: BigUint = BigUint::from(0u8);
    pub static ref A_FIELD_ELEMENT: FieldElement = FieldElement::new(
        *A_VALUE.clone(), *P_MODULUS.clone()
    );

    // B (곡선 계수 B)
    pub static ref B_VALUE: BigUint = BigUint::from(7u8);
    pub static ref B_FIELD_ELEMENT: FieldElement = FieldElement::new(
        *B_VALUE.clone(), *P_MODULUS.clone()
    );

    // Gx (기준점 G의 X좌표)
    pub static ref GX_STR: &'static str = "79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798";
    pub static ref GX_FIELD_ELEMENT: FieldElement = FieldElement::new(
        BigUint::from_str_radix(*GX_STR, 16)
            .expect("Failed to parse GX_STR"),
        P_MODULUS.clone()
    );

    // Gy (기준점 G의 Y좌표)
    pub static ref GY_STR: &'static str = "483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8";
    pub static ref GY_FIELD_ELEMENT: FieldElement = FieldElement::new(
        BigUint::from_str_radix(*GY_STR, 16)
            .expect("Failed to parse GY_STR"),
        P_MODULUS.clone()
    );

    // G_POINT (기준점 G)
    pub static ref G_POINT: Point = Point::Coordinates {
        x: GX_FIELD_ELEMENT.clone(),
        y: GY_FIELD_ELEMENT.clone(),
    };

    // n (G의 위수)
    pub static ref N_ORDER_STR: &'static str = "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141";
    pub static ref N_ORDER: BigUint = BigUint::from_str_radix(*N_ORDER_STR, 16)
        .expect("Failed to parse N_ORDER_STR");

    // SECP256K1_CURVE (타원곡선 인스턴스)
    // 이 인스턴스를 통해 모든 ECC 연산 메소드에 접근합니다.
    pub static ref SECP256K1_CURVE: EllipticCurve = EllipticCurve {
        p: P_MODULUS.clone(),
        a: A_FIELD_ELEMENT.clone(),
        b: B_FIELD_ELEMENT.clone(),
        g: G_POINT.clone(),
        n: N_ORDER.clone(),
    };
}



// 파일을 읽어 그 내용의 바이트값을 반환함.
fn read_file_to_bytes_sync(path: &str) -> Result<Vec<u8>, io::Error> {
    fs::read(path)
}

// path에 data(byte)를 씀.
fn write_bytes_to_file_sync(path: &str, data: &[u8]) -> Result<(), io::Error> {
    fs::write(path, data)
}

// main 실행 함수. 코드가 실행되면 이 함수가 실행됨.
fn main() -> Result<(), Box<dyn std::error::Error>> {
    let aes_key = aes_encryption()?;
    ecc_encryption(aes_key)?;

    println!("Select:\n1. Random Integer Generator\n2. Public Key Generator\n3. Encryptor\n");
    let mut initial_input = String::new();
    io::stdin().read_line(&mut initial_input).unwrap();
    initial_input = initial_input.trim().to_owned();
    if &initial_input == "1" {
        rand_generator()?;
    } else if &initial_input == "2" {

    } else if &initial_input == "2" {

    } else {
        eprintln!("Invalid Input. Terminating Program..");
        process::exit(1);
    }



    Ok(())
}

fn rand_generator() -> Result<(), Box<dyn std::error::Error>> {



    println!("a");
    Ok(())
}

// AES-256 암호화 함수. 파일 데이터를 암호화함.
fn aes_encryption() -> Result<[u8; KEY_SIZE], Box<dyn std::error::Error>> {

    // 비밀 키를 생성함.
    let mut key_bytes = [0u8; KEY_SIZE];
    OsRng.try_fill_bytes(&mut key_bytes)?;

    // 초기화 벡터를 생성함.
    let mut iv_bytes = [0u8; BLOCK_SIZE];
    OsRng.try_fill_bytes(&mut iv_bytes)?;

    let mut file_temp_path = String::new();
    println!("Enter the File Path: ");
    io::stdin().read_line(&mut file_temp_path).unwrap();
    let file_original_path_str = file_temp_path.trim().trim_matches('\'');
    let file_original_path = Path::new(file_original_path_str);
    let plain_bytes = read_file_to_bytes_sync(file_original_path_str)?;

    let buffer_len = plain_bytes.len() + BLOCK_SIZE;
    let mut buffer = vec![0u8; buffer_len];
    buffer[..plain_bytes.len()].copy_from_slice(&plain_bytes);

    let cipher = Encryptor::<Aes256>::new(&key_bytes.into(), &iv_bytes.into());

    let ciphertext_bytes = cipher.encrypt_padded_mut::<Pkcs7>(&mut buffer, plain_bytes.len())
        .map_err(|e| format!("Encryption Error: {:?}", e))?;

    println!("\n생성된 암호문 (Hex, without IV): {}", hex::encode(ciphertext_bytes));
    println!("암호문 길이 (패딩 포함): {} 바이트", ciphertext_bytes.len());
    println!("비밀 키: {}", hex::encode(&key_bytes));
    println!("IV: {}", hex::encode(&iv_bytes));

    let mut encrypted_file_content = iv_bytes.to_vec();
    encrypted_file_content.extend_from_slice(ciphertext_bytes);

    println!("IV + 암호문: {}", hex::encode(&encrypted_file_content));

    let output_file_name = format!("{}.aes", file_original_path.file_name().unwrap().to_string_lossy());
    let output_file_path = file_original_path.with_file_name(output_file_name);

    write_bytes_to_file_sync(output_file_path.to_str().unwrap(), &encrypted_file_content)?;

    println!("AES Encryption Complete.");


    Ok(key_bytes)
}

// ECC 암호화 함수. AES 비밀 키를 암호화함.
fn ecc_encryption(key: [u8;KEY_SIZE]) -> Result<(), Box<dyn std::error::Error>> {
    println!("{:?}", key);



    Ok(())
}
