// Encryption
use std::fs;
use std::io;
use aes::Aes256;
use cipher::{KeyIvInit, block_padding::Pkcs7, BlockEncryptMut};
use cbc::Encryptor;
use rand::{rngs::OsRng, TryRngCore};
use hex;
use std::path::Path;


const KEY_SIZE: usize = 32; // 대칭키 크기
const BLOCK_SIZE: usize = 16; // AES Block 크기

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
    aes_encription()?;
    Ok(())
}

// AES-256 암호화 함수. 파일 데이터를 암호화함.
fn aes_encription() -> Result<(), Box<dyn std::error::Error>> {

    // 비밀 키를 생성함.
    let mut key_bytes = [0u8; KEY_SIZE];
    OsRng.try_fill_bytes(&mut key_bytes)?;
    println!("비밀 키: {}", hex::encode(&key_bytes));

    // 초기화 벡터를 생성함.
    let mut iv_bytes = [0u8; BLOCK_SIZE];
    OsRng.try_fill_bytes(&mut iv_bytes)?;
    // println!("{}", hex::encode(&iv_bytes));

    let mut file_temp_path = String::new();
    println!("Enter the File Path: ");
    io::stdin().read_line(&mut file_temp_path).unwrap();
    let file_original_path_str = file_temp_path.trim().trim_matches('\'');
    let file_original_path = Path::new(file_original_path_str);
    // println!("Path: {}", file_original_path);
    let plain_bytes = read_file_to_bytes_sync(file_original_path_str)?;

    let buffer_len = plain_bytes.len() + BLOCK_SIZE;
    let mut buffer = vec![0u8; buffer_len];
    buffer[..plain_bytes.len()].copy_from_slice(&plain_bytes);

    let cipher = Encryptor::<Aes256>::new(&key_bytes.into(), &iv_bytes.into());

    let ciphertext_bytes = cipher.encrypt_padded_mut::<Pkcs7>(&mut buffer, plain_bytes.len())
        .map_err(|e| format!("Encryption Error: {:?}", e))?;

    println!("\n생성된 암호문 (Hex): {}", hex::encode(&ciphertext_bytes)); // (1)
    println!("암호문 길이 (패딩 포함): {} 바이트", ciphertext_bytes.len());

    let mut encrypted_file_content = iv_bytes.to_vec();
    encrypted_file_content.extend_from_slice(ciphertext_bytes); // 만약 (1)에서 &가 빠지면, hex::encode로 value가 이동하므로 이 line에서 해당 변수를 사용할 수 없음. 소유권을 제대로 이해할 수 있는 코드임.

    println!("{}", hex::encode(&encrypted_file_content));

    let output_file_name = format!("{}.aes", file_original_path.file_name().unwrap().to_string_lossy());
    let output_file_path = file_original_path.with_file_name(output_file_name);

    write_bytes_to_file_sync(output_file_path.to_str().unwrap(), &encrypted_file_content)?;

    println!("Complete.");


    Ok(())
}


