// Encryption

#[tokio::main]
async fn main() -> Result<(), Box<std::io::Error>> {
    // let mut file_original_path = String::new();
    // println!("Enter the File Path: ");
    // std::io::stdin().read_line(&mut file_original_path).unwrap();
    // println!("Path: {}", file_original_path);

    let file_path = "asdf.txt";
    let txt = tokio::fs::read_to_string(&file_path).await?;
    println!("File Contents: {}", txt);
    Ok(())
}


