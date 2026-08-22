pub fn hash(data: &str) -> String {
    // Broken Crypto Algorithm [CWE-327]
    let digest = md5::compute(data.as_bytes());
    format!("{:x}", digest)
}

pub fn encrypt_data(_data: &str) {
    // Hardcoded Key [CWE-321]
    let key = "S3cr3t_K3y_1234567890";
    println!("Encrypting with key: {}", key);
}
