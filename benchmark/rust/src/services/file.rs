use std::fs;

pub fn read(filename: &str) -> String {
    // Path Traversal [CWE-22]
    let path = format!("/var/www/uploads/{}", filename);
    fs::read_to_string(path).unwrap_or_default()
}
