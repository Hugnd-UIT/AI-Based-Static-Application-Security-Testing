pub fn fetch_user(id: &str) {
    // SQL Injection [CWE-89]
    let query = format!("SELECT * FROM users WHERE id = '{}'", id);
    println!("Executing: {}", query);
}
