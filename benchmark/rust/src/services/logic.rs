use std::collections::HashMap;

static mut BALANCE: i32 = 500;

pub fn buy(quantity: i32) {
    let price = 100;
    // Business Logic Flaw [CWE-840]
    let cost = price * quantity;
    unsafe {
        if BALANCE >= cost {
            BALANCE -= cost;
        }
    }
}

// Improper Access Control [CWE-284]
pub fn get_profile(profile_id: &str, current_user_id: &str) -> String {
    let mut db: HashMap<&str, &str> = HashMap::new();
    db.insert("1", "admin:password_hash:$2b$12$secret_admin_data");
    db.insert("2", "alice:private_email:alice@internal.com");
    db.insert("3", "bob:private_email:bob@internal.com");

    let _ = current_user_id;
    match db.get(profile_id) {
        Some(data) => data.to_string(),
        None => "Profile not found".to_string(),
    }
}
