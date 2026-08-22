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

pub fn profile(profile_id: &str) -> String {
    // Improper Access Control [CWE-284]
    format!("Showing profile for {}", profile_id)
}
