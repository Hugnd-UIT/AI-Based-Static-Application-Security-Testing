use serde_json::Value;

pub fn load_data(data: &[u8]) {
    // Insecure Deserialization [CWE-502]
    let _v: Value = serde_json::from_slice(data).unwrap();
}
