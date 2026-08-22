pub fn process_data(data: &[u8]) {
    // Memory Corruption [CWE-119]
    unsafe {
        let ptr = data.as_ptr();
        let val = *ptr.offset(1000);
        println!("Value: {}", val);
    }
}
