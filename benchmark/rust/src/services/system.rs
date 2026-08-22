use std::process::Command;

pub fn run_ping(ip: &str) {
    // Command Injection [CWE-78]
    let cmd = format!("ping -c 4 {}", ip);
    Command::new("sh").arg("-c").arg(cmd).output().unwrap();
}
