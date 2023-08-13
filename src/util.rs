use colored::Colorize;

use crate::config::ScFmt;

pub fn print_info(message: &str) {
    let output = format!("[{}] {}", "*".blue(), message);
    eprintln!("{}", output);
}

pub fn print_success(message: &str) {
    let output = format!("[{}] {}", "+".green(), message);
    println!("{}", output);
}

pub fn print_warning(message: &str) {
    let output = format!("[{}] {}", "!".yellow(), message);
    println!("{}", output);
}

pub fn print_error(message: &str) {
    let output = format!("[{}] {}", "-".red(), message);
    eprintln!("{}", output);
}

pub fn print_shellcode_quoted(shellcode: &[u8]) {
    print!("\"");
    for byte in shellcode.iter() {
        print!("\\{:02x}", byte);
    }
    print!("\"");
}

pub fn print_shellcode_hex(shellcode: &[u8]) {
    for byte in shellcode.iter() {
        print!("{:02x}", byte);
    }
}