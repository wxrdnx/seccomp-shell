use colored::Colorize;

pub fn print_info(message: &str) {
    let output = format!("[{}] {}", "*".blue(), message.blue().bold());
    eprintln!("{}", output);
}

pub fn print_success(message: &str) {
    let output = format!("[{}] {}", "+".green(), message.green().bold());
    println!("{}", output);
}

pub fn print_warning(message: &str) {
    let output = format!("[{}] {}", "!".yellow(), message.yellow().bold());
    println!("{}", output);
}

pub fn print_error(message: &str) {
    let output = format!("[{}] {}", "-".red(), message.red().bold());
    eprintln!("{}", output);
}

pub fn print_shellcode_quoted(shellcode: &[u8]) {
    print!("\"");
    for byte in shellcode.iter() {
        print!("\\x{:02x}", byte);
    }
    println!("\"");
}

pub fn print_shellcode_hex(shellcode: &[u8]) {
    for byte in shellcode.iter() {
        print!("{:02x}", byte);
    }
    println!("");
}