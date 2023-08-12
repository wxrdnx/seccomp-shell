use colored::Colorize;

pub fn print_success(message: &str) {
    let output = format!("[{}] {}", "+".green(), message);
    println!("{}", output);
}

pub fn print_warning(message: &str) {
    let output = format!("[{}] {}", "+".yellow(), message);
    println!("{}", output);
}

pub fn print_error(message: &str) {
    let output = format!("[{}] {}", "+".red(), message);
    eprintln!("{}", output);
}