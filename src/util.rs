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

pub fn colorized_file(file_name: &str, d_type: u8) -> String {
    match d_type {
        0 => { // DT_UNKNOWN
            file_name.to_string()
        }
        1 => { // DT_FIFO
            file_name.yellow().on_black().to_string()
        },
        2 => { // DT_CHR
            file_name.yellow().bold().to_string()
        },
        4 => { // DT_DIR
            file_name.blue().bold().to_string()
        },
        6 => { // DT_BLK
            file_name.yellow().bold().to_string()
        },
        8 => { // DT_REG
            file_name.to_string()
        },
        10 => { // DT_LNK
            file_name.cyan().bold().to_string()
        }
        12 => { // DT_SOCK
            file_name.magenta().bold().to_string()
        },
        14 => { // DT_WHT
            file_name.to_string()
        },
        _ => {
            file_name.to_string()
        }
    }
}