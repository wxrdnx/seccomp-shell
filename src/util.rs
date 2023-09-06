use std::{net::Shutdown, error::Error, fs::File, io::Read};

use colored::Colorize;
use rand::{thread_rng, Rng, distributions::Alphanumeric};

use crate::config::Config;

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

pub fn print_failed(message: &str) {
    let output = format!("[{}] {}", "-".red(), message.red().bold());
    eprintln!("{}", output);
}

pub fn print_error(err: Box<dyn Error>) {
    let message = format!("Error: {}", err);
    print_failed(&message);
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

pub fn close_connection(config: &mut Config) {
    if config.conn.is_some() {
        config.conn.as_ref().unwrap().shutdown(Shutdown::Both).unwrap_or_default();
        config.conn = None;
    }
    print_info("Server closed");
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

pub fn gen_random_filename(original_name: &str) -> String {
    let rand_stream: Vec<u8> = thread_rng().sample_iter(&Alphanumeric).take(10).collect();
    let rand_string = String::from_utf8_lossy(&rand_stream);
    format!("/tmp/{}_{}", original_name, rand_string)
}

pub fn read_bytes_from_file(file_name: &str) -> Result<Vec<u8>, Box<dyn Error>> {
    let payload_file = File::open(file_name);
    if let Err(err) = payload_file {
        let message = format!("cannot access file '{}': {}", file_name, err);
        return Err(message.into());
    }
    let mut payload: Vec<u8> = Vec::new();
    payload_file.unwrap().read_to_end(&mut payload)?;

    Ok(payload)
}