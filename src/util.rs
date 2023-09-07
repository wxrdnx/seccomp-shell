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

pub const SHUFFLES: [[usize; 64]; 8] = [
    [47, 27, 10, 37, 4, 20, 52, 56, 12, 2, 44, 3, 34, 16, 16, 23, 16, 42, 38, 1, 4, 15, 12, 21, 6, 12, 11, 1, 5, 26, 2, 6, 3, 17, 24, 1, 22, 10, 5, 19, 15, 19, 12, 19, 6, 6, 6, 16, 2, 4, 13, 8, 6, 6, 0, 2, 4, 4, 5, 3, 1, 1, 1, 0],
    [33, 15, 9, 24, 38, 48, 50, 19, 37, 24, 49, 25, 24, 21, 4, 18, 17, 23, 39, 3, 10, 11, 38, 38, 5, 4, 26, 24, 20, 4, 15, 23, 13, 5, 14, 20, 0, 10, 23, 3, 20, 6, 18, 18, 5, 4, 13, 13, 4, 0, 9, 12, 4, 6, 4, 5, 6, 1, 1, 0, 1, 2, 1, 0],
    [57, 12, 61, 13, 38, 24, 38, 35, 49, 28, 14, 1, 0, 50, 38, 14, 7, 36, 21, 1, 0, 9, 9, 26, 23, 3, 15, 11, 35, 5, 31, 17, 15, 4, 2, 0, 21, 15, 15, 16, 2, 21, 8, 1, 3, 0, 14, 14, 4, 11, 3, 1, 8, 5, 8, 3, 2, 2, 4, 4, 1, 0, 0, 0],
    [4, 32, 11, 46, 12, 25, 13, 41, 6, 31, 19, 28, 20, 29, 41, 38, 24, 30, 30, 4, 26, 11, 38, 2, 7, 3, 17, 3, 12, 1, 1, 12, 14, 19, 20, 22, 23, 8, 25, 16, 12, 10, 11, 4, 14, 2, 5, 0, 7, 4, 0, 6, 9, 1, 1, 1, 2, 2, 1, 3, 3, 0, 1, 0],
    [58, 46, 11, 14, 11, 15, 47, 0, 43, 12, 22, 21, 27, 1, 22, 11, 46, 40, 21, 19, 37, 15, 5, 35, 35, 10, 9, 21, 1, 10, 24, 11, 30, 28, 3, 16, 6, 5, 10, 14, 15, 18, 14, 3, 8, 0, 10, 0, 12, 1, 4, 4, 5, 3, 2, 4, 6, 0, 3, 1, 1, 1, 1, 0],
    [59, 18, 23, 18, 13, 9, 14, 9, 43, 36, 36, 17, 20, 17, 38, 44, 21, 16, 33, 15, 17, 14, 2, 22, 17, 34, 28, 1, 3, 20, 15, 24, 17, 12, 0, 12, 23, 4, 15, 4, 16, 15, 2, 16, 8, 12, 3, 1, 3, 6, 5, 6, 1, 6, 2, 7, 0, 4, 3, 2, 3, 1, 1, 0],
    [9, 57, 10, 23, 40, 50, 48, 27, 27, 38, 5, 2, 13, 27, 32, 3, 41, 36, 34, 42, 23, 32, 21, 39, 31, 12, 4, 9, 23, 31, 19, 18, 12, 21, 28, 11, 22, 5, 19, 22, 13, 10, 18, 10, 14, 17, 4, 3, 3, 3, 8, 4, 5, 5, 0, 2, 6, 4, 3, 3, 3, 1, 1, 0],
    [14, 33, 22, 59, 10, 57, 2, 16, 49, 29, 11, 11, 41, 27, 19, 3, 25, 8, 29, 16, 26, 11, 1, 9, 17, 31, 28, 21, 6, 3, 31, 19, 27, 11, 25, 17, 24, 6, 3, 20, 20, 13, 11, 20, 9, 13, 11, 1, 11, 8, 9, 6, 7, 1, 5, 4, 6, 5, 1, 0, 1, 0, 0, 0],
];

#[inline(always)]
pub fn shuffle(data: &mut [u8]) {
    for shuffle in SHUFFLES {
        for i in 0..64 {
            data.swap(63 - i, shuffle[i]);
        }
    }
}

#[inline(always)]
pub fn substitute(data: &mut [u8]) {
    data.iter_mut().for_each(|n| {
        let mut mn = (257, (*n as i16) + 1);
        let mut xy = (0, 1);
        
        while mn.1 != 0 {
            xy = (xy.1, xy.0 - (mn.0 / mn.1) * xy.1);
            mn = (mn.1, mn.0 % mn.1);
        }
        
        while xy.0 < 0 {
            xy.0 += 257;
        }
        *n = (((xy.0 + 113) % 256) ^ 137) as u8;
    });
}