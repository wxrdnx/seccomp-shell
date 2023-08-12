use std::io::{self, Write};
use std::error::Error;
use colored::Colorize;

use crate::server;
use crate::config::Config;

pub fn help() {
    println!("
    Core Commands
    =============

        Command       Description
        -------       -----------
        help          Help menu
        server        Establish C&C server
        configure     Shellcode configuration
        revshell      Start reverse shell
        exit          Exit program
");
}

pub fn prompt(config: &mut Config) {
    let ps = ">".bold();

    let stdin = io::stdin();
    let stdout = io::stdout();
    let mut stdout_handle = stdout.lock();
    let mut line = String::new();
    
    write!(stdout_handle, "{} ", ps)?;
    stdout_handle.flush()?;

    while let Ok(bytes_read) = stdin.read_line(&mut line) {
        if bytes_read == 0 {
            break;
        }
        let mut iter = line.trim().split_whitespace();
        if let Some(command) = iter.next() {
            if command == "help" {
                help();
            } else if command == "server" {
                server::prompt(config);
            } else if command == "exit" {
                return;
            }
        } else {
            help();
        }
    }
}
