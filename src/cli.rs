use colored::Colorize;
use std::{error::Error, io::{self, Write}};

use crate::config::Config;
use crate::server;
use crate::util::{print_error};

fn help() {
    println!(
        "
    Core Commands
    =============

        Command       Description
        -------       -----------
        help          Help menu
        server        Establish C&C server
        configure     Shellcode configuration
        revshell      Start reverse shell
        exit          Exit program
"
    );
}

fn help_e(message: &str) {
    print_error(message);
    help();
}

pub fn prompt(config: &mut Config) -> Result<(), Box<dyn Error>> {
    let ps = ">".bold();

    let stdin = io::stdin();
    let stdout = io::stdout();
    let mut stdout_handle = stdout.lock();

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
            } else if command == "server" {
                server::prompt(config);
            } else if command == "exit" {
                break;
            } else {
                let message = format!("Unknown command {}", command);
                help_e(&message);
            }
        } else {
            help();
        }
    }
    Ok(())
}
