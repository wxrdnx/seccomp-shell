use colored::Colorize;
use std::{error::Error, io::{self, Write}};

use crate::{config::Config, shell};
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
        shell         Start reverse shell
        exit          Exit program
"
    );
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
            match command {
                "help" => {
                    help();
                },
                "server" => {
                    server::prompt(config)?;
                },
                "shell" => {
                    if !config.connected {
                        print_error("Server not connected");
                    } else {
                        shell::prompt(config)?;
                    }
                },
                "back" => {
                    continue;
                },
                "exit" => {
                    break;
                },
                _ => {
                    let message = format!("Unknown command {}", command);
                    print_error(&message);
                    help();
                },
            };
        } else {
            help();
        }
    }
    Ok(())
}
