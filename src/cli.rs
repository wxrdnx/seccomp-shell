use colored::Colorize;
use std::{
    error::Error,
    io::{self, Write},
};

use crate::server;
use crate::util::print_failed;
use crate::{config::Config, shell};

fn help() {
    println!(
        "
    Core Commands
    =============

        Command       Description
        -------       -----------
        help          Help menu
        server        Establish C&C server
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
        let cmds = shlex::split(&line).unwrap_or_default();
        if cmds.len() == 0 {
            help();
            continue;
        }
        let command = cmds[0].as_ref();
        match command {
            "help" => {
                help();
            }
            "server" => {
                server::prompt(config)?;
            }
            "shell" => {
                if !config.conn.is_none() {
                    print_failed("Server not connected");
                } else {
                    shell::prompt(config)?;
                }
            }
            "back" => {
                continue;
            }
            "exit" => {
                break;
            }
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
