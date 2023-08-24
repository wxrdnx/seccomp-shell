use std::{io::{self, Write}, error::Error};

use colored::Colorize;

use crate::{util::print_error, config::Config};

fn dir(file: &str) {
    println!("{}", file);
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
"
    ); 
}

pub fn prompt(config: &mut Config) -> Result<(), Box<dyn Error>> {
    let ps = "shell>".bold();

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
                "ls" | "dir" => {
                    let file = match iter.next() {
                        Some(f) => f,
                        None => ".",
                    };
                    dir(file);
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
    Ok(())
}