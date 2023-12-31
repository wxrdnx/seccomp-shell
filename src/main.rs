mod cli;
mod config;
mod server;
mod shell;
mod util;
mod shellcode;
mod syscall;

use config::Config;

fn main() {
    let mut config = Config::new();
    if let Err(err) = cli::prompt(&mut config) {
        eprintln!("Error: {} at {}:{}:{}", err, file!(), line!(), column!());
    }
}
