mod cli;
mod config;
mod server;
mod util;

use config::Config;

fn main() {
    let mut config = Config::new();
    let mut line = String::new();
    cli::prompt(&mut config);
}
