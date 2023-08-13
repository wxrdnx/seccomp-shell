use std::net::{IpAddr, Ipv4Addr};
use syscalls::x86_64::Sysno;
use std::fmt;

#[derive(Debug)]
pub enum ScFmt {
    ScFmtQuoted,
    ScFmtHex,
}

impl fmt::Display for ScFmt {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let text = match self {
            ScFmt::ScFmtQuoted => "quoted",
            ScFmt::ScFmtHex => "hex",
            _ => "quoted",
        };
        text.fmt(f)
    }
}

#[derive(Debug)]
pub struct Config {
    pub connected: bool,
    pub server_host: Ipv4Addr,
    pub server_port: u16,
    pub sc_fmt: ScFmt,
    pub open_syscall: Sysno,
    pub read_syscall: Sysno,
    pub write_syscall: Sysno,
}

impl Config {
    pub fn new() -> Self {
        Config {
            connected: false,
            server_host: Ipv4Addr::new(127, 0, 0, 1),
            server_port: 4444,
            sc_fmt: ScFmt::ScFmtQuoted,
            open_syscall: Sysno::open,
            read_syscall: Sysno::read,
            write_syscall: Sysno::write,
        }
    }
}

pub struct Receiver {
    pub shellcode: &'static [u8],
    pub shellcode_len: usize,
    pub host_index: usize,
    pub port_index: usize,
}