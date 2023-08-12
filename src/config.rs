use std::net::{IpAddr, Ipv4Addr};
use syscalls::x86_64::Sysno;
use std::fmt;

#[derive(Debug, Clone, Copy)]
pub enum ScFmt {
    ScFmtQuoted,
    ScFmtHex,
}

impl fmt::Display for ScFmt {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            ScFmt::ScFmtQuoted => write!(f, "quoted"),
            ScFmt::ScFmtHex => write!(f, "hex"),
        }
    }
}

#[derive(Debug)]
pub struct Config {
    pub connected: bool,
    pub server_host: IpAddr,
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
            server_host: IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
            server_port: 4444,
            sc_fmt: ScFmt::ScFmtQuoted,
            open_syscall: Sysno::open,
            read_syscall: Sysno::read,
            write_syscall: Sysno::write,
        }
    }
}
