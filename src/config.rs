use std::net::{Ipv4Addr, TcpStream};
use syscalls::x86_64::Sysno;
use std::fmt;

use crate::syscall::SYS_READ;

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
        };
        text.fmt(f)
    }
}

#[derive(Debug)]
pub struct Syscall {
    pub sysno: Sysno,
}

impl Syscall {
    pub fn new(sysno: Sysno) -> Self {
        Self { sysno }
    }
}

impl fmt::Display for Syscall {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let text = match self.sysno {
            Sysno::read => "SYS_read",
            Sysno::recvfrom => "SYS_recvfrom",
            _ => "SYS_read",
        };
        text.fmt(f)
    }
}

#[derive(Debug)]
pub struct Config {
    pub server_host: Ipv4Addr,
    pub server_port: u16,
    pub sc_fmt: ScFmt,
    pub conn: Option<TcpStream>,
    pub open_syscall: Syscall,
    pub read_syscall: Syscall,
    pub write_syscall: Syscall,
}

impl Config {
    pub fn new() -> Self {
        Self {
            server_host: Ipv4Addr::new(127, 0, 0, 1),
            server_port: 4444,
            sc_fmt: ScFmt::ScFmtQuoted,
            conn: None,
            open_syscall: Syscall::new(Sysno::open),
            read_syscall: SYS_READ,
            write_syscall: Syscall::new(Sysno::write),
        }
    }
}

pub struct Receiver {
    pub shellcode: &'static [u8],
    pub shellcode_len: usize,
    pub host_index: usize,
    pub port_index: usize,
}

pub struct DirSender {
    pub shellcode: &'static [u8],
    pub dir_len_index: usize,
}

pub struct CatSender {
    pub shellcode: &'static [u8],
    pub file_len_index: usize,
}

pub struct CdSender {
    pub shellcode: &'static [u8],
    pub file_len_index: usize,
}

pub struct PwdSender {
    pub shellcode: &'static [u8],
}

pub struct UploadSender {
    pub shellcode: &'static [u8],
    pub file_len_index: usize,
    pub perm_index: usize,
}

pub struct RmSender {
    pub shellcode: &'static [u8],
    pub file_len_index: usize,
}

pub struct MvSender {
    pub shellcode: &'static [u8],
    pub source_file_len_index: usize,
    pub dest_file_len_index: usize,
}

pub struct CpSender {
    pub shellcode: &'static [u8],
    pub source_file_len_index: usize,
    pub dest_file_len_index: usize,
    pub perm_index: usize,
}

pub struct MkdirSender {
    pub shellcode: &'static [u8],
    pub dir_len_index: usize,
    pub perm_index: usize,
}

pub struct RmdirSender {
    pub shellcode: &'static [u8],
    pub file_len_index: usize,
}

pub struct GetuidSender {
    pub shellcode: &'static [u8],
}

pub struct GetgidSender {
    pub shellcode: &'static [u8],
}
pub struct TcpScanner {
    pub shellcode: &'static [u8],
}

pub struct NetcatEscaper {
    pub shellcode: &'static [u8],
    pub port_index: usize,
    pub payload_length_index0: usize,
    pub payload_length_index1: usize,
}

pub struct FlagChecker {
    pub shellcode: &'static [u8],
    pub flag_index: usize,
    pub encoded_index: usize,
}
