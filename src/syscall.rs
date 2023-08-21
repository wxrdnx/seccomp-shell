use syscalls::Sysno;
use crate::config::Syscall;

pub const SYS_READ: Syscall = Syscall {
    sysno: Sysno::read
};
pub const SYS_RECVFROM: Syscall = Syscall {
    sysno: Sysno::recvfrom
};