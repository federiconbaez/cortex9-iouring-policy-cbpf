//! IORING_OP_* numbers from uapi linux/io_uring.h (mainline as of 2026-10).

use std::collections::HashMap;

/// Last exclusive opcode index (`IORING_OP_LAST`).
pub const IORING_OP_LAST: u32 = 65;

/// Map symbolic opcode names to their numeric values.
pub fn opcode_table() -> HashMap<&'static str, u32> {
    let pairs: &[(&str, u32)] = &[
        ("IORING_OP_NOP", 0),
        ("IORING_OP_READV", 1),
        ("IORING_OP_WRITEV", 2),
        ("IORING_OP_FSYNC", 3),
        ("IORING_OP_READ_FIXED", 4),
        ("IORING_OP_WRITE_FIXED", 5),
        ("IORING_OP_POLL_ADD", 6),
        ("IORING_OP_POLL_REMOVE", 7),
        ("IORING_OP_SYNC_FILE_RANGE", 8),
        ("IORING_OP_SENDMSG", 9),
        ("IORING_OP_RECVMSG", 10),
        ("IORING_OP_TIMEOUT", 11),
        ("IORING_OP_TIMEOUT_REMOVE", 12),
        ("IORING_OP_ACCEPT", 13),
        ("IORING_OP_ASYNC_CANCEL", 14),
        ("IORING_OP_LINK_TIMEOUT", 15),
        ("IORING_OP_CONNECT", 16),
        ("IORING_OP_FALLOCATE", 17),
        ("IORING_OP_OPENAT", 18),
        ("IORING_OP_CLOSE", 19),
        ("IORING_OP_FILES_UPDATE", 20),
        ("IORING_OP_STATX", 21),
        ("IORING_OP_READ", 22),
        ("IORING_OP_WRITE", 23),
        ("IORING_OP_FADVISE", 24),
        ("IORING_OP_MADVISE", 25),
        ("IORING_OP_SEND", 26),
        ("IORING_OP_RECV", 27),
        ("IORING_OP_OPENAT2", 28),
        ("IORING_OP_EPOLL_CTL", 29),
        ("IORING_OP_SPLICE", 30),
        ("IORING_OP_PROVIDE_BUFFERS", 31),
        ("IORING_OP_REMOVE_BUFFERS", 32),
        ("IORING_OP_TEE", 33),
        ("IORING_OP_SHUTDOWN", 34),
        ("IORING_OP_RENAMEAT", 35),
        ("IORING_OP_UNLINKAT", 36),
        ("IORING_OP_MKDIRAT", 37),
        ("IORING_OP_SYMLINKAT", 38),
        ("IORING_OP_LINKAT", 39),
        ("IORING_OP_MSG_RING", 40),
        ("IORING_OP_FSETXATTR", 41),
        ("IORING_OP_SETXATTR", 42),
        ("IORING_OP_FGETXATTR", 43),
        ("IORING_OP_GETXATTR", 44),
        ("IORING_OP_SOCKET", 45),
        ("IORING_OP_URING_CMD", 46),
        ("IORING_OP_SEND_ZC", 47),
        ("IORING_OP_SENDMSG_ZC", 48),
        ("IORING_OP_READ_MULTISHOT", 49),
        ("IORING_OP_WAITID", 50),
        ("IORING_OP_FUTEX_WAIT", 51),
        ("IORING_OP_FUTEX_WAKE", 52),
        ("IORING_OP_FUTEX_WAITV", 53),
        ("IORING_OP_FIXED_FD_INSTALL", 54),
        ("IORING_OP_FTRUNCATE", 55),
        ("IORING_OP_BIND", 56),
        ("IORING_OP_LISTEN", 57),
        ("IORING_OP_RECV_ZC", 58),
        ("IORING_OP_EPOLL_WAIT", 59),
        ("IORING_OP_READV_FIXED", 60),
        ("IORING_OP_WRITEV_FIXED", 61),
        ("IORING_OP_PIPE", 62),
        ("IORING_OP_NOP128", 63),
        ("IORING_OP_URING_CMD128", 64),
    ];
    pairs.iter().copied().collect()
}

pub fn lookup_opcode(name: &str) -> Option<u32> {
    opcode_table().get(name).copied()
}

/// IOSQE_* flag bits (uapi).
pub mod sqe_flags {
    pub const FIXED_FILE: u8 = 1 << 0;
    pub const IO_DRAIN: u8 = 1 << 1;
    pub const IO_LINK: u8 = 1 << 2;
    pub const IO_HARDLINK: u8 = 1 << 3;
    pub const ASYNC: u8 = 1 << 4;
    pub const BUFFER_SELECT: u8 = 1 << 5;
    pub const CQE_SKIP_SUCCESS: u8 = 1 << 6;

    pub fn parse(name: &str) -> Option<u8> {
        match name {
            "IOSQE_FIXED_FILE" => Some(FIXED_FILE),
            "IOSQE_IO_DRAIN" => Some(IO_DRAIN),
            "IOSQE_IO_LINK" => Some(IO_LINK),
            "IOSQE_IO_HARDLINK" => Some(IO_HARDLINK),
            "IOSQE_ASYNC" => Some(ASYNC),
            "IOSQE_BUFFER_SELECT" => Some(BUFFER_SELECT),
            "IOSQE_CQE_SKIP_SUCCESS" => Some(CQE_SKIP_SUCCESS),
            _ => None,
        }
    }
}

/// AF_* family numbers used by the SOCKET PDU.
pub mod families {
    pub fn parse(name: &str) -> Option<u32> {
        match name {
            "AF_UNIX" | "AF_LOCAL" => Some(1),
            "AF_INET" => Some(2),
            "AF_INET6" => Some(10),
            "AF_NETLINK" => Some(16),
            "AF_PACKET" => Some(17),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn msg_ring_is_40() {
        assert_eq!(lookup_opcode("IORING_OP_MSG_RING"), Some(40));
    }

    #[test]
    fn socket_is_45() {
        assert_eq!(lookup_opcode("IORING_OP_SOCKET"), Some(45));
    }

    #[test]
    fn last_is_65() {
        assert_eq!(IORING_OP_LAST, 65);
        assert!(opcode_table().values().all(|&v| v < IORING_OP_LAST));
    }
}
