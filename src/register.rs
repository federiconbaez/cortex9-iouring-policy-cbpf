//! Attempt to register cBPF filters with the running kernel.
//!
//! On kernels < 7.0 (no IORING_REGISTER_BPF_FILTER) this returns a hard error.
//! Silent skips are forbidden: callers must treat `Unsupported` as failure in
//! enforcement / CI jobs.

use crate::cbpf::{CompiledPolicy, SockFilter};
use std::io;

/// IORING_REGISTER_BPF_FILTER from uapi (linux 7.0+).
pub const IORING_REGISTER_BPF_FILTER: u32 = 37;

/// IO_URING_BPF_FILTER_DENY_REST
pub const IO_URING_BPF_FILTER_DENY_REST: u32 = 1;

/// IO_URING_BPF_CMD_FILTER
pub const IO_URING_BPF_CMD_FILTER: u16 = 1;

#[derive(Debug)]
pub enum RegisterError {
    /// Kernel has no IORING_REGISTER_BPF_FILTER (expected on 6.x).
    Unsupported {
        kernel: String,
        detail: String,
    },
    Io(io::Error),
    Other(String),
}

impl std::fmt::Display for RegisterError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RegisterError::Unsupported { kernel, detail } => {
                write!(
                    f,
                    "kernel {kernel} does not support IORING_REGISTER_BPF_FILTER: {detail}"
                )
            }
            RegisterError::Io(e) => write!(f, "io: {e}"),
            RegisterError::Other(s) => write!(f, "{s}"),
        }
    }
}

impl std::error::Error for RegisterError {}

pub fn read_kernel_release() -> String {
    std::fs::read_to_string("/proc/sys/kernel/osrelease")
        .unwrap_or_else(|_| "unknown".into())
        .trim()
        .to_string()
}

/// True if osrelease looks like >= 7.0.0 (best-effort; enforcement still probes).
pub fn kernel_maybe_supports_bpf_filter(release: &str) -> bool {
    let major = release
        .split(|c: char| !c.is_ascii_digit())
        .next()
        .and_then(|s| s.parse::<u32>().ok())
        .unwrap_or(0);
    major >= 7
}

/// Probe: create a ring and try IORING_REGISTER_BPF_FILTER with a trivial deny filter.
///
/// Returns Ok(()) only if the kernel accepted the registration. On this box
/// (6.12) this MUST return Err(Unsupported) — never Ok and never a silent skip.
#[cfg(target_os = "linux")]
pub fn probe_register(compiled: &CompiledPolicy) -> Result<(), RegisterError> {
    use std::mem;

    let release = read_kernel_release();

    // io_uring_setup
    #[repr(C)]
    struct Params {
        sq_entries: u32,
        cq_entries: u32,
        flags: u32,
        sq_thread_cpu: u32,
        sq_thread_idle: u32,
        features: u32,
        wq_fd: u32,
        resv: [u32; 3],
        sq_off: [u8; 40],
        cq_off: [u8; 40],
    }

    let mut params: Params = unsafe { mem::zeroed() };
    let ring_fd = unsafe { libc::syscall(libc::SYS_io_uring_setup, 2i32, &mut params as *mut _) };
    if ring_fd < 0 {
        return Err(RegisterError::Io(io::Error::last_os_error()));
    }
    let ring_fd = ring_fd as i32;

    // Build io_uring_bpf / io_uring_bpf_filter for the first compiled filter,
    // or a NOP-deny if empty.
    let (opcode, insns): (u32, Vec<SockFilter>) = if let Some(f) = compiled.filters.first() {
        (f.opcode, f.insns.clone())
    } else {
        (
            0,
            vec![SockFilter {
                code: 0x06, // BPF_RET|BPF_K
                jt: 0,
                jf: 0,
                k: 0,
            }],
        )
    };

    #[repr(C)]
    struct IoUringBpfFilter {
        opcode: u32,
        flags: u32,
        filter_len: u32,
        resv: u32,
        filter_ptr: u64,
        resv2: [u64; 5],
    }
    #[repr(C)]
    struct IoUringBpf {
        cmd_type: u16,
        cmd_flags: u16,
        resv: u32,
        filter: IoUringBpfFilter,
    }

    let flags = if compiled.deny_rest {
        IO_URING_BPF_FILTER_DENY_REST
    } else {
        0
    };

    let arg = IoUringBpf {
        cmd_type: IO_URING_BPF_CMD_FILTER,
        cmd_flags: 0,
        resv: 0,
        filter: IoUringBpfFilter {
            opcode,
            flags,
            filter_len: insns.len() as u32,
            resv: 0,
            filter_ptr: insns.as_ptr() as u64,
            resv2: [0; 5],
        },
    };

    // io_uring_register(fd, opcode, arg, nr_args)
    // SYS_io_uring_register = 427 on x86_64
    let rc = unsafe {
        libc::syscall(
            427, // SYS_io_uring_register
            ring_fd,
            IORING_REGISTER_BPF_FILTER as i64,
            &arg as *const _,
            1i64,
        )
    };
    let err = io::Error::last_os_error();
    unsafe { libc::close(ring_fd) };

    if rc == 0 {
        return Ok(());
    }

    let errno = err.raw_os_error().unwrap_or(0);
    // EINVAL / EOPNOTSUPP / ENOSYS => feature missing
    if matches!(errno, libc::EINVAL | libc::ENOSYS | libc::EOPNOTSUPP)
        || !kernel_maybe_supports_bpf_filter(&release)
    {
        return Err(RegisterError::Unsupported {
            kernel: release,
            detail: format!("io_uring_register(BPF_FILTER) rc={rc} errno={errno} ({err})"),
        });
    }
    Err(RegisterError::Io(err))
}

#[cfg(not(target_os = "linux"))]
pub fn probe_register(_compiled: &CompiledPolicy) -> Result<(), RegisterError> {
    Err(RegisterError::Unsupported {
        kernel: "non-linux".into(),
        detail: "io_uring BPF filters are Linux-only".into(),
    })
}
