//! Compilador de políticas io_uring → cBPF (`IORING_REGISTER_BPF_FILTER`).
//!
//! *Iouring-policy-cbpf* turns an OCI-like JSON profile (see
//! `fixtures/default.json`, taken from gvozdetsky/iouring-lab) into classic BPF
//! filters the kernel accepts via `IORING_REGISTER_BPF_FILTER` (Linux ≥ 7.0).

pub mod cbpf;
pub mod opcodes;
pub mod policy;
pub mod register;

pub use cbpf::{compile, decide, interpret, BpfCtx, CompiledPolicy, OpcodeFilter, SockFilter};
pub use policy::{DefaultAction, Policy, PolicyError};
pub use register::{probe_register, read_kernel_release, RegisterError};

/// Evaluate every opcode `0..IORING_OP_LAST` with the userspace interpreter and
/// return `(allowed_ok, denied_ok, total_allow, total_deny)`.
pub fn measure_opcode_coverage(policy: &Policy) -> Coverage {
    let compiled = compile(policy);
    let mut allow_ok = 0u32;
    let mut allow_total = 0u32;
    let mut deny_ok = 0u32;
    let mut deny_total = 0u32;

    let socket_op = opcodes::lookup_opcode("IORING_OP_SOCKET").unwrap_or(u32::MAX);
    for op in 0..opcodes::IORING_OP_LAST {
        // For SOCKET, feed an allowed family so the opcode-level allow is measurable.
        let family = if op == socket_op {
            policy.socket_families.first().copied().unwrap_or(0)
        } else {
            0
        };
        let ctx = BpfCtx {
            opcode: op as u8,
            socket_family: family,
            ..BpfCtx::default()
        };
        let expected = policy.allows(op);
        let got = decide(&compiled, &ctx);
        if expected {
            allow_total += 1;
            if got {
                allow_ok += 1;
            }
        } else {
            deny_total += 1;
            if !got {
                deny_ok += 1;
            }
        }
    }
    Coverage {
        allow_ok,
        allow_total,
        deny_ok,
        deny_total,
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Coverage {
    pub allow_ok: u32,
    pub allow_total: u32,
    pub deny_ok: u32,
    pub deny_total: u32,
}

impl Coverage {
    pub fn perfect(&self) -> bool {
        self.allow_ok == self.allow_total && self.deny_ok == self.deny_total
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lab_profile_coverage_is_perfect() {
        let p = Policy::parse_json(include_str!("../fixtures/default.json")).unwrap();
        let c = measure_opcode_coverage(&p);
        assert_eq!(c.allow_total, 38, "lab profile lists 38 ops");
        assert!(c.perfect(), "coverage={c:?}");
    }
}
