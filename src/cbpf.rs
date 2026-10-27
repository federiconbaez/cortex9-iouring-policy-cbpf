//! Classic BPF (cBPF) instruction helpers, emitter and userspace interpreter.
//!
//! Layout of `struct io_uring_bpf_ctx` (uapi):
//!   offset 0:  user_data  u64
//!   offset 8:  opcode u8 | sqe_flags u8 | pdu_size u8 | pad
//!   offset 16: union { socket { family u32, type u32, protocol u32 }, ... }
//!
//! Filter return: 0 = deny, nonzero = allow (kernel runs bpf_prog_run).

use crate::opcodes::{lookup_opcode, IORING_OP_LAST};
use crate::policy::Policy;

/// One classic BPF instruction (`struct sock_filter`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(C)]
pub struct SockFilter {
    pub code: u16,
    pub jt: u8,
    pub jf: u8,
    pub k: u32,
}

impl SockFilter {
    pub const fn new(code: u16, jt: u8, jf: u8, k: u32) -> Self {
        Self { code, jt, jf, k }
    }
}

// BPF class / size / mode bits (linux/filter.h / linux/bpf_common.h)
const BPF_LD: u16 = 0x00;
const BPF_LDX: u16 = 0x01;
const BPF_ALU: u16 = 0x04;
const BPF_JMP: u16 = 0x05;
const BPF_RET: u16 = 0x06;
const BPF_W: u16 = 0x00;
const BPF_ABS: u16 = 0x20;
const BPF_IMM: u16 = 0x00;
const BPF_K: u16 = 0x00;
const BPF_JA: u16 = 0x00;
const BPF_JEQ: u16 = 0x10;
const BPF_JSET: u16 = 0x40;
const BPF_AND: u16 = 0x50;
const BPF_RSH: u16 = 0x70;

/// Offsets into `io_uring_bpf_ctx` (32-bit aligned loads only).
pub const OFF_OPCODE_WORD: u32 = 8; // low byte = opcode, next = sqe_flags
pub const OFF_SOCKET_FAMILY: u32 = 16;

/// A filter bound to one opcode, ready for IORING_REGISTER_BPF_FILTER.
#[derive(Debug, Clone)]
pub struct OpcodeFilter {
    pub opcode: u32,
    pub insns: Vec<SockFilter>,
}

/// Full compilation result.
#[derive(Debug, Clone)]
pub struct CompiledPolicy {
    pub filters: Vec<OpcodeFilter>,
    /// Corresponds to IO_URING_BPF_FILTER_DENY_REST.
    pub deny_rest: bool,
    /// Opcodes that have no filter and will be denied when deny_rest is set.
    pub denied_by_rest: Vec<u32>,
}

/// Emit per-opcode allow filters (+ optional sqe_flags / socket family checks).
pub fn compile(policy: &Policy) -> CompiledPolicy {
    let mut filters = Vec::new();
    for &opcode in &policy.allow_opcodes {
        let insns = emit_allow_filter(opcode, policy);
        filters.push(OpcodeFilter { opcode, insns });
    }
    // Explicit deny under default-allow: emit a constant-deny filter.
    if !policy.deny_rest() {
        for &opcode in &policy.deny_opcodes {
            filters.push(OpcodeFilter {
                opcode,
                insns: vec![SockFilter::new(BPF_RET | BPF_K, 0, 0, 0)],
            });
        }
    }

    let mut denied_by_rest = Vec::new();
    if policy.deny_rest() {
        for op in 0..IORING_OP_LAST {
            if !policy.allow_opcodes.contains(&op) {
                denied_by_rest.push(op);
            }
        }
    }

    CompiledPolicy {
        filters,
        deny_rest: policy.deny_rest(),
        denied_by_rest,
    }
}

fn emit_allow_filter(opcode: u32, policy: &Policy) -> Vec<SockFilter> {
    let mut insns = Vec::new();

    // Optional: deny if any forbidden SQE flag bit is set.
    // Word at OFF_OPCODE_WORD: bits[15:8] = sqe_flags.
    if policy.denied_sqe_flags != 0 {
        let mask = (policy.denied_sqe_flags as u32) << 8;
        insns.push(SockFilter::new(
            BPF_LD | BPF_W | BPF_ABS,
            0,
            0,
            OFF_OPCODE_WORD,
        ));
        // A = word; JSET mask -> deny
        // BPF_JMP|BPF_JSET|BPF_K: if (A & k) jt else jf
        // We'll append RET 0 / RET 1 at the end; use forward jumps with placeholders.
        // Pattern:
        //   LD ABS 8
        //   JSET mask, 0, 1   ; if set, fall through to RET 0; else skip to continue
        //   RET 0
        //   ... rest ...
        insns.push(SockFilter::new(BPF_JMP | BPF_JSET | BPF_K, 0, 1, mask));
        insns.push(SockFilter::new(BPF_RET | BPF_K, 0, 0, 0));
    }

    // For SOCKET: allow only listed families (if the list is non-empty).
    let socket_op = lookup_opcode("IORING_OP_SOCKET").unwrap();
    if opcode == socket_op && !policy.socket_families.is_empty() {
        insns.push(SockFilter::new(
            BPF_LD | BPF_W | BPF_ABS,
            0,
            0,
            OFF_SOCKET_FAMILY,
        ));
        // Chain of JEQ family -> allow; final RET 0
        let n = policy.socket_families.len();
        for (i, &fam) in policy.socket_families.iter().enumerate() {
            // if A == fam -> jump to RET 1, which will sit after the chain + RET 0
            // remaining JEQ insns: (n - 1 - i), then RET 0 (1), then RET 1
            let jf_to_next = 0u8; // fall to next JEQ / RET 0
            let jt_to_allow = (n - 1 - i) as u8 + 1; // skip remaining + RET 0
            insns.push(SockFilter::new(
                BPF_JMP | BPF_JEQ | BPF_K,
                jt_to_allow,
                jf_to_next,
                fam,
            ));
        }
        insns.push(SockFilter::new(BPF_RET | BPF_K, 0, 0, 0)); // deny unknown family
        insns.push(SockFilter::new(BPF_RET | BPF_K, 0, 0, 1)); // allow
        return insns;
    }

    insns.push(SockFilter::new(BPF_RET | BPF_K, 0, 0, 1)); // allow
    insns
}

/// Simulated `io_uring_bpf_ctx` for the userspace interpreter.
#[derive(Debug, Clone, Copy, Default)]
pub struct BpfCtx {
    pub user_data: u64,
    pub opcode: u8,
    pub sqe_flags: u8,
    pub pdu_size: u8,
    pub socket_family: u32,
    pub socket_type: u32,
    pub socket_protocol: u32,
}

impl BpfCtx {
    fn load_word(&self, off: u32) -> Option<u32> {
        match off {
            0 => Some((self.user_data & 0xffff_ffff) as u32),
            4 => Some((self.user_data >> 32) as u32),
            8 => Some(
                self.opcode as u32
                    | ((self.sqe_flags as u32) << 8)
                    | ((self.pdu_size as u32) << 16),
            ),
            12 => Some(0), // pad
            16 => Some(self.socket_family),
            20 => Some(self.socket_type),
            24 => Some(self.socket_protocol),
            _ => None,
        }
    }
}

/// Run a classic BPF program against a ctx. Returns the RET value (0 deny, 1 allow).
pub fn interpret(insns: &[SockFilter], ctx: &BpfCtx) -> Result<u32, String> {
    let mut a: u32 = 0;
    let mut x: u32 = 0;
    let mut pc: usize = 0;
    let mut steps = 0usize;
    while pc < insns.len() {
        steps += 1;
        if steps > 4096 {
            return Err("interpreter step limit".into());
        }
        let insn = insns[pc];
        let code = insn.code;
        let class = code & 0x07;
        match class {
            c if c == BPF_RET => {
                let k_mode = code & 0x18;
                // BPF_K = 0x00, BPF_A = 0x10
                let val = if k_mode == 0x00 { insn.k } else { a };
                return Ok(val);
            }
            c if c == BPF_LD || c == BPF_LDX => {
                let size = code & 0x18;
                let mode = code & 0xe0;
                if size != BPF_W {
                    return Err(format!("unsupported LD size {size:#x}"));
                }
                let val = if mode == BPF_ABS {
                    ctx.load_word(insn.k)
                        .ok_or_else(|| format!("OOB load at {}", insn.k))?
                } else if mode == BPF_IMM {
                    insn.k
                } else {
                    return Err(format!("unsupported LD mode {mode:#x}"));
                };
                if class == BPF_LD {
                    a = val;
                } else {
                    x = val;
                }
                pc += 1;
            }
            c if c == BPF_ALU => {
                let op = code & 0xf0;
                let src = code & 0x08; // 0 = K, 8 = X
                let rhs = if src == 0 { insn.k } else { x };
                match op {
                    BPF_AND => a &= rhs,
                    BPF_RSH => a >>= rhs,
                    0x00 => a += rhs, // ADD
                    0x10 => a = a.wrapping_sub(rhs),
                    0x20 => a = a.wrapping_mul(rhs),
                    0x40 => a |= rhs,
                    0xa0 => a ^= rhs,
                    0xb0 => a = !a,
                    _ => return Err(format!("unsupported ALU op {op:#x}")),
                }
                pc += 1;
            }
            c if c == BPF_JMP => {
                let op = code & 0xf0;
                let src_k = insn.k;
                let take = match op {
                    BPF_JA => true,
                    BPF_JEQ => a == src_k,
                    BPF_JSET => (a & src_k) != 0,
                    0x20 => a > src_k,  // JGT
                    0x30 => a >= src_k, // JGE
                    _ => return Err(format!("unsupported JMP op {op:#x}")),
                };
                if op == BPF_JA {
                    pc = pc.checked_add(1 + insn.k as usize).ok_or("JA OOB")?;
                } else if take {
                    pc = pc.checked_add(1 + insn.jt as usize).ok_or("jt OOB")?;
                } else {
                    pc = pc.checked_add(1 + insn.jf as usize).ok_or("jf OOB")?;
                }
            }
            _ => return Err(format!("unsupported class {class:#x}")),
        }
    }
    Err("fell off end of program".into())
}

/// Evaluate a compiled policy for one ctx (userspace oracle).
pub fn decide(compiled: &CompiledPolicy, ctx: &BpfCtx) -> bool {
    let op = ctx.opcode as u32;
    if let Some(f) = compiled.filters.iter().find(|f| f.opcode == op) {
        match interpret(&f.insns, ctx) {
            Ok(v) => v != 0,
            Err(_) => false,
        }
    } else if compiled.deny_rest {
        false
    } else {
        true // no filter and no DENY_REST => kernel allows
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::Policy;

    fn lab_policy() -> Policy {
        Policy::parse_json(include_str!("../fixtures/default.json")).unwrap()
    }

    #[test]
    fn default_profile_allows_read_denies_msg_ring() {
        let c = compile(&lab_policy());
        assert!(c.deny_rest);
        assert_eq!(c.filters.len(), 38);

        let allow_read = decide(
            &c,
            &BpfCtx {
                opcode: 22, // READ
                ..Default::default()
            },
        );
        assert!(allow_read);

        let deny_msg = decide(
            &c,
            &BpfCtx {
                opcode: 40, // MSG_RING
                ..Default::default()
            },
        );
        assert!(!deny_msg);
    }

    #[test]
    fn buffer_select_flag_denied_on_allowed_opcode() {
        let c = compile(&lab_policy());
        let ok = decide(
            &c,
            &BpfCtx {
                opcode: 22,
                sqe_flags: 0,
                ..Default::default()
            },
        );
        assert!(ok);
        let bad = decide(
            &c,
            &BpfCtx {
                opcode: 22,
                sqe_flags: crate::opcodes::sqe_flags::BUFFER_SELECT,
                ..Default::default()
            },
        );
        assert!(!bad);
    }

    #[test]
    fn socket_family_filter() {
        let c = compile(&lab_policy());
        let inet = decide(
            &c,
            &BpfCtx {
                opcode: 45,
                socket_family: 2,
                ..Default::default()
            },
        );
        assert!(inet);
        let netlink = decide(
            &c,
            &BpfCtx {
                opcode: 45,
                socket_family: 16,
                ..Default::default()
            },
        );
        assert!(!netlink);
    }
}
