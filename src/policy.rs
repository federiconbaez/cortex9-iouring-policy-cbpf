//! Declarative io_uring policy (OCI-like / iouring-lab shape).

use crate::opcodes::{self, families, sqe_flags, IORING_OP_LAST};
use serde::Deserialize;
use std::collections::BTreeSet;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum PolicyError {
    #[error("JSON: {0}")]
    Json(#[from] serde_json::Error),
    #[error("unknown opcode '{0}'")]
    UnknownOpcode(String),
    #[error("unknown SQE flag '{0}'")]
    UnknownFlag(String),
    #[error("unknown socket family '{0}'")]
    UnknownFamily(String),
    #[error("defaultAction must be 'allow' or 'deny'")]
    BadDefaultAction,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RawPolicy {
    pub default_action: String,
    #[serde(default)]
    pub ops: Vec<String>,
    /// Explicit denials when defaultAction is allow (optional extension).
    #[serde(default)]
    pub deny_ops: Vec<String>,
    #[serde(default)]
    pub socket_families: Vec<String>,
    #[serde(default)]
    pub denied_sqe_flags: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DefaultAction {
    Allow,
    Deny,
}

/// Compiled view of a policy ready for cBPF emission.
#[derive(Debug, Clone)]
pub struct Policy {
    pub default_action: DefaultAction,
    /// Opcodes that should be allowed (have an allow filter).
    pub allow_opcodes: BTreeSet<u32>,
    /// Opcodes explicitly denied (dummy deny / omitted under DENY_REST).
    pub deny_opcodes: BTreeSet<u32>,
    /// Allowed AF_* for IORING_OP_SOCKET (empty = no extra family check).
    pub socket_families: Vec<u32>,
    /// IOSQE bits that must NOT be set on allowed ops.
    pub denied_sqe_flags: u8,
}

impl Policy {
    pub fn parse_json(input: &str) -> Result<Self, PolicyError> {
        let raw: RawPolicy = serde_json::from_str(input)?;
        Self::from_raw(raw)
    }

    pub fn from_raw(raw: RawPolicy) -> Result<Self, PolicyError> {
        let default_action = match raw.default_action.to_ascii_lowercase().as_str() {
            "deny" => DefaultAction::Deny,
            "allow" => DefaultAction::Allow,
            _ => return Err(PolicyError::BadDefaultAction),
        };

        let mut allow_opcodes = BTreeSet::new();
        for name in &raw.ops {
            let op = opcodes::lookup_opcode(name)
                .ok_or_else(|| PolicyError::UnknownOpcode(name.clone()))?;
            allow_opcodes.insert(op);
        }

        let mut deny_opcodes = BTreeSet::new();
        for name in &raw.deny_ops {
            let op = opcodes::lookup_opcode(name)
                .ok_or_else(|| PolicyError::UnknownOpcode(name.clone()))?;
            deny_opcodes.insert(op);
            allow_opcodes.remove(&op);
        }

        // Under default deny, every opcode not in allow is denied.
        if default_action == DefaultAction::Deny {
            for op in 0..IORING_OP_LAST {
                if !allow_opcodes.contains(&op) {
                    deny_opcodes.insert(op);
                }
            }
        }

        let mut denied_sqe_flags: u8 = 0;
        for name in &raw.denied_sqe_flags {
            let bit =
                sqe_flags::parse(name).ok_or_else(|| PolicyError::UnknownFlag(name.clone()))?;
            denied_sqe_flags |= bit;
        }

        let mut socket_families = Vec::new();
        for name in &raw.socket_families {
            let fam =
                families::parse(name).ok_or_else(|| PolicyError::UnknownFamily(name.clone()))?;
            socket_families.push(fam);
        }
        socket_families.sort_unstable();
        socket_families.dedup();

        Ok(Policy {
            default_action,
            allow_opcodes,
            deny_opcodes,
            socket_families,
            denied_sqe_flags,
        })
    }

    /// Whether DENY_REST should be set when registering with the kernel.
    pub fn deny_rest(&self) -> bool {
        self.default_action == DefaultAction::Deny
    }

    pub fn allows(&self, opcode: u32) -> bool {
        if self.deny_opcodes.contains(&opcode) {
            return false;
        }
        if self.allow_opcodes.contains(&opcode) {
            return true;
        }
        matches!(self.default_action, DefaultAction::Allow)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_default_lab_profile() {
        let raw = include_str!("../fixtures/default.json");
        let p = Policy::parse_json(raw).unwrap();
        assert_eq!(p.default_action, DefaultAction::Deny);
        assert_eq!(p.allow_opcodes.len(), 38);
        assert!(p.allows(0)); // NOP
        assert!(!p.allows(40)); // MSG_RING
        assert!(!p.allows(46)); // URING_CMD
        assert!(p.denied_sqe_flags & sqe_flags::BUFFER_SELECT != 0);
        assert!(p.socket_families.contains(&2)); // AF_INET
    }
}
