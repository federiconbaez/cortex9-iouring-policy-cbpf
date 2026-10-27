//! Medición reproducible: cobertura del perfil default.json de iouring-lab.
//!
//! ```text
//! cargo test --test coverage_lab -- --nocapture
//! ```

use iouring_policy_cbpf::{compile, decide, measure_opcode_coverage, BpfCtx, Policy};

#[test]
fn lab_default_json_38_allows_and_all_denies() {
    let policy = Policy::parse_json(include_str!("../fixtures/default.json")).expect("parse");
    let cov = measure_opcode_coverage(&policy);
    eprintln!(
        "MEASURE allow={}/{} deny={}/{}",
        cov.allow_ok, cov.allow_total, cov.deny_ok, cov.deny_total
    );
    assert_eq!(cov.allow_total, 38);
    assert_eq!(cov.allow_ok, 38);
    assert_eq!(cov.deny_ok, cov.deny_total);
    assert!(cov.perfect());
}

#[test]
fn lab_denies_msg_ring_and_uring_cmd_and_netlink() {
    let policy = Policy::parse_json(include_str!("../fixtures/default.json")).unwrap();
    let c = compile(&policy);

    assert!(!decide(
        &c,
        &BpfCtx {
            opcode: 40,
            ..BpfCtx::default()
        }
    )); // MSG_RING
    assert!(!decide(
        &c,
        &BpfCtx {
            opcode: 46,
            ..BpfCtx::default()
        }
    )); // URING_CMD
    assert!(!decide(
        &c,
        &BpfCtx {
            opcode: 45,
            socket_family: 16, // AF_NETLINK
            ..BpfCtx::default()
        }
    ));
    assert!(decide(
        &c,
        &BpfCtx {
            opcode: 45,
            socket_family: 1, // AF_UNIX
            ..BpfCtx::default()
        }
    ));
}
