//! Enforcement probe: must exit non-zero when the kernel cannot register
//! cBPF io_uring filters. Used by the CI `enforce` job. Never skips.

use iouring_policy_cbpf::{compile, probe_register, read_kernel_release, Policy};
use std::process::ExitCode;

fn main() -> ExitCode {
    let release = read_kernel_release();
    println!("kernel={release}");

    let policy = match Policy::parse_json(include_str!("../../fixtures/default.json")) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("parse: {e}");
            return ExitCode::from(1);
        }
    };
    let compiled = compile(&policy);
    match probe_register(&compiled) {
        Ok(()) => {
            println!("register=ok");
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("register=FAIL: {e}");
            eprintln!(
                "IORING_REGISTER_BPF_FILTER requires Linux >= 7.0; \
                 refusing to skip on unsupported kernels"
            );
            ExitCode::from(2)
        }
    }
}
