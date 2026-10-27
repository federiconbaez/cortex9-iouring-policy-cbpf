//! CLI: compile an io_uring policy JSON to cBPF (and optionally probe the kernel).

use clap::{Parser, Subcommand};
use iouring_policy_cbpf::{
    compile, measure_opcode_coverage, probe_register, read_kernel_release, Policy,
};
use std::path::PathBuf;
use std::process::ExitCode;

#[derive(Parser, Debug)]
#[command(name = "iouring-policy", about = "Compile io_uring policies to cBPF")]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand, Debug)]
enum Cmd {
    /// Parse a policy and print the compiled filters (dry-run, no kernel).
    Compile {
        #[arg(value_name = "POLICY.json")]
        policy: PathBuf,
        /// Dump hex-encoded instructions per opcode.
        #[arg(long)]
        dump: bool,
    },
    /// Userspace coverage measurement (interpreter oracle).
    Measure {
        #[arg(value_name = "POLICY.json")]
        policy: PathBuf,
    },
    /// Try IORING_REGISTER_BPF_FILTER against the running kernel.
    ///
    /// Fails hard (exit 2) if the kernel does not support it. Never skips.
    Register {
        #[arg(value_name = "POLICY.json")]
        policy: PathBuf,
    },
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    match cli.cmd {
        Cmd::Compile { policy, dump } => match run_compile(&policy, dump) {
            Ok(()) => ExitCode::SUCCESS,
            Err(e) => {
                eprintln!("error: {e}");
                ExitCode::FAILURE
            }
        },
        Cmd::Measure { policy } => match run_measure(&policy) {
            Ok(code) => code,
            Err(e) => {
                eprintln!("error: {e}");
                ExitCode::FAILURE
            }
        },
        Cmd::Register { policy } => match run_register(&policy) {
            Ok(()) => ExitCode::SUCCESS,
            Err(code) => code,
        },
    }
}

fn load(path: &PathBuf) -> Result<Policy, String> {
    let text = std::fs::read_to_string(path).map_err(|e| e.to_string())?;
    Policy::parse_json(&text).map_err(|e| e.to_string())
}

fn run_compile(path: &PathBuf, dump: bool) -> Result<(), String> {
    let policy = load(path)?;
    let compiled = compile(&policy);
    println!(
        "filters={} deny_rest={} denied_by_rest={}",
        compiled.filters.len(),
        compiled.deny_rest,
        compiled.denied_by_rest.len()
    );
    if dump {
        for f in &compiled.filters {
            print!("opcode {}: ", f.opcode);
            for insn in &f.insns {
                print!(
                    "{{{:#06x},{},{},{:#x}}} ",
                    insn.code, insn.jt, insn.jf, insn.k
                );
            }
            println!();
        }
    }
    Ok(())
}

fn run_measure(path: &PathBuf) -> Result<ExitCode, String> {
    let policy = load(path)?;
    let c = measure_opcode_coverage(&policy);
    println!(
        "allow={}/{} deny={}/{} perfect={}",
        c.allow_ok,
        c.allow_total,
        c.deny_ok,
        c.deny_total,
        c.perfect()
    );
    if c.perfect() {
        Ok(ExitCode::SUCCESS)
    } else {
        Ok(ExitCode::from(1))
    }
}

fn run_register(path: &PathBuf) -> Result<(), ExitCode> {
    let policy = match load(path) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("error: {e}");
            return Err(ExitCode::FAILURE);
        }
    };
    let compiled = compile(&policy);
    let release = read_kernel_release();
    println!("kernel={release}");
    match probe_register(&compiled) {
        Ok(()) => {
            println!("register=ok");
            Ok(())
        }
        Err(e) => {
            eprintln!("register=FAIL: {e}");
            eprintln!(
                "enforcement requires Linux >= 7.0 with IORING_REGISTER_BPF_FILTER; \
                 this is not a skip"
            );
            Err(ExitCode::from(2))
        }
    }
}
