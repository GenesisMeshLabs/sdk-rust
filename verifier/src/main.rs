//! `genesis-mesh-verify`: verifies Genesis Mesh records and evidence exports
//! offline with the SDK's `verify` module, the same code the SDK verifies
//! with. It never contacts a network and never needs a private key: every
//! key and record is given on the command line, as a file or a value.
//!
//! Exit codes, one per verdict: 0 verified, 1 not verified, 2 usage error,
//! 3 an input could not be read, 4 not available in this version.

#![forbid(unsafe_code)]

mod args;
mod commands;
mod input;
mod report;

use std::process::ExitCode;

/// Verified: every check passed.
pub const EXIT_VERIFIED: u8 = 0;
/// Read and checked, and not verified: a failure names its reason.
pub const EXIT_FAILED: u8 = 1;
/// The command line is wrong.
pub const EXIT_USAGE: u8 = 2;
/// An input could not be read: missing, not UTF-8, not strict JSON, or not
/// the kind of document it should be.
pub const EXIT_UNREADABLE: u8 = 3;
/// The command is not available in this version.
pub const EXIT_UNSUPPORTED: u8 = 4;

/// Why the verifier stopped before giving a verdict.
#[derive(Debug)]
pub enum Stop {
    /// The command line is wrong.
    Usage(String),
    /// An input could not be read.
    Unreadable(String),
    /// Not available in this version.
    Unsupported(String),
    /// Not verified before the verification could run (exit 1): a pack
    /// given with `--prior` does not verify, or `--require-anchors` without
    /// anchors.
    Failed(String),
}

impl Stop {
    fn code(&self) -> u8 {
        match self {
            Stop::Usage(_) => EXIT_USAGE,
            Stop::Unreadable(_) => EXIT_UNREADABLE,
            Stop::Unsupported(_) => EXIT_UNSUPPORTED,
            Stop::Failed(_) => EXIT_FAILED,
        }
    }

    fn message(&self) -> &str {
        match self {
            Stop::Usage(m) | Stop::Unreadable(m) | Stop::Unsupported(m) | Stop::Failed(m) => m,
        }
    }
}

fn main() -> ExitCode {
    let mut argv = Vec::new();
    for arg in std::env::args_os().skip(1) {
        match arg.into_string() {
            Ok(arg) => argv.push(arg),
            Err(arg) => {
                eprintln!("genesis-mesh-verify: error: not UTF-8: {arg:?}");
                return ExitCode::from(EXIT_USAGE);
            }
        }
    }
    let json = argv.iter().any(|a| a == "--json");
    match args::parse(&argv).and_then(commands::run) {
        Ok(code) => ExitCode::from(code),
        Err(stop) => {
            if json {
                let error = serde_json::json!({
                    "error": {"exit_code": stop.code(), "message": stop.message()}
                });
                println!("{error:#}");
            }
            eprintln!("genesis-mesh-verify: error: {}", stop.message());
            if matches!(stop, Stop::Usage(_)) {
                eprintln!("Run 'genesis-mesh-verify --help' for usage.");
            }
            ExitCode::from(stop.code())
        }
    }
}
