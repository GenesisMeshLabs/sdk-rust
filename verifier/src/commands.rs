//! The commands: each reads its inputs, verifies with the SDK's `verify`
//! module and prints the result.

use genesis_mesh_sdk::{
    canonical::parse_timestamp,
    verify::{
        check_events_against_anchors, export_checkpoint, parse_export_lines,
        verify_evidence_events, verify_record, verify_store_anchors, VerificationFailure,
        VerifyEvidenceOptions, VerifyRecordOptions,
    },
    Value,
};

use crate::{
    args::{self, Command, ExportArgs, PackArgs, RecordArgs},
    input, report, Stop, EXIT_FAILED, EXIT_VERIFIED,
};

/// Run a parsed command line; the exit code of its verdict.
pub fn run(cli: args::Cli) -> Result<u8, Stop> {
    match cli.command {
        Command::Help => {
            print!("{}", args::USAGE);
            Ok(EXIT_VERIFIED)
        }
        Command::Version => {
            println!("genesis-mesh-verify {}", env!("CARGO_PKG_VERSION"));
            Ok(EXIT_VERIFIED)
        }
        Command::Record(args) => record(&args, cli.json),
        Command::Export(args) => export(&args, cli.json),
        Command::Pack(args) => pack(&args),
    }
}

fn verdict(verified: bool) -> u8 {
    if verified {
        EXIT_VERIFIED
    } else {
        EXIT_FAILED
    }
}

fn no_keys(na_keys: &[String], executor_keys: &Option<std::path::PathBuf>) -> Result<(), Stop> {
    if na_keys.is_empty() && executor_keys.is_none() {
        return Err(Stop::Usage(
            "give the keys to verify against: --na-key and/or --executor-keys".into(),
        ));
    }
    Ok(())
}

/// `record <kind> <file>`: one signed record, as an export verifies it.
fn record(args: &RecordArgs, json: bool) -> Result<u8, Stop> {
    no_keys(&args.na_keys, &args.executor_keys)?;
    let mut record = input::object(&args.file)?;
    // A decision as the NA returns it ({"decision": ..., ...}) is read as
    // the decision it holds.
    if args.kind == "decision" && record.get("decision_id").is_none() {
        if let Some(decision) = record.get("decision").filter(|d| d.is_object()) {
            record = decision.clone();
        }
    }
    let at = match &args.at {
        Some(at) => Some(
            parse_timestamp(at)
                .map_err(|_| Stop::Usage(format!("--at {at:?} is not an RFC 3339 timestamp")))?,
        ),
        None => None,
    };
    let expected_policies = if args.expect_policies.is_empty() {
        None
    } else {
        Some(
            args.expect_policies
                .iter()
                .map(|p| input::object(p))
                .collect::<Result<Vec<Value>, Stop>>()?,
        )
    };
    let options = VerifyRecordOptions {
        na_public_keys: input::public_keys(&args.na_keys)?,
        executor_keys: match &args.executor_keys {
            Some(path) => input::executor_keys(path)?,
            None => Vec::new(),
        },
        at,
        freshness_proof_issuer_keys: input::public_keys(&args.freshness_keys)?,
        expected_policies,
        expected_attestation: match &args.expect_attestation {
            Some(path) => Some(input::object(path)?),
            None => None,
        },
    };
    let result = verify_record(&args.kind, &record, &options);
    if json {
        println!("{:#}", serde_json::to_value(&result).unwrap_or_default());
    } else {
        print!("{}", report::record(&result));
    }
    Ok(verdict(result.verified))
}

/// `export <file>`: an evidence export, as `genesis-mesh evidence
/// verify-export` verifies it, with the same JSON.
fn export(args: &ExportArgs, json: bool) -> Result<u8, Stop> {
    no_keys(&args.na_keys, &args.executor_keys)?;
    let text = input::text(&args.file)?;
    let events = parse_export_lines(&text).map_err(|e| {
        Stop::Unreadable(format!("export {} is malformed: {e}", args.file.display()))
    })?;
    let na_public_keys = input::public_keys(&args.na_keys)?;
    let executor_keys = match &args.executor_keys {
        Some(path) => input::executor_keys(path)?,
        None => Vec::new(),
    };
    // An export that starts after a retention checkpoint continues from it.
    let checkpoint = match &args.checkpoint {
        Some(path) => Some(input::object(path)?),
        None => export_checkpoint(&events),
    };
    let anchors = match &args.known_anchors {
        Some(path) => Some(input::anchors(path)?),
        None => None,
    };
    let options = VerifyEvidenceOptions {
        checkpoint,
        ..VerifyEvidenceOptions::new(na_public_keys.clone(), executor_keys)
    };
    let mut result = verify_evidence_events(&events, &options);
    let coverage = anchors.map(|anchors| {
        let chain = verify_store_anchors(&anchors, Some(&na_public_keys), None);
        for failure in chain.failures {
            let n = failure.anchor_sequence.unwrap_or_default();
            result.verified = false;
            result.failures.push(VerificationFailure {
                store_sequence: None,
                reason: failure.reason,
                detail: format!("anchor {n} {}", failure.detail)
                    .trim_end()
                    .to_owned(),
            });
        }
        check_events_against_anchors(
            &events,
            &anchors,
            &mut result,
            args.partial,
            args.from_anchor,
        )
    });
    if json {
        let mut out = serde_json::to_value(&result).unwrap_or_default();
        if let Some(coverage) = &coverage {
            out["anchors"] = serde_json::to_value(coverage).unwrap_or_default();
        }
        println!("{out:#}");
    } else {
        print!("{}", report::export(&result, coverage.as_ref()));
    }
    Ok(verdict(result.verified))
}

/// `pack <dir>`: not available until the audit pack format is final.
fn pack(args: &PackArgs) -> Result<u8, Stop> {
    let _ = (&args.dir, &args.anchors, &args.known_anchors);
    Err(Stop::Unsupported(
        "pack verification is not available in this version: it follows the Genesis Mesh \
         1.5.0 audit pack format; verify the pack's export with 'genesis-mesh-verify export'"
            .into(),
    ))
}
