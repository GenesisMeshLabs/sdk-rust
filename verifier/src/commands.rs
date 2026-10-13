//! The commands: each reads its inputs, verifies with the SDK's `verify`,
//! `key_history` and `audit_pack` modules and prints the result.

use std::path::Path;

use genesis_mesh_sdk::{
    audit_pack::{
        differences_from_pack_checks, differences_from_report, parse_changes, verify_audit_pack,
        VerifyPackOptions,
    },
    canonical::parse_timestamp,
    key_history::{verify_key_history, KeyHistoryVerification, NaKeyHistory},
    verify::{
        check_events_against_anchors, export_checkpoint, parse_export_lines,
        verify_evidence_events, verify_record, verify_store_anchors, EvidenceVerification,
        VerificationFailure, VerifyEvidenceOptions, VerifyRecordOptions,
    },
    Value,
};

use crate::{
    args::{self, Command, ExportArgs, KeyHistoryArgs, PackArgs, RecordArgs},
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
        Command::Pack(args) => pack(&args, cli.json),
        Command::KeyHistory(args) => key_history(&args, cli.json),
    }
}

fn verdict(verified: bool) -> u8 {
    if verified {
        EXIT_VERIFIED
    } else {
        EXIT_FAILED
    }
}

fn print_json(value: &Value) {
    println!("{value:#}");
}

/// The NA keys a record or export is verified against: a key history read
/// from the root key held, or keys valid at every time.
enum Keys {
    Ready(Option<NaKeyHistory>),
    /// The key history did not verify from the root key.
    Refused(KeyHistoryVerification),
}

fn na_keys(
    na_keys: &[String],
    executor_keys: &Option<std::path::PathBuf>,
    history: &Option<std::path::PathBuf>,
    root_key: &Option<String>,
) -> Result<Keys, Stop> {
    match (history, root_key) {
        (Some(_), None) => {
            return Err(Stop::Usage(
                "--key-history needs --root-key: keys in the history prove nothing alone".into(),
            ))
        }
        (None, Some(_)) => return Err(Stop::Usage("--root-key goes with --key-history".into())),
        _ => {}
    }
    if na_keys.is_empty() && executor_keys.is_none() && history.is_none() {
        return Err(Stop::Usage(
            "give the keys to verify against: --na-key or --key-history, and/or --executor-keys"
                .into(),
        ));
    }
    let (Some(path), Some(root)) = (history, root_key) else {
        return Ok(Keys::Ready(None));
    };
    let result = read_key_history(path, root)?;
    Ok(match result.history.clone().filter(|_| result.verified) {
        Some(history) => Keys::Ready(Some(history)),
        None => Keys::Refused(result),
    })
}

fn read_key_history(path: &Path, root: &str) -> Result<KeyHistoryVerification, Stop> {
    let data = input::object(path)?;
    let successions = match &data["successions"] {
        Value::Array(items) => items.clone(),
        Value::Null => Vec::new(),
        _ => {
            return Err(Stop::Unreadable(format!(
                "cannot read {}: successions is not a list",
                path.display()
            )))
        }
    };
    let root = input::public_key(root)?;
    Ok(verify_key_history(
        &data["genesis"],
        &successions,
        Some(&root),
    ))
}

/// A key history that does not verify fails the verification it was given
/// for: nothing it holds can vouch for a record.
fn history_refused(refused: &KeyHistoryVerification, json: bool) -> u8 {
    let failures: Vec<VerificationFailure> = refused
        .failures
        .iter()
        .map(|f| VerificationFailure {
            store_sequence: None,
            reason: f.reason.clone(),
            detail: format!("key history: key {}", f.key_sequence.unwrap_or_default()),
        })
        .collect();
    if json {
        print_json(&serde_json::json!({"verified": false, "failures": failures}));
    } else {
        println!("Key history: does not verify from the root key held");
        println!("Result     : FAILED");
        for f in &failures {
            println!("  - {} {}", f.reason, f.detail);
        }
    }
    EXIT_FAILED
}

/// `record <kind> <file>`: one signed record, as an export verifies it.
fn record(args: &RecordArgs, json: bool) -> Result<u8, Stop> {
    let keys = na_keys(
        &args.na_keys,
        &args.executor_keys,
        &args.key_history,
        &args.root_key,
    )?;
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
        key_history: match keys {
            Keys::Ready(history) => history,
            Keys::Refused(refused) => return Ok(history_refused(&refused, json)),
        },
    };
    let result = verify_record(&args.kind, &record, &options);
    if json {
        print_json(&serde_json::to_value(&result).unwrap_or_default());
    } else {
        print!("{}", report::record(&result));
    }
    Ok(verdict(result.verified))
}

/// `export <file>`: an evidence export, as `genesis-mesh evidence
/// verify-export` verifies it, with the same JSON.
fn export(args: &ExportArgs, json: bool) -> Result<u8, Stop> {
    let keys = na_keys(
        &args.na_keys,
        &args.executor_keys,
        &args.key_history,
        &args.root_key,
    )?;
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
    let key_history = match keys {
        Keys::Ready(history) => history,
        Keys::Refused(refused) => return Ok(history_refused(&refused, json)),
    };
    let options = VerifyEvidenceOptions {
        checkpoint,
        key_history,
        ..VerifyEvidenceOptions::new(na_public_keys, executor_keys)
    };
    let mut result: EvidenceVerification = verify_evidence_events(&events, &options);
    let coverage = anchors.map(|anchors| {
        let chain = verify_store_anchors(&anchors, Some(&options.na_keys()), None);
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
        print_json(&out);
    } else {
        print!("{}", report::export(&result, coverage.as_ref()));
    }
    Ok(verdict(result.verified))
}

/// `pack <dir>`: an audit pack, as `genesis-mesh audit verify` verifies it,
/// with the same JSON and the differences from what the pack says of itself.
fn pack(args: &PackArgs, json: bool) -> Result<u8, Stop> {
    let files = input::pack_files(&args.dir)?;
    let held = match &args.known_anchors {
        Some(path) => Some(input::anchors(path)?),
        None => None,
    };
    let mut options = VerifyPackOptions::new(input::public_key(&args.root_key)?, held);
    if let Some(path) = &args.executor_keys {
        options.executor_keys = input::executor_keys(path)?;
    }
    if let Some(path) = &args.changes {
        let csv = path
            .extension()
            .and_then(|e| e.to_str())
            .is_some_and(|e| e.eq_ignore_ascii_case("csv"));
        let changes = parse_changes(&input::text(path)?, csv)
            .map_err(|e| Stop::Unreadable(format!("{}: {e}", path.display())))?;
        options.changes = Some(changes);
    }
    options.tolerance_seconds = args.tolerance_seconds;
    let result = verify_audit_pack(&files, &options);
    let mut differences = differences_from_pack_checks(&result, &files);
    differences.extend(differences_from_report(&result, &files));
    if json {
        let mut out = result.to_json();
        out["report_differences"] = Value::Array(differences);
        print_json(&out);
    } else {
        print!("{}", report::pack(&result, &differences));
    }
    Ok(verdict(result.verified))
}

/// `key-history <file>`: a genesis block and its successions, from the root
/// key held.
fn key_history(args: &KeyHistoryArgs, json: bool) -> Result<u8, Stop> {
    let root = args.root_key.as_deref().ok_or_else(|| {
        Stop::Usage("key-history needs --root-key: keys in the history prove nothing alone".into())
    })?;
    let result = read_key_history(&args.file, root)?;
    if json {
        print_json(&result.to_json());
    } else {
        print!("{}", report::key_history(&result));
    }
    Ok(verdict(result.verified))
}
