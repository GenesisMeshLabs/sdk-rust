//! The format adapter of the differential harness: how a reference vector
//! becomes a command line for the binary, and how the binary's output is
//! read back into the form the vector expects.
//!
//! The shared suites (`tests/fixtures`) and the anchors fixture are adapted
//! here. The core's verification corpus
//! (`scripts/export_reference_corpus.py --suite verification`) is read
//! through the same function: a vector kind without an adapter is skipped
//! and reported, so the corpus can land before its adapters do. Update this
//! file when the corpus format is final.

use std::{collections::BTreeSet, path::Path};

use serde_json::{json, Map, Value};

use crate::common::{Run, Scratch};

/// A key that verifies nothing: given where a vector names no key.
const NO_KEY: &str = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";

/// The counts an export result carries when nonzero.
const COUNTS: [&str; 6] = [
    "observations",
    "break_glass",
    "judgements",
    "quarantined",
    "remediations",
    "reviews",
];

/// How a run is read back.
pub enum Projection {
    /// Verdict, failures (deduplicated and sorted), counts.
    Export,
    /// Every failure in order: `store_sequence` and `reason`.
    ExportFailures,
    /// A decision's `accepted` and `reason`.
    Decision,
    /// Whether a record verifies: signature, fields and form.
    RecordValid,
    /// The exit code and the whole JSON output, as the reference CLI's.
    CliOutput,
    /// The corpus's export verdict: `verified` when it names one, and every
    /// failure's `store_sequence` and `reason`.
    CorpusExport,
    /// `verified`, the failures' `key_sequence` and `reason`, and the keys.
    KeyHistory,
    /// `verified`, the sorted failure reasons and warnings, and the
    /// unmatched changes when the pack was checked against a log.
    Pack,
}

/// One vector as a run of the binary.
pub struct Case {
    pub args: Vec<String>,
    pub expected: Value,
    pub projection: Projection,
}

/// A vector the binary runs, or why it does not.
pub enum Adapted {
    Run(Case),
    Skip(String),
}

fn strings(value: &Value) -> Vec<String> {
    value
        .as_array()
        .map(|a| {
            a.iter()
                .filter_map(|v| v.as_str().map(str::to_owned))
                .collect()
        })
        .unwrap_or_default()
}

fn na_keys(args: &mut Vec<String>, keys: &[String]) {
    if keys.is_empty() {
        args.extend(["--na-key".to_owned(), NO_KEY.to_owned()]);
    }
    for key in keys {
        args.extend(["--na-key".to_owned(), key.clone()]);
    }
}

/// The record kind of a model name, and for a record an executor or
/// observer signs, the key role and the field naming its sovereign.
fn record_kind(model: &str) -> Option<(&'static str, Option<(&'static str, &'static str)>)> {
    Some(match model {
        "ObservationRecord" => ("observation", Some(("observer", "observer_sovereign_id"))),
        "BreakGlassRecord" => ("break_glass", Some(("executor", "executor_sovereign_id"))),
        "RemediationRecord" => ("remediation", Some(("executor", "executor_sovereign_id"))),
        "ExecutionEvidence" => ("execution", Some(("executor", "executor_sovereign_id"))),
        "JudgementRecord" => ("judgement", None),
        "QuarantineRecord" => ("quarantine", None),
        "RegistryRecord" => ("registry", None),
        "ReviewRecord" => ("review", None),
        "BoundaryDecision" => ("decision", None),
        "BoundaryPolicy" => ("policy", None),
        "MembershipAttestation" => ("attestation", None),
        _ => return None,
    })
}

fn export_case(v: &Value, scratch: &Scratch, projection: Projection) -> Adapted {
    let input = &v["input"];
    if input["contiguous"] == false {
        return Adapted::Skip("a filtered history; the binary verifies exports".into());
    }
    let mut args = vec![
        "export".to_owned(),
        scratch.file("export.jsonl", input["lines"].as_str().unwrap_or_default()),
        "--json".to_owned(),
    ];
    na_keys(&mut args, &strings(&input["na_public_keys"]));
    if let Some(keys) = input.get("executor_keys") {
        args.extend([
            "--executor-keys".to_owned(),
            scratch.json("keys.json", keys),
        ]);
    }
    if let Some(checkpoint) = input.get("checkpoint").filter(|c| !c.is_null()) {
        args.extend([
            "--checkpoint".to_owned(),
            scratch.json("checkpoint.json", checkpoint),
        ]);
    }
    Adapted::Run(Case {
        args,
        expected: v["expected"].clone(),
        projection,
    })
}

fn decision_case(v: &Value, scratch: &Scratch) -> Adapted {
    let input = &v["input"];
    let mut args = vec![
        "record".to_owned(),
        "decision".to_owned(),
        scratch.json("decision.json", &input["decision"]),
        "--json".to_owned(),
    ];
    na_keys(&mut args, &strings(&input["operator_public_keys"]));
    if let Some(now) = input["now"].as_str() {
        args.extend(["--at".to_owned(), now.to_owned()]);
    }
    Adapted::Run(Case {
        args,
        expected: v["expected"].clone(),
        projection: Projection::Decision,
    })
}

fn record_case(v: &Value, scratch: &Scratch) -> Adapted {
    let record = &v["record"];
    let model = v["model"].as_str().unwrap_or_default();
    let Some((kind, signer)) = record_kind(model) else {
        return Adapted::Skip(format!("no record kind for model {model}"));
    };
    let key = v["public_key"].as_str().unwrap_or(NO_KEY).to_owned();
    let mut args = vec![
        "record".to_owned(),
        kind.to_owned(),
        scratch.json("record.json", record),
        "--json".to_owned(),
    ];
    match signer {
        // The vector's key, registered as the record's signer.
        Some((role, sovereign)) => {
            let keys = json!([{
                "key_id": record["signature"]["key_id"].as_str().unwrap_or("none"),
                "public_key": key,
                "executor_sovereign_id": record[sovereign].as_str().unwrap_or_default(),
                "role": role,
            }]);
            args.extend([
                "--executor-keys".to_owned(),
                scratch.json("keys.json", &keys),
            ]);
        }
        None => na_keys(&mut args, &[key]),
    }
    Adapted::Run(Case {
        args,
        expected: v["expected"].clone(),
        projection: Projection::RecordValid,
    })
}

fn anchors_case(v: &Value, scratch: &Scratch) -> Adapted {
    let input = &v["input"];
    let mut args = vec![
        "export".to_owned(),
        scratch.file("export.jsonl", input["lines"].as_str().unwrap_or_default()),
        "--known-anchors".to_owned(),
        scratch.json("anchors.json", &input["anchors"]),
        "--executor-keys".to_owned(),
        scratch.json("keys.json", &input["executor_keys"]),
        "--json".to_owned(),
    ];
    na_keys(&mut args, &strings(&input["na_public_keys"]));
    for flag in ["partial", "from_anchor"] {
        if input[flag] == true {
            args.push(format!("--{}", flag.replace('_', "-")));
        }
    }
    let expected = &v["expected"];
    let expected = if expected["error"] == true {
        json!({"error": true})
    } else {
        json!({"exit_code": expected["exit_code"], "output": expected["output"]})
    };
    Adapted::Run(Case {
        args,
        expected,
        projection: Projection::CliOutput,
    })
}

/// A case of the core's verification corpus (`corpus.json`, 1.5.0) as a run
/// of the binary: `export` (a one-entry or whole export with the key
/// history), `key-history` and `pack`, each in the directory it names.
pub fn adapt_corpus(case: &Value, dir: &Path) -> Adapted {
    let path = dir.join(case["path"].as_str().unwrap_or_default());
    let file = |name: &str| path.join(name).to_str().unwrap_or_default().to_owned();
    let has = |name: &str| path.join(name).exists();
    let expected = case["expected"].clone();
    let (args, projection) = match case["command"].as_str().unwrap_or_default() {
        "export" => (
            vec![
                "export".to_owned(),
                file("export.jsonl"),
                "--key-history".to_owned(),
                file("key-history.json"),
                "--root-key".to_owned(),
                file("root.pub"),
                "--executor-keys".to_owned(),
                file("executor-keys.json"),
                "--json".to_owned(),
            ],
            Projection::CorpusExport,
        ),
        "key-history" => (
            vec![
                "key-history".to_owned(),
                file("key-history.json"),
                "--root-key".to_owned(),
                file("root.pub"),
                "--json".to_owned(),
            ],
            Projection::KeyHistory,
        ),
        "pack" => {
            let mut args = vec![
                "pack".to_owned(),
                file("pack"),
                "--anchor".to_owned(),
                file("root.pub"),
                "--json".to_owned(),
            ];
            if has("anchors.json") {
                args.extend(["--known-anchors".to_owned(), file("anchors.json")]);
            }
            if has("changes.json") {
                args.extend(["--changes".to_owned(), file("changes.json")]);
            }
            (args, Projection::Pack)
        }
        other => return Adapted::Skip(format!("no adapter for corpus command {other}")),
    };
    Adapted::Run(Case {
        args,
        expected,
        projection,
    })
}

fn key_history_file(input: &Value, scratch: &Scratch) -> (String, String) {
    let history = json!({"genesis": input["genesis"], "successions": input["successions"]});
    (
        scratch.json("key-history.json", &history),
        input["root_public_key"]
            .as_str()
            .unwrap_or(NO_KEY)
            .to_owned(),
    )
}

fn history_export_case(v: &Value, scratch: &Scratch) -> Adapted {
    let input = &v["input"];
    let (history, root) = key_history_file(input, scratch);
    Adapted::Run(Case {
        args: vec![
            "export".to_owned(),
            scratch.file("export.jsonl", input["lines"].as_str().unwrap_or_default()),
            "--key-history".to_owned(),
            history,
            "--root-key".to_owned(),
            root,
            "--executor-keys".to_owned(),
            scratch.json("keys.json", &input["executor_keys"]),
            "--json".to_owned(),
        ],
        expected: v["expected"].clone(),
        projection: Projection::CorpusExport,
    })
}

fn key_history_case(v: &Value, scratch: &Scratch) -> Adapted {
    let (history, root) = key_history_file(&v["input"], scratch);
    Adapted::Run(Case {
        args: vec![
            "key-history".to_owned(),
            history,
            "--root-key".to_owned(),
            root,
            "--json".to_owned(),
        ],
        expected: v["expected"].clone(),
        projection: Projection::KeyHistory,
    })
}

fn pack_case(v: &Value, scratch: &Scratch) -> Adapted {
    let input = &v["input"];
    for (path, text) in input["files"].as_object().into_iter().flatten() {
        scratch.file(&format!("pack/{path}"), text.as_str().unwrap_or_default());
    }
    let mut args = vec![
        "pack".to_owned(),
        scratch
            .path()
            .join("pack")
            .to_str()
            .unwrap_or_default()
            .to_owned(),
        "--anchor".to_owned(),
        input["root_public_key"]
            .as_str()
            .unwrap_or(NO_KEY)
            .to_owned(),
        "--json".to_owned(),
    ];
    if !input["held_anchors"].is_null() {
        args.extend([
            "--known-anchors".to_owned(),
            scratch.json("anchors.json", &input["held_anchors"]),
        ]);
    }
    if input.get("changes").is_some_and(|c| !c.is_null()) {
        let changes = json!({ "changes": input["changes"] });
        args.extend([
            "--changes".to_owned(),
            scratch.json("changes.json", &changes),
        ]);
    }
    Adapted::Run(Case {
        args,
        expected: v["expected"].clone(),
        projection: Projection::Pack,
    })
}

/// A vector of a suite as a run of the binary.
pub fn adapt(suite: &str, v: &Value, scratch: &Scratch) -> Adapted {
    match (suite, v["kind"].as_str().unwrap_or_default()) {
        // 1.5.0: the audit suite's exports carry the NA's key history.
        ("audit", "verify_export") => history_export_case(v, scratch),
        ("audit", "key_history") => key_history_case(v, scratch),
        ("audit", "pack") => pack_case(v, scratch),
        (_, "verify_export") => export_case(v, scratch, Projection::Export),
        ("field_registry", "export") => export_case(v, scratch, Projection::ExportFailures),
        (_, "verify_decision") => decision_case(v, scratch),
        (_, "verify_record") => record_case(v, scratch),
        (_, "verify_export_anchors") => anchors_case(v, scratch),
        (_, kind) => Adapted::Skip(format!("no adapter for {kind} vectors")),
    }
}

fn sequence(f: &Value) -> i64 {
    f["store_sequence"].as_i64().unwrap_or(0)
}

/// Failures as a sorted set of (store position, reason); an absent
/// position reads as 0, as the reference runners report it.
fn failure_set(failures: &Value) -> Value {
    let set: BTreeSet<(i64, String)> = failures
        .as_array()
        .into_iter()
        .flatten()
        .map(|f| {
            (
                sequence(f),
                f["reason"].as_str().unwrap_or_default().to_owned(),
            )
        })
        .collect();
    Value::Array(
        set.into_iter()
            .map(|(s, r)| json!({"store_sequence": s, "reason": r}))
            .collect(),
    )
}

/// What the vector expects, read back in the form the projection compares.
pub fn expected(case: &Case) -> Value {
    match case.projection {
        Projection::Export => json!({
            "verified": case.expected["verified"],
            "failures": failure_set(&case.expected["failures"]),
            "counts": case.expected["counts"],
        }),
        _ => case.expected.clone(),
    }
}

/// The binary's run, read back in the form the vector expects.
pub fn project(case: &Case, run: &Run) -> Value {
    if matches!(case.projection, Projection::CliOutput) && run.code > 1 {
        return json!({"error": true});
    }
    let out = run.json();
    match case.projection {
        Projection::Export => {
            let counts: Map<String, Value> = COUNTS
                .iter()
                .filter_map(|k| Some((k.to_string(), out.get(*k)?.clone())))
                .collect();
            json!({
                "verified": out["verified"],
                "failures": failure_set(&out["failures"]),
                "counts": counts,
            })
        }
        Projection::ExportFailures => {
            let failures: Vec<Value> = out["failures"]
                .as_array()
                .into_iter()
                .flatten()
                .map(|f| json!({"store_sequence": f["store_sequence"], "reason": f["reason"]}))
                .collect();
            json!({ "failures": failures })
        }
        Projection::Decision => json!({"accepted": out["verified"], "reason": out["reason"]}),
        Projection::RecordValid => {
            let form = [
                "payload_invalid",
                "invalid_signature",
                "unknown_field",
                "non_canonical_form",
            ];
            let refused = out["failures"]
                .as_array()
                .into_iter()
                .flatten()
                .any(|f| form.contains(&f["reason"].as_str().unwrap_or_default()));
            json!({ "valid": !refused })
        }
        Projection::CliOutput => json!({"exit_code": run.code, "output": out}),
        Projection::CorpusExport => {
            let failures: Vec<Value> = out["failures"]
                .as_array()
                .into_iter()
                .flatten()
                .map(|f| json!({"store_sequence": f["store_sequence"], "reason": f["reason"]}))
                .collect();
            if case.expected.get("verified").is_some() {
                json!({"verified": out["verified"], "failures": failures})
            } else {
                json!({ "failures": failures })
            }
        }
        Projection::KeyHistory => json!({
            "verified": out["verified"],
            "failures": out["failures"].as_array().into_iter().flatten()
                .map(|f| json!({"key_sequence": f["key_sequence"], "reason": f["reason"]}))
                .collect::<Vec<_>>(),
            "keys": out.get("keys").cloned().unwrap_or(json!([])),
        }),
        Projection::Pack => {
            let set = |key: &str| -> Value {
                let set: BTreeSet<String> = out[key]
                    .as_array()
                    .into_iter()
                    .flatten()
                    .filter_map(|f| f["reason"].as_str().map(str::to_owned))
                    .collect();
                json!(set)
            };
            let mut got = json!({
                "verified": out["verified"],
                "reasons": set("failures"),
                "warnings": set("warnings"),
            });
            if let Some(completeness) = out.get("completeness") {
                got["unmatched_changes"] = json!(completeness["unmatched_changes"]
                    .as_array()
                    .into_iter()
                    .flatten()
                    .map(|c| c["index"].clone())
                    .collect::<Vec<_>>());
            }
            got
        }
    }
}
