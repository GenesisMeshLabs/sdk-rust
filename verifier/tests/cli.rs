//! The command line of genesis-mesh-verify: commands, output forms, exit
//! codes, and that it holds no network or signing code.

mod common;

use common::{fixture, run, Scratch};
use serde_json::{json, Value};

/// The reference vectors' export, keys and records, written to files.
struct Vectors {
    v: Value,
    scratch: Scratch,
}

impl Vectors {
    fn new(name: &str) -> Self {
        Vectors {
            v: fixture("python-vectors"),
            scratch: Scratch::new(name),
        }
    }

    fn na_key(&self) -> String {
        self.v["na_public_key"].as_str().unwrap().to_owned()
    }

    fn keys(&self) -> String {
        self.scratch.json("keys.json", &self.v["executor_keys"])
    }

    fn export(&self, text: &str) -> String {
        self.scratch.file("export.jsonl", text)
    }

    fn reference_export(&self) -> String {
        self.export(self.v["export"].as_str().unwrap())
    }
}

#[test]
fn help_and_version() {
    let help = run(&["--help"]);
    assert_eq!(help.code, 0);
    assert!(help
        .stdout
        .contains("genesis-mesh-verify record <kind> <file>"));
    assert!(help.stdout.contains("never contacts a network"));
    let version = run(&["--version"]);
    assert_eq!(version.code, 0);
    assert_eq!(
        version.stdout.trim(),
        format!("genesis-mesh-verify {}", env!("CARGO_PKG_VERSION"))
    );
}

#[test]
fn a_decision_is_judged_as_of_its_own_time_unless_told_otherwise() {
    let t = Vectors::new("decision-time");
    // The decision as the NA returned it, years after it expired.
    let allowed = t.scratch.json("allowed.json", &t.v["allowed"]);
    let r = run(&["record", "decision", &allowed, "--na-key", &t.na_key()]);
    assert_eq!(r.code, 0, "{}", r.stdout);
    assert!(r.stdout.contains("Result     : VERIFIED (authorized)"));
    assert!(r.stdout.contains("Decision   : allows its action"));
    let late = run(&[
        "record",
        "decision",
        &allowed,
        "--na-key",
        &t.na_key(),
        "--at",
        "2100-01-01T00:00:00Z",
        "--json",
    ]);
    assert_eq!(late.code, 1);
    assert_eq!(late.json()["reason"], "decision_expired");
    assert_eq!(late.json()["verified"], false);
    // A genuine denial is verified: the record is authentic.
    let bare = t.scratch.json("denied.json", &t.v["denied"]["decision"]);
    let denied = run(&[
        "record",
        "decision",
        &bare,
        "--na-key",
        &t.na_key(),
        "--json",
    ]);
    assert_eq!(denied.code, 0, "{}", denied.stdout);
    assert_eq!(denied.json()["authorized"], false);
    assert!(denied.json()["reason"]
        .as_str()
        .unwrap()
        .starts_with("unauthorized_"));
}

#[test]
fn a_decision_binds_the_policies_and_attestation_expected() {
    let t = Vectors::new("decision-bindings");
    let allowed = t.scratch.json("allowed.json", &t.v["allowed"]);
    let policy = t.scratch.json("policy.json", &t.v["policy"]);
    let attestation = t.scratch.json("attestation.json", &t.v["attestation"]);
    let args = |policy: &str| {
        run(&[
            "record",
            "decision",
            &allowed,
            "--na-key",
            &t.na_key(),
            "--expect-policy",
            policy,
            "--expect-attestation",
            &attestation,
            "--json",
        ])
    };
    assert_eq!(args(&policy).json()["reason"], "authorized");
    let mut other = t.v["policy"].clone();
    other["version"] = json!(99);
    let other = t.scratch.json("other.json", &other);
    let refused = args(&other);
    assert_eq!(refused.code, 1);
    assert_eq!(refused.json()["reason"], "policy_binding_mismatch");
}

#[test]
fn records_verify_under_the_keys_their_kind_needs() {
    let t = Vectors::new("records");
    let execution = t.scratch.json("execution.json", &t.v["executions"][0]);
    let ok = run(&[
        "record",
        "execution",
        &execution,
        "--executor-keys",
        &t.keys(),
    ]);
    assert_eq!(ok.code, 0, "{}", ok.stdout);
    assert!(ok.stdout.contains("Record     : execution 7ecd4840"));
    // The NA's key does not sign execution evidence.
    let na = run(&[
        "record",
        "execution",
        &execution,
        "--na-key",
        &t.na_key(),
        "--json",
    ]);
    assert_eq!(na.code, 1);
    assert_eq!(na.json()["reason"], "invalid_signature");
    // Nor does a key registered for another sovereign.
    let mut keys = t.v["executor_keys"].clone();
    keys[0]["executor_sovereign_id"] = json!("someone-else");
    let other = t.scratch.json("other-keys.json", &keys);
    let refused = run(&["record", "execution", &execution, "--executor-keys", &other]);
    assert_eq!(refused.code, 1);
    assert!(refused.stdout.contains("Result     : FAILED"));
    assert!(refused.stdout.contains("- invalid_signature execution"));
    // `checkpoint` names a retention checkpoint; the proof is the NA's.
    let checkpoint = t.scratch.json("checkpoint.json", &t.v["checkpoint"]);
    let cp = run(&[
        "record",
        "checkpoint",
        &checkpoint,
        "--na-key",
        &t.na_key(),
        "--json",
    ]);
    assert_eq!(cp.code, 0, "{}", cp.stdout);
    assert_eq!(cp.json()["kind"], "retention_checkpoint");
    let proof = t
        .scratch
        .json("proof.json", &t.v["allowed"]["justification_proof"]);
    assert_eq!(
        run(&["record", "justification", &proof, "--na-key", &t.na_key()]).code,
        0
    );
    let policy = t.scratch.json("policy.json", &t.v["policy"]);
    assert_eq!(
        run(&["record", "policy", &policy, "--na-key", &t.na_key()]).code,
        0
    );
}

#[test]
fn an_export_verifies_and_a_changed_one_fails_by_name() {
    let t = Vectors::new("export");
    let export = t.reference_export();
    let ok = run(&[
        "export",
        &export,
        "--na-key",
        &t.na_key(),
        "--executor-keys",
        &t.keys(),
    ]);
    assert_eq!(ok.code, 0, "{}", ok.stdout);
    assert!(ok.stdout.contains("Entries    : 8"));
    assert!(ok.stdout.contains("Result     : VERIFIED"));
    let changed =
        t.v["export"]
            .as_str()
            .unwrap()
            .replacen("sp-secret.create", "sp-secret.delete", 1);
    let changed = t.export(&changed);
    let failed = run(&[
        "export",
        &changed,
        "--na-key",
        &t.na_key(),
        "--executor-keys",
        &t.keys(),
    ]);
    assert_eq!(failed.code, 1);
    assert!(
        failed.stdout.contains("Result     : FAILED"),
        "{}",
        failed.stdout
    );
    assert!(failed.stdout.contains("#1: "), "{}", failed.stdout);
}

#[test]
fn an_export_is_checked_against_a_directory_of_held_anchors() {
    let suite = fixture("anchors");
    let vector = suite["vectors"]
        .as_array()
        .unwrap()
        .iter()
        .find(|v| v["id"] == "export-anchored")
        .unwrap();
    let input = &vector["input"];
    let scratch = Scratch::new("anchor-dir");
    for anchor in input["anchors"].as_array().unwrap() {
        let n = anchor["anchor_sequence"].as_i64().unwrap();
        scratch.json(&format!("held/anchor-{n:010}.json"), anchor);
    }
    // An interrupted write leaves an empty file: it holds no anchor.
    scratch.file("held/anchor-0000000009.json", "");
    scratch.file("held/notes.txt", "not an anchor");
    let mut args = vec![
        "export".to_owned(),
        scratch.file("export.jsonl", input["lines"].as_str().unwrap()),
        "--known-anchors".to_owned(),
        scratch.path().join("held").to_str().unwrap().to_owned(),
        "--executor-keys".to_owned(),
        scratch.json("keys.json", &input["executor_keys"]),
    ];
    for key in input["na_public_keys"].as_array().unwrap() {
        args.extend(["--na-key".to_owned(), key.as_str().unwrap().to_owned()]);
    }
    let readable = run(&args);
    assert_eq!(readable.code, 0, "{}", readable.stdout);
    assert!(readable.stdout.contains(
        "Anchors    : 3 matched of 3; anchored through #8; 0 entries after the last anchor"
    ));
    args.push("--json".to_owned());
    assert_eq!(run(&args).json(), vector["expected"]["output"]);
    // A directory without anchors cannot vouch for anything.
    let empty = Scratch::new("no-anchors");
    std::fs::create_dir_all(empty.path()).unwrap();
    let pos = args.iter().position(|a| a == "--known-anchors").unwrap();
    args[pos + 1] = empty.path().to_str().unwrap().to_owned();
    assert_eq!(run(&args).code, 3);
}

#[test]
fn a_given_checkpoint_must_be_the_nas() {
    let t = Vectors::new("checkpoint");
    let mut checkpoint = t.v["checkpoint"].clone();
    checkpoint["signature"] = Value::Null;
    let checkpoint = t.scratch.json("checkpoint.json", &checkpoint);
    let r = run(&[
        "export",
        &t.reference_export(),
        "--na-key",
        &t.na_key(),
        "--executor-keys",
        &t.keys(),
        "--checkpoint",
        &checkpoint,
        "--json",
    ]);
    assert_eq!(r.code, 1);
    assert_eq!(
        r.json()["failures"],
        json!([{"store_sequence": null, "reason": "invalid_signature", "detail": "retention_checkpoint"}])
    );
}

#[test]
fn each_way_of_stopping_has_its_exit_code() {
    let t = Vectors::new("errors");
    let key = t.na_key();
    let export = t.reference_export();
    let record = t.scratch.json("record.json", &t.v["executions"][0]);
    let not_json = t.scratch.file("not.json", "{\"a\": 1,}");
    let malformed = t.export("{\"schema\": \"gm.evidence.event\"}\n");
    let missing = t.scratch.path().join("missing.json");
    let missing = missing.to_str().unwrap();
    let (key, export, record) = (key.as_str(), export.as_str(), record.as_str());
    let (not_json, malformed) = (not_json.as_str(), malformed.as_str());
    for (args, code) in [
        (vec!["record", "execution", missing, "--na-key", key], 3),
        (vec!["record", "execution", not_json, "--na-key", key], 3),
        (vec!["export", malformed, "--na-key", key], 3),
        (
            vec!["record", "execution", record, "--na-key", "not-a-key"],
            2,
        ),
        (vec!["record", "execution", record], 2),
        (vec!["record", "anchor", record, "--na-key", key], 2),
        (
            vec![
                "record", "decision", record, "--na-key", key, "--at", "soon",
            ],
            2,
        ),
        (vec!["export", export, "--na-key", key, "--colour"], 2),
        (vec!["audit", export], 2),
        (vec!["pack", "pack-dir", "--anchor", key], 3),
        (vec!["pack", export], 2),
        (vec!["key-history", record], 2),
        (vec!["export", export, "--key-history", record], 2),
    ] {
        let r = run(&args);
        assert_eq!(r.code, code, "{args:?}: {}", r.stderr);
        assert!(
            r.stderr.starts_with("genesis-mesh-verify: error: "),
            "{args:?}"
        );
        assert!(r.stdout.is_empty(), "{args:?}");
    }
    // With --json, the error is also on standard output.
    let r = run(&["pack", "pack-dir", "--anchor", key, "--json"]);
    assert_eq!(r.code, 3);
    assert_eq!(r.json()["error"]["exit_code"], 3);
}

#[test]
fn a_key_file_reads_as_the_key_it_holds() {
    let t = Vectors::new("key-file");
    let file = t
        .scratch
        .file("na.pub", &format!("# the NA key\n\n{}\n", t.na_key()));
    let checkpoint = t.scratch.json("checkpoint.json", &t.v["checkpoint"]);
    assert_eq!(
        run(&["record", "checkpoint", &checkpoint, "--na-key", &file]).code,
        0
    );
}

/// The verifier never contacts a network and never needs a private key:
/// clippy.toml refuses the SDK's clients, sockets and signing in the
/// binary's code, and this keeps anyone from allowing them there.
#[test]
fn the_binary_holds_no_network_or_signing_code() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let forbidden = [
        "reqwest",
        "hyper",
        "tokio",
        "std::net",
        "TcpStream",
        "UdpSocket",
        "GenesisMeshClient",
        "HttpTransport",
        "SigningKey",
        "load_signing_key",
        "sign_canonical",
        "allow(clippy::disallowed",
    ];
    let mut sources = vec![root.join("Cargo.toml")];
    for entry in std::fs::read_dir(root.join("src")).unwrap() {
        sources.push(entry.unwrap().path());
    }
    for path in sources {
        let text = std::fs::read_to_string(&path).unwrap();
        for word in forbidden {
            assert!(!text.contains(word), "{} names {word}", path.display());
        }
    }
    let clippy = std::fs::read_to_string(root.join("clippy.toml")).unwrap();
    for path in [
        "std::net::TcpStream",
        "genesis_mesh_sdk::GenesisMeshClient",
        "genesis_mesh_sdk::load_signing_key",
    ] {
        assert!(
            clippy.contains(path),
            "clippy.toml no longer refuses {path}"
        );
    }
}

/// The frozen 1.5.0 pack (the core's conformance/fixtures/audit-pack-1.5.0),
/// copied into a scratch directory so a test can change it.
fn frozen_pack(name: &str) -> (Scratch, String, String, String) {
    let fixture =
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../tests/fixtures/audit-pack-1.5.0");
    let scratch = Scratch::new(name);
    fn copy(from: &std::path::Path, to: &std::path::Path) {
        std::fs::create_dir_all(to).unwrap();
        for entry in std::fs::read_dir(from).unwrap() {
            let path = entry.unwrap().path();
            let target = to.join(path.file_name().unwrap());
            if path.is_dir() {
                copy(&path, &target);
            } else {
                std::fs::copy(&path, &target).unwrap();
            }
        }
    }
    copy(&fixture, scratch.path());
    let at = |p: &str| scratch.path().join(p).to_str().unwrap().to_owned();
    let (pack, root, anchors) = (at("pack"), at("root.pub"), at("anchors.json"));
    (scratch, pack, root, anchors)
}

#[test]
fn the_frozen_pack_verifies_and_agrees_with_its_own_checks() {
    let (_scratch, pack, root, anchors) = frozen_pack("frozen");
    let readable = run(&[
        "pack",
        &pack,
        "--anchor",
        &root,
        "--known-anchors",
        &anchors,
    ]);
    assert_eq!(readable.code, 0, "{}", readable.stdout);
    assert!(readable
        .stdout
        .contains("Range      : entries 6 to 11 (6 entries)"));
    assert!(readable
        .stdout
        .contains("NA keys    : 2 in the key history"));
    assert!(readable.stdout.contains("Result     : VERIFIED"));
    assert!(!readable.stdout.contains("differs"), "{}", readable.stdout);
    let out = run(&[
        "pack",
        &pack,
        "--anchor",
        &root,
        "--known-anchors",
        &anchors,
        "--json",
    ])
    .json();
    assert_eq!(out["verified"], true);
    assert_eq!(out["check_differences"], json!([]));
    assert!(out.get("report_differences").is_none(), "{out}");
    assert!(
        out["period"]["from"].is_string() && out["period"]["until"].is_string(),
        "{out}"
    );
    assert_eq!(out["counts"]["key_successions"], 1);
    assert_eq!(out["keys"].as_array().unwrap().len(), 2);
    // Without held anchors: the pack's integrity only, said as a warning.
    let alone = run(&["pack", &pack, "--anchor", &root, "--json"]).json();
    assert_eq!(alone["verified"], true);
    assert_eq!(alone["warnings"][0]["reason"], "no_held_anchors");
    // Another root key: nothing in the pack vouches for itself.
    let other = run(&[
        "pack",
        &pack,
        "--anchor",
        &key_of(7),
        "--known-anchors",
        &anchors,
        "--json",
    ]);
    assert_eq!(other.code, 1);
    assert_eq!(
        other.json()["failures"][0]["reason"],
        "genesis_root_mismatch"
    );
}

fn key_of(byte: u8) -> String {
    use base64::{engine::general_purpose::STANDARD, Engine as _};
    // Not a key anyone holds a private half of: only its form matters here.
    STANDARD.encode([byte; 32])
}

#[test]
fn a_changed_pack_fails_by_name() {
    // A file tampered with.
    let (scratch, pack, root, anchors) = frozen_pack("tampered");
    let report = scratch.path().join("pack/report.md");
    let text = std::fs::read_to_string(&report).unwrap();
    std::fs::write(&report, text.replace("**yes**", "**no**")).unwrap();
    let r = run(&[
        "pack",
        &pack,
        "--anchor",
        &root,
        "--known-anchors",
        &anchors,
        "--json",
    ]);
    assert_eq!(r.code, 1);
    let failures = r.json()["failures"].clone();
    assert_eq!(failures[0]["reason"], "manifest_digest_mismatch");
    assert_eq!(failures[0]["file"], "report.md");
    // A record removed from the range.
    let (scratch, pack, root, anchors) = frozen_pack("removed");
    let entries = scratch.path().join("pack/entries.jsonl");
    let text = std::fs::read_to_string(&entries).unwrap();
    let kept: Vec<&str> = text
        .lines()
        .enumerate()
        .filter(|(i, _)| *i != 2)
        .map(|(_, l)| l)
        .collect();
    std::fs::write(&entries, kept.join("\n") + "\n").unwrap();
    let r = run(&[
        "pack",
        &pack,
        "--anchor",
        &root,
        "--known-anchors",
        &anchors,
        "--json",
    ]);
    assert_eq!(r.code, 1);
    assert_eq!(
        r.json()["failures"][0]["reason"],
        "manifest_digest_mismatch"
    );
    // A file the manifest does not list.
    let (scratch, pack, root, anchors) = frozen_pack("unlisted");
    scratch.file("pack/notes.txt", "added later");
    let r = run(&[
        "pack",
        &pack,
        "--anchor",
        &root,
        "--known-anchors",
        &anchors,
    ]);
    assert_eq!(r.code, 1);
    assert!(
        r.stdout.contains("notes.txt #None: manifest_unlisted_file"),
        "{}",
        r.stdout
    );
    // A rewritten range the NA re-signed and re-anchored fails against the
    // anchors held (the audit suite's pack-rewritten-re-anchored, run by the
    // differential harness, is the same case with a consistent manifest).
}

#[test]
fn a_pack_is_matched_against_an_outside_log() {
    let (scratch, pack, root, anchors) = frozen_pack("changes");
    let csv = scratch.file(
        "changes.csv",
        "source,source_event_id,resource_id,action,changed_at,actor\n\
         ,,kv:vault/unknown,delete,2026-01-12T00:00:00+00:00,someone\n",
    );
    let r = run(&[
        "pack",
        &pack,
        "--anchor",
        &root,
        "--known-anchors",
        &anchors,
        "--changes",
        &csv,
        "--json",
    ]);
    assert_eq!(r.code, 1, "{}", r.stdout);
    let out = r.json();
    assert_eq!(out["failures"][0]["reason"], "change_unmatched");
    assert_eq!(out["completeness"]["unmatched_changes"][0]["index"], 1);
    let bad = scratch.file(
        "bad.csv",
        "resource_id,action,changed_at\nr,update,2026-01-12T00:00:00\n",
    );
    assert_eq!(
        run(&["pack", &pack, "--anchor", &root, "--changes", &bad]).code,
        3
    );
}

#[test]
fn a_key_history_verifies_from_the_root_key_held() {
    let (scratch, pack, root, _) = frozen_pack("history");
    let genesis: Value =
        serde_json::from_str(&std::fs::read_to_string(format!("{pack}/genesis.json")).unwrap())
            .unwrap();
    let history: Value = serde_json::from_str(
        &std::fs::read_to_string(format!("{pack}/keys/na-key-history.json")).unwrap(),
    )
    .unwrap();
    let file = scratch.json(
        "history.json",
        &json!({"genesis": genesis, "successions": history["successions"]}),
    );
    let r = run(&["key-history", &file, "--root-key", &root]);
    assert_eq!(r.code, 0, "{}", r.stdout);
    assert!(r.stdout.contains("Key 2"), "{}", r.stdout);
    let refused = run(&["key-history", &file, "--root-key", &key_of(9), "--json"]);
    assert_eq!(refused.code, 1);
    assert_eq!(
        refused.json()["failures"][0]["reason"],
        "genesis_root_mismatch"
    );
    // An export verified with a history that does not verify fails.
    let export = scratch.file(
        "export.jsonl",
        &std::fs::read_to_string(format!("{pack}/entries.jsonl")).unwrap(),
    );
    let r = run(&[
        "export",
        &export,
        "--key-history",
        &file,
        "--root-key",
        &key_of(9),
        "--json",
    ]);
    assert_eq!(r.code, 1);
    assert_eq!(r.json()["failures"][0]["reason"], "genesis_root_mismatch");
}

/// 1.5.0 review fixes: anchors can be required, a period asked for, the
/// cited entries checked against packs verified before, and the report a
/// verification renders written out.
#[test]
fn a_pack_is_checked_against_what_the_auditor_holds() {
    let (scratch, pack, root, anchors) = frozen_pack("options");
    // Without anchors, --require-anchors fails (exit 1).
    let r = run(&["pack", &pack, "--anchor", &root, "--require-anchors"]);
    assert_eq!(r.code, 1, "{}", r.stderr);
    assert!(r.stderr.contains("--require-anchors"));
    // A period the pack does not cover.
    let wide = run(&[
        "pack",
        &pack,
        "--anchor",
        &root,
        "--known-anchors",
        &anchors,
        "--json",
        "--period",
        "2020-01-01T00:00:00Z",
        "2030-01-01T00:00:00Z",
    ]);
    assert_eq!(wide.code, 1);
    assert_eq!(
        wide.json()["failures"][0]["reason"],
        "pack_period_not_covered"
    );
    assert_eq!(wide.json()["period"]["asked_from"], "2020-01-01T00:00:00Z");
    // A cited entry that differs from the one a prior pack holds.
    let cited = std::fs::read_to_string(format!("{pack}/cited.jsonl")).unwrap();
    let first: Value = serde_json::from_str(cited.lines().next().unwrap()).unwrap();
    let position = first["entry"]["store_sequence"]
        .as_i64()
        .unwrap()
        .to_string();
    let prior = scratch.json("prior.json", &json!({ position: "0".repeat(64) }));
    let r = run(&[
        "pack",
        &pack,
        "--anchor",
        &root,
        "--known-anchors",
        &anchors,
        "--prior-entries",
        &prior,
        "--json",
    ]);
    assert_eq!(r.code, 1);
    let reasons: Vec<Value> = r.json()["failures"]
        .as_array()
        .unwrap()
        .iter()
        .map(|f| f["reason"].clone())
        .collect();
    assert!(
        reasons.contains(&json!("cited_entry_mismatch")),
        "{reasons:?}"
    );
    // A prior pack that does not verify is refused before anything else.
    let (bad, bad_pack, _, _) = frozen_pack("bad-prior");
    bad.file("pack/notes.txt", "added later");
    let r = run(&[
        "pack",
        &pack,
        "--anchor",
        &root,
        "--known-anchors",
        &anchors,
        "--prior",
        &bad_pack,
    ]);
    assert_eq!(r.code, 1);
    assert!(r.stderr.contains("does not verify"), "{}", r.stderr);
    // The report this verification renders.
    let report = scratch.path().join("own-report.md");
    let report_arg = report.to_str().unwrap().to_owned();
    let r = run(&[
        "pack",
        &pack,
        "--anchor",
        &root,
        "--known-anchors",
        &anchors,
        "--report",
        &report_arg,
    ]);
    assert_eq!(r.code, 0, "{}", r.stdout);
    let text = std::fs::read_to_string(&report).unwrap();
    assert!(text.contains(
        "Verified by this verifier, from the root key and the anchors it holds: **yes**."
    ));
    // The pack's range, verified as an export with the entries it cites.
    let r = run(&[
        "export",
        &format!("{pack}/entries.jsonl"),
        "--cited",
        &format!("{pack}/cited.jsonl"),
        "--key-history",
        &scratch.json("history.json", &json!({
            "genesis": serde_json::from_str::<Value>(&std::fs::read_to_string(format!("{pack}/genesis.json")).unwrap()).unwrap(),
            "successions": serde_json::from_str::<Value>(&std::fs::read_to_string(format!("{pack}/keys/na-key-history.json")).unwrap()).unwrap()["successions"],
        })),
        "--root-key",
        &root,
        "--executor-keys",
        &format!("{pack}/keys/executor-keys.json"),
        "--json",
    ]);
    assert_eq!(r.code, 0, "{}", r.stdout);
}

/// Keys supplied with --executor-keys are not placed in the store, as the
/// reference reads them: placement comes only from registry records the NA
/// signed in a pack (the audit suite's export-key-retired, through the CLI).
#[test]
fn a_supplied_key_is_not_placed() {
    let suite = fixture("audit");
    let v = suite["vectors"]
        .as_array()
        .unwrap()
        .iter()
        .find(|v| v["id"] == "export-key-retired")
        .unwrap();
    let input = &v["input"];
    assert!(v["expected"]["failures"]
        .to_string()
        .contains("evidence_executor_key_retired"));
    let scratch = Scratch::new("supplied-keys");
    let history = json!({"genesis": input["genesis"], "successions": input["successions"]});
    let r = run(&[
        "export",
        &scratch.file("export.jsonl", input["lines"].as_str().unwrap()),
        "--key-history",
        &scratch.json("history.json", &history),
        "--root-key",
        input["root_public_key"].as_str().unwrap(),
        "--executor-keys",
        &scratch.json("keys.json", &input["executor_keys"]),
        "--json",
    ]);
    assert!(
        !r.stdout.contains("evidence_executor_key_retired"),
        "{}",
        r.stdout
    );
}

/// A vector of the grants suite (1.6.0).
fn grant_vector(id: &str) -> Value {
    fixture("grants")["vectors"]
        .as_array()
        .unwrap()
        .iter()
        .find(|v| v["id"] == id)
        .unwrap()
        .clone()
}

#[test]
fn grant_records_verify_under_the_keys_their_kind_needs() {
    let scratch = Scratch::new("grant-records");
    let na = grant_vector("signature-CapabilityGrant-signer")["public_key"]
        .as_str()
        .unwrap()
        .to_owned();
    let grant = scratch.json(
        "grant.json",
        &grant_vector("canonical-CapabilityGrant")["record"],
    );
    let ok = run(&["record", "grant", &grant, "--na-key", &na, "--json"]);
    assert_eq!(ok.code, 0, "{}", ok.stdout);
    assert_eq!(ok.json()["kind"], "grant");
    let token = scratch.json("token.json", &grant_vector("canonical-TimeToken")["record"]);
    assert_eq!(
        run(&["record", "time-token", &token, "--na-key", &na]).code,
        0
    );
    // A use: its bearer key (an executor key), and its time token by the NA.
    let signer = grant_vector("signature-GrantExecutionEvidence-signer");
    let keys = scratch.json(
        "keys.json",
        &json!([{
            "key_id": "executor-b", "public_key": signer["public_key"],
            "executor_sovereign_id": signer["record"]["executor_sovereign_id"], "role": "executor",
        }]),
    );
    let used = scratch.json("use.json", &signer["record"]);
    let both = run(&[
        "record",
        "grant-execution",
        &used,
        "--executor-keys",
        &keys,
        "--na-key",
        &na,
    ]);
    assert_eq!(both.code, 0, "{}", both.stdout);
    let no_na = run(&[
        "record",
        "grant-execution",
        &used,
        "--executor-keys",
        &keys,
        "--json",
    ]);
    assert_eq!(no_na.code, 1);
    assert_eq!(no_na.json()["reason"], "grant_time_token_invalid");
}

#[test]
fn an_export_of_grants_counts_them_and_fails_a_missing_grant_by_name() {
    let scratch = Scratch::new("grant-export");
    let valid = grant_vector("export-valid")["input"].clone();
    let keys = scratch.json("keys.json", &valid["executor_keys"]);
    let na = valid["na_public_keys"][0].as_str().unwrap().to_owned();
    let export = scratch.file("export.jsonl", valid["lines"].as_str().unwrap());
    let ok = run(&["export", &export, "--na-key", &na, "--executor-keys", &keys]);
    assert_eq!(ok.code, 0, "{}", ok.stdout);
    assert!(ok.stdout.contains("Grants     : 1"), "{}", ok.stdout);
    assert!(ok.stdout.contains("Grant uses : 2"), "{}", ok.stdout);
    assert!(ok.stdout.contains("Revocations: 1"), "{}", ok.stdout);
    let missing = grant_vector("export-grant-missing")["input"]["lines"].clone();
    let export = scratch.file("missing.jsonl", missing.as_str().unwrap());
    let refused = run(&["export", &export, "--na-key", &na, "--executor-keys", &keys]);
    assert_eq!(refused.code, 1);
    assert!(
        refused.stdout.contains("grant_missing"),
        "{}",
        refused.stdout
    );
}
