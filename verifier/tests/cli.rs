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
        (vec!["pack", "pack-dir", "--anchor", key], 4),
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
    let r = run(&["pack", "pack-dir", "--json"]);
    assert_eq!(r.code, 4);
    assert_eq!(r.json()["error"]["exit_code"], 4);
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
