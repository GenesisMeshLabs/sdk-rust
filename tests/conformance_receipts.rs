//! Conformance receipts (tests/receipts): the runner table against the suite
//! files and the runners' sources, and what a receipt says.
//!
//! Each runner checks its own counts when it finishes. These tests check the
//! table those counts rest on: every shared suite copied here has exactly one
//! runner, the runner exists and records its vectors, and the kinds left out
//! are the ones meant (the NA-only kinds a suite declares among them).

mod receipts;

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use receipts::{Receipt, FIXTURES, NO_KIND, RUNNERS, SCHEMA, VARIABLE};
use serde_json::{json, Value};

/// This crate's own suite files in tests/fixtures, not shared suites of the
/// core: they are not in the contract bundle and have no receipt.
const OWN_VECTORS: &[&str] = &["anchors.json"];

fn root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn suite(name: &str) -> Value {
    let path = root().join(FIXTURES).join(format!("{name}.json"));
    serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap()
}

#[test]
fn every_shared_suite_has_exactly_one_runner() {
    let mut files = BTreeSet::new();
    for entry in std::fs::read_dir(root().join(FIXTURES)).unwrap() {
        let path = entry.unwrap().path();
        let name = path.file_name().unwrap().to_str().unwrap().to_owned();
        if !name.ends_with(".json") || OWN_VECTORS.contains(&name.as_str()) {
            continue;
        }
        // A suite file names its suite and holds vectors; other copies (the
        // bundle's kind table, the Python fixtures) are not suites.
        let value: Value = serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
        if value["suite"].is_string() && value["vectors"].is_array() {
            assert_eq!(value["suite"], name.trim_end_matches(".json"), "{name}");
            files.insert(name.trim_end_matches(".json").to_owned());
        }
    }
    let listed: Vec<&str> = RUNNERS.iter().map(|(suite, ..)| *suite).collect();
    let unique: BTreeSet<String> = listed.iter().map(|s| s.to_string()).collect();
    assert_eq!(
        unique.len(),
        listed.len(),
        "a suite is listed twice: {listed:?}"
    );
    assert_eq!(
        unique, files,
        "the shared suites in {FIXTURES} and the listed runners differ"
    );
    for name in OWN_VECTORS {
        assert!(
            root().join(FIXTURES).join(name).is_file(),
            "{name} is gone: drop it from OWN_VECTORS"
        );
    }
}

#[test]
fn every_runner_records_its_vectors_and_finishes() {
    for (suite, file, test, _) in RUNNERS {
        // A Windows checkout may have CRLF line endings.
        let source = std::fs::read_to_string(root().join(file))
            .unwrap()
            .replace("\r\n", "\n");
        let body = source
            .split(&format!("fn {test}() {{"))
            .nth(1)
            .unwrap_or_else(|| panic!("{file} has no fn {test}"));
        let body = body.split("\n}\n").next().unwrap();
        for call in [
            format!("receipts::Receipt::start(\"{suite}\", file!(), \"{test}\")"),
            ".ran(".to_owned(),
            ".finish(".to_owned(),
        ] {
            let flat = body
                .split_whitespace()
                .collect::<String>()
                .replace(",)", ")");
            let call: String = call.split_whitespace().collect();
            assert!(flat.contains(&call), "{file}:{test} does not call {call}");
        }
        assert!(
            source.contains("\nmod receipts;\n") || source.starts_with("mod receipts;\n"),
            "{file}"
        );
    }
}

#[test]
fn the_kinds_left_out_are_in_their_suites_and_include_the_na_only_kinds() {
    for (name, _, _, not_run) in RUNNERS {
        let suite = suite(name);
        assert_eq!(suite["suite"], *name);
        let kinds = receipts::kind_counts(&suite);
        for kind in *not_run {
            assert!(
                kinds.contains_key(*kind),
                "{name}: {kind} is not a kind of the suite"
            );
        }
        assert!(
            kinds.keys().any(|k| !not_run.contains(&k.as_str())),
            "{name}: no kind of the suite is run"
        );
        if let Some(na_only) = suite["na_only_kinds"].as_array() {
            for kind in na_only {
                assert!(
                    not_run.contains(&kind.as_str().unwrap()),
                    "{name}: NA-only kind {kind} is run"
                );
            }
        }
    }
}

fn scratch(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("gm-receipts-{}-{name}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    dir
}

#[test]
fn a_receipt_counts_what_ran_and_what_is_left_out_by_design() {
    let suite = suite("grants");
    let mut receipt = Receipt::start(
        "grants",
        "tests/grants.rs",
        "every_vector_gives_the_reference_outcome",
    );
    for v in suite["vectors"].as_array().unwrap() {
        if v["kind"] != "issuance" {
            receipt.ran(v);
        }
    }
    let got = receipt.check(&suite);
    let mut run = receipts::kind_counts(&suite);
    let issuance = run.remove("issuance").unwrap();
    assert_eq!(
        got,
        json!({
            "schema": SCHEMA,
            "suite": "grants",
            "file": "tests/fixtures/grants.json",
            "runner": "tests/grants.rs:every_vector_gives_the_reference_outcome",
            "run": run,
            "not_run": {"issuance": issuance},
        })
    );
    let dir = scratch("write");
    receipt.write(&dir, &got);
    let path = dir.join("grants.grants.json");
    let written: Value = serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
    assert_eq!(written, got);
    // The next run of the runner first removes it, so a failing run leaves none.
    receipt.clear(&dir);
    assert!(!path.exists());
    receipt.clear(&dir);
    std::fs::remove_dir_all(&dir).unwrap();
}

#[test]
#[should_panic(expected = "ran short")]
fn a_runner_that_skips_a_vector_it_runs_fails() {
    let suite = suite("vouching");
    let mut receipt = Receipt::start(
        "vouching",
        "tests/vouching.rs",
        "every_vouching_vector_matches_the_reference",
    );
    for v in suite["vectors"].as_array().unwrap().iter().skip(1) {
        receipt.ran(v);
    }
    receipt.check(&suite);
}

#[test]
#[should_panic(expected = "listed as not run, yet ran")]
fn a_runner_that_runs_a_kind_it_lists_as_left_out_fails() {
    let suite = suite("grants");
    let mut receipt = Receipt::start(
        "grants",
        "tests/grants.rs",
        "every_vector_gives_the_reference_outcome",
    );
    for v in suite["vectors"].as_array().unwrap() {
        receipt.ran(v);
    }
    receipt.check(&suite);
}

#[test]
#[should_panic(expected = "is not the listed runner")]
fn only_the_listed_runner_of_a_suite_writes_its_receipt() {
    Receipt::start(
        "grants",
        "tests/grants.rs",
        "a_grant_record_verifies_alone_by_kind",
    );
}

#[test]
fn a_vector_without_a_kind_counts_under_the_star() {
    let suite = suite("admin_auth");
    assert!(suite["vectors"]
        .as_array()
        .unwrap()
        .iter()
        .all(|v| v.get("kind").is_none()));
    let counts = receipts::kind_counts(&suite);
    assert_eq!(counts.keys().collect::<Vec<_>>(), [NO_KIND]);
}

#[test]
fn the_variable_is_the_one_the_core_sets() {
    assert_eq!(VARIABLE, "GM_CONFORMANCE_RECEIPTS");
    assert!(Path::new(FIXTURES).is_relative());
}
