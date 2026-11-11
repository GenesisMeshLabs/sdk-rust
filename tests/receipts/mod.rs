//! Conformance receipts (the core's contract bundle, schema
//! `gm.contract.receipt/1`).
//!
//! Each shared suite the bundle maps to this crate has one runner: the test
//! that walks every vector of the suite file. The runner records each vector
//! whose assertions passed with [`Receipt::ran`] and ends with
//! [`Receipt::finish`], which checks that it ran every vector of every kind it
//! runs and that the kinds it does not run are the ones [`RUNNERS`] lists.
//! When `GM_CONFORMANCE_RECEIPTS` names a directory, `finish` then writes
//! `<dir>/<suite>.<test file>.json` for the core's `gm_contract.py
//! receipt-check`; unset, nothing is written. A runner that fails panics
//! before `finish`, so it leaves no receipt: its suite is unaccounted for,
//! never reported as run.

#![allow(dead_code)] // Each test crate uses part of this module.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use serde_json::{json, Value};

pub const VARIABLE: &str = "GM_CONFORMANCE_RECEIPTS";
pub const SCHEMA: &str = "gm.contract.receipt/1";
/// The kind of a vector without one.
pub const NO_KIND: &str = "*";

/// The runner of each shared suite: (suite, test file, test, the kinds this
/// crate does not run by design).
pub const RUNNERS: &[(&str, &str, &str, &[&str])] = &[
    (
        "admin_auth",
        "tests/auth_contract.rs",
        "matches_admin_signature_conformance_vectors",
        &[],
    ),
    (
        "audit",
        "tests/audit.rs",
        "every_vector_gives_the_reference_outcome",
        &[],
    ),
    // No agreement or data-usage verifier in this crate.
    (
        "canonical",
        "tests/canonical_conformance.rs",
        "every_vector_gives_the_reference_outcome",
        &["verify_agreement", "verify_intent"],
    ),
    (
        "field_registry",
        "tests/field_registry_conformance.rs",
        "every_vector_gives_the_reference_outcome",
        &["verify_agreement"],
    ),
    // The suite's na_only_kinds: the NA's issuance check.
    (
        "grants",
        "tests/grants.rs",
        "every_vector_gives_the_reference_outcome",
        &["issuance"],
    ),
    // Only the boundary decisions: no agreement, data-usage or canonical-JSON
    // runner of the interop scenario in this crate.
    (
        "interop",
        "tests/decision_vectors.rs",
        "every_decision_vector_gets_the_references_answer",
        &[
            "agreement",
            "canonical_json",
            "data_access_intent",
            "data_license_policy",
        ],
    ),
    (
        "node",
        "tests/node_conformance.rs",
        "reproduces_every_node_vector",
        &[],
    ),
    // The NA's own rules over time bounds and policy history.
    (
        "out_of_band",
        "tests/out_of_band.rs",
        "every_vector_gives_the_reference_outcome",
        &["time_bounds", "policy_history"],
    ),
    (
        "remediation",
        "tests/remediation.rs",
        "every_vector_gives_the_reference_outcome",
        &[],
    ),
    (
        "vouching",
        "tests/vouching.rs",
        "every_vouching_vector_matches_the_reference",
        &[],
    ),
];

/// Where the suites are copied in this repository.
pub const FIXTURES: &str = "tests/fixtures";

/// The directory `GM_CONFORMANCE_RECEIPTS` names; unset or empty, none.
pub fn receipts_dir() -> Option<PathBuf> {
    std::env::var_os(VARIABLE)
        .filter(|d| !d.is_empty())
        .map(PathBuf::from)
}

pub fn kind_of(vector: &Value) -> &str {
    vector["kind"].as_str().unwrap_or(NO_KIND)
}

/// Vectors per kind in a suite.
pub fn kind_counts(suite: &Value) -> BTreeMap<String, u64> {
    let mut counts = BTreeMap::new();
    for vector in suite["vectors"].as_array().expect("the suite has vectors") {
        *counts.entry(kind_of(vector).to_owned()).or_insert(0) += 1;
    }
    counts
}

pub struct Receipt {
    suite: &'static str,
    file: &'static str,
    test: &'static str,
    not_run: &'static [&'static str],
    run: BTreeMap<String, u64>,
}

impl Receipt {
    /// The receipt of the runner of `suite`; `file` is `file!()` and `test`
    /// the runner's name, which must match [`RUNNERS`].
    pub fn start(suite: &str, file: &str, test: &str) -> Self {
        let &(suite, file, test, not_run) = RUNNERS
            .iter()
            .find(|(s, f, t, _)| *s == suite && Path::new(f) == Path::new(file) && *t == test)
            .unwrap_or_else(|| panic!("{file}:{test} is not the listed runner of suite {suite}"));
        let receipt = Receipt {
            suite,
            file,
            test,
            not_run,
            run: BTreeMap::new(),
        };
        if let Some(dir) = receipts_dir() {
            receipt.clear(&dir);
        }
        receipt
    }

    /// Removes a receipt an earlier run left in `dir`: it must not stand for
    /// this run, whose suite is unaccounted for if it fails.
    pub fn clear(&self, dir: &Path) {
        match std::fs::remove_file(self.path(dir)) {
            Err(e) if e.kind() != std::io::ErrorKind::NotFound => panic!("{e}"),
            _ => {}
        }
    }

    /// A vector whose assertions passed (call it after them).
    pub fn ran(&mut self, vector: &Value) {
        *self.run.entry(kind_of(vector).to_owned()).or_insert(0) += 1;
    }

    /// Checks the counts against the suite, then writes the receipt when
    /// `GM_CONFORMANCE_RECEIPTS` is set.
    pub fn finish(self, suite: &Value) {
        let receipt = self.check(suite);
        if let Some(dir) = receipts_dir() {
            self.write(&dir, &receipt);
        }
    }

    /// The receipt, after checking that every kind of `suite` is run in full
    /// or listed as not run, and nothing else.
    pub fn check(&self, suite: &Value) -> Value {
        assert_eq!(
            suite["suite"], self.suite,
            "{}: the suite file names another suite",
            self.file
        );
        let counts = kind_counts(suite);
        let mut not_run = BTreeMap::new();
        for (kind, total) in &counts {
            if self.not_run.contains(&kind.as_str()) {
                assert!(
                    !self.run.contains_key(kind),
                    "{}: kind {kind} is listed as not run, yet ran",
                    self.suite
                );
                not_run.insert(kind.clone(), *total);
            } else {
                assert_eq!(
                    self.run.get(kind).copied().unwrap_or(0),
                    *total,
                    "{}: kind {kind} ran short (or is neither run nor listed as not run)",
                    self.suite
                );
            }
        }
        for kind in self.not_run {
            assert!(
                counts.contains_key(*kind),
                "{}: not-run kind {kind} is not in the suite",
                self.suite
            );
        }
        for kind in self.run.keys() {
            assert!(
                counts.contains_key(kind),
                "{}: ran kind {kind}, not in the suite",
                self.suite
            );
        }
        json!({
            "schema": SCHEMA,
            "suite": self.suite,
            "file": format!("{FIXTURES}/{}.json", self.suite),
            "runner": format!("{}:{}", self.file, self.test),
            "run": self.run,
            "not_run": not_run,
        })
    }

    /// `<dir>/<suite>.<test file stem>.json`.
    pub fn path(&self, dir: &Path) -> PathBuf {
        let stem = Path::new(self.file).file_stem().unwrap().to_str().unwrap();
        dir.join(format!("{}.{stem}.json", self.suite))
    }

    pub fn write(&self, dir: &Path, receipt: &Value) {
        std::fs::create_dir_all(dir).unwrap();
        let mut text = serde_json::to_string_pretty(receipt).unwrap();
        text.push('\n');
        std::fs::write(self.path(dir), text).unwrap();
    }
}
