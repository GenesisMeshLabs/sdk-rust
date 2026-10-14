//! Running the binary from the tests: the one cargo built, or the one
//! `GM_VERIFY_BINARY` names (a release binary, as CI checks the static ones).

#![allow(dead_code)]

use std::{
    path::{Path, PathBuf},
    process::Command,
    sync::atomic::{AtomicU32, Ordering},
};

use serde_json::Value;

/// The binary under test.
pub fn binary() -> PathBuf {
    std::env::var_os("GM_VERIFY_BINARY")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(env!("CARGO_BIN_EXE_genesis-mesh-verify")))
}

/// A fresh directory for one case's files, removed when dropped.
pub struct Scratch(pub PathBuf);

impl Scratch {
    pub fn new(name: &str) -> Self {
        static NEXT: AtomicU32 = AtomicU32::new(0);
        let n = NEXT.fetch_add(1, Ordering::Relaxed);
        let dir = std::env::temp_dir().join(format!("gm-verify-{}-{name}-{n}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        Scratch(dir)
    }

    /// Write a file and return its path as an argument.
    pub fn file(&self, name: &str, contents: &str) -> String {
        let path = self.0.join(name);
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).unwrap();
        }
        std::fs::write(&path, contents).unwrap();
        path.to_str().unwrap().to_owned()
    }

    /// Write a JSON file.
    pub fn json(&self, name: &str, value: &Value) -> String {
        self.file(name, &serde_json::to_string(value).unwrap())
    }

    pub fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// What a run printed and its exit code.
pub struct Run {
    pub code: i32,
    pub stdout: String,
    pub stderr: String,
}

impl Run {
    /// Standard output as JSON.
    pub fn json(&self) -> Value {
        serde_json::from_str(&self.stdout)
            .unwrap_or_else(|e| panic!("not JSON ({e}): {}\n{}", self.stdout, self.stderr))
    }
}

/// Run the binary with these arguments.
pub fn run<S: AsRef<str>>(args: &[S]) -> Run {
    let output = Command::new(binary())
        .args(args.iter().map(AsRef::as_ref))
        .output()
        .expect("the verifier runs");
    Run {
        code: output.status.code().unwrap_or(-1),
        stdout: String::from_utf8(output.stdout).unwrap(),
        stderr: String::from_utf8(output.stderr).unwrap(),
    }
}

/// A shared fixture of the SDK (`tests/fixtures`), embedded so the test
/// binary also runs where the sources are not, as CI runs it offline.
pub fn fixture(name: &str) -> Value {
    let text = match name {
        "anchors" => include_str!("../../../tests/fixtures/anchors.json"),
        "audit" => include_str!("../../../tests/fixtures/audit.json"),
        "canonical" => include_str!("../../../tests/fixtures/canonical.json"),
        "field_registry" => include_str!("../../../tests/fixtures/field_registry.json"),
        "grants" => include_str!("../../../tests/fixtures/grants.json"),
        "out_of_band" => include_str!("../../../tests/fixtures/out_of_band.json"),
        "python-vectors" => include_str!("../../../tests/fixtures/python-vectors.json"),
        "remediation" => include_str!("../../../tests/fixtures/remediation.json"),
        other => panic!("no fixture {other}"),
    };
    serde_json::from_str(text).unwrap()
}
