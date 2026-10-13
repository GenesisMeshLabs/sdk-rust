//! The readable form of a result.

use std::fmt::Write as _;

use genesis_mesh_sdk::{
    audit_pack::PackVerification,
    key_history::KeyHistoryVerification,
    verify::{AnchorCoverage, EvidenceVerification, RecordVerification, VerificationFailure},
    Value,
};

fn failures(out: &mut String, failures: &[VerificationFailure]) {
    for f in failures {
        let at = f
            .store_sequence
            .map_or_else(|| "-".to_owned(), |s| s.to_string());
        let line = format!("#{at}: {} {}", f.reason, f.detail);
        let _ = writeln!(out, "  - {}", line.trim_end());
    }
}

/// A record's result.
pub fn record(result: &RecordVerification) -> String {
    let mut out = String::new();
    let id = result.record_id.as_deref().unwrap_or("(no id)");
    let _ = writeln!(out, "Record     : {} {id}", result.kind);
    if let Some(authorized) = result.authorized {
        let verdict = if authorized { "allows" } else { "denies" };
        let _ = writeln!(out, "Decision   : {verdict} its action");
    }
    if result.verified {
        let _ = writeln!(out, "Result     : VERIFIED ({})", result.reason);
    } else {
        let _ = writeln!(out, "Result     : FAILED");
        for f in &result.failures {
            let line = format!("{} {}", f.reason, f.detail);
            let _ = writeln!(out, "  - {}", line.trim_end());
        }
    }
    for w in &result.warnings {
        let _ = writeln!(out, "Warning    : {} {}", w.reason, w.detail);
    }
    out
}

/// A pack's result, in the reference CLI's readable form, with where it
/// differs from what the pack says of itself.
pub fn pack(result: &PackVerification, differences: &[Value]) -> String {
    let mut out = String::new();
    let range = |key: &str| {
        result
            .range
            .get(key)
            .map_or("None".to_owned(), Value::to_string)
    };
    let _ = writeln!(
        out,
        "Range      : entries {} to {} ({} entries)",
        range("from_sequence"),
        range("through_sequence"),
        range("entries")
    );
    let counts: Vec<String> = result
        .counts
        .iter()
        .filter(|(k, v)| **v > 0 && k.as_str() != "checked_entries")
        .map(|(k, v)| format!("{k} {v}"))
        .collect();
    let counts = if counts.is_empty() {
        "none".to_owned()
    } else {
        counts.join(", ")
    };
    let _ = writeln!(out, "Records    : {counts}");
    let _ = writeln!(out, "NA keys    : {} in the key history", result.keys.len());
    if let Some(c) = &result.completeness {
        let len = |key: &str| c[key].as_array().map_or(0, Vec::len);
        let _ = writeln!(
            out,
            "Changes    : {}: {} matched, {} without a record, {} outside the period, {} records without a change",
            c["changes"],
            len("pairs"),
            len("unmatched_changes"),
            len("outside_period"),
            len("unmatched_records")
        );
    }
    if let Some(period) = &result.period {
        let at = |key: &str| period.get(key).and_then(Value::as_str).unwrap_or_default();
        let _ = writeln!(out, "Period     : {} to {}", at("from"), at("until"));
    }
    let verdict = if result.verified {
        "VERIFIED"
    } else {
        "FAILED"
    };
    let _ = writeln!(out, "Result     : {verdict}");
    for f in &result.failures {
        let at = f
            .store_sequence
            .map_or_else(|| "None".to_owned(), |s| s.to_string());
        let line = format!(
            "{} #{at}: {} {}",
            f.file.as_deref().unwrap_or("-"),
            f.reason,
            f.detail
        );
        let _ = writeln!(out, "  - {}", line.trim_end());
    }
    let unanchored = result
        .warnings
        .iter()
        .filter(|w| w.reason == "cited_entry_unanchored")
        .count();
    for w in result
        .warnings
        .iter()
        .filter(|w| w.reason != "cited_entry_unanchored")
    {
        let at = w
            .store_sequence
            .map_or_else(|| "None".to_owned(), |s| s.to_string());
        let line = format!(
            "{} #{at}: {} {}",
            w.file.as_deref().unwrap_or("-"),
            w.reason,
            w.detail
        );
        let _ = writeln!(out, "  ~ {}", line.trim_end());
    }
    if unanchored > 0 {
        let _ = writeln!(
            out,
            "  ~ {unanchored} cited entries are covered by no prior pack and no held anchor              (cited_entry_unanchored): their signatures verify, their place in the store is not proven"
        );
    }
    for d in &result.report_differences {
        let _ = writeln!(
            out,
            "  ! report.md line {}: pack {}, rendered {}",
            d["line"], d["pack"], d["verifier"]
        );
    }
    for d in differences {
        let _ = writeln!(
            out,
            "  ! differs from the pack's own checks: {}: pack {}, here {}",
            d["field"].as_str().unwrap_or_default(),
            d["pack"],
            d["verifier"]
        );
    }
    out
}

/// A key history's result.
pub fn key_history(result: &KeyHistoryVerification) -> String {
    let mut out = String::new();
    for key in result.history.iter().flat_map(|h| h.keys.iter()) {
        let shown = key.to_json();
        let at = |field: &str| shown[field].as_str().unwrap_or("-").to_owned();
        let until = if key.succeeded_at.is_some() {
            at("succeeded_at")
        } else {
            at("valid_to")
        };
        let _ = writeln!(
            out,
            "Key {}      : {} ({}), from {} until {}{}",
            key.key_sequence,
            key.public_key,
            key.key_id.as_deref().unwrap_or("no id"),
            at("valid_from"),
            until,
            if key.valid_to_enforced {
                ""
            } else {
                " (end not enforced)"
            }
        );
    }
    let verdict = if result.verified {
        "VERIFIED"
    } else {
        "FAILED"
    };
    let _ = writeln!(out, "Result     : {verdict}");
    for f in &result.failures {
        let _ = writeln!(
            out,
            "  - key {}: {}",
            f.key_sequence.unwrap_or_default(),
            f.reason
        );
    }
    out
}

/// An export's result, in the reference CLI's readable form.
pub fn export(result: &EvidenceVerification, anchors: Option<&AnchorCoverage>) -> String {
    let mut out = String::new();
    let _ = writeln!(out, "Entries    : {}", result.checked_entries);
    let _ = writeln!(out, "Decisions  : {}", result.decisions);
    let _ = writeln!(out, "Executions : {}", result.executions);
    for (label, count) in [
        ("Observations", result.observations),
        ("Break-glass", result.break_glass),
        ("Judgements", result.judgements),
        ("Quarantined", result.quarantined),
        ("Remediations", result.remediations),
        ("Reviews", result.reviews),
    ] {
        if count > 0 {
            let _ = writeln!(out, "{label:<11}: {count}");
        }
    }
    if let Some(a) = anchors {
        let through = a
            .anchored_through_sequence
            .map_or_else(|| "None".to_owned(), |s| s.to_string());
        let _ = writeln!(
            out,
            "Anchors    : {} matched of {}; anchored through #{through}; {} entries after the last anchor",
            a.anchors_matched, a.anchors_checked, a.unanchored_entries
        );
    }
    let verdict = if result.verified {
        "VERIFIED"
    } else {
        "FAILED"
    };
    let _ = writeln!(out, "Result     : {verdict}");
    failures(&mut out, &result.failures);
    for w in &result.warnings {
        let at = w
            .store_sequence
            .map_or_else(|| "-".to_owned(), |s| s.to_string());
        let _ = writeln!(out, "Warning    : #{at}: {} {}", w.reason, w.detail);
    }
    out
}
