//! The readable form of a result.

use std::fmt::Write as _;

use genesis_mesh_sdk::verify::{
    AnchorCoverage, EvidenceVerification, RecordVerification, VerificationFailure,
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
