### Added

- **`genesis-mesh-verify`, the independent offline verifier.** A binary built
  from this crate verifies an audit pack as `genesis-mesh audit verify` does
  (`pack <dir> --anchor <root key>`, with `--known-anchors`,
  `--require-anchors`, `--prior`, `--prior-entries`, `--period`, `--report`,
  `--executor-keys`, `--changes` and `--tolerance-seconds`; the report it
  renders byte for byte and the differences from the pack's own
  `checks.json`), one signed
  record of any kind (`record <kind> <file>`), an evidence export (`export
  <file>`, with `--key-history`/`--root-key` or `--na-key`,
  `--executor-keys`, `--known-anchors`, `--checkpoint`, `--partial`,
  `--from-anchor` and `--cited` for a pack's range) and a key history (`key-history <file> --root-key`), with
  the Python reference's verdicts and reason codes, as readable text or JSON
  (`--json`), and one exit code per verdict: 0 verified, 1 not verified, 2
  usage error, 3 unreadable input. It passes the core's verification corpus
  (169 cases) and verifies the frozen 1.5.0 pack. It never needs a private
  key and never contacts a network: clippy rules, tests and CI enforce both.
  See `docs/verifier.md`.
- **Static, signed and reproducible release binaries.** Each release attaches
  `genesis-mesh-verify` for x86-64 and arm64 Linux (musl, statically linked),
  with SHA-256 checksums, Sigstore bundles and build info.
  `scripts/build_verifier.sh` pins the toolchain, the crates, the build time
  and the recorded paths, so a security team can rebuild a release and
  compare digests; CI builds each binary twice and compares them.
- **`verify::verify_record`** verifies one record as an export verifies it,
  with the same reason codes and order: every entry kind, a policy or an
  attestation (`VerifyRecordOptions`, `RecordVerification`,
  `verify::RECORD_KINDS`).
- **NA key succession.** `key_history::verify_key_history` verifies the
  genesis block (held to the rules of every signed record) and the key
  successions, each signed by the root key, the new key and the outgoing
  key, from the root key held, with the reference's checks and reason codes
  in its order: `genesis_invalid`, `genesis_root_mismatch`, `unknown_field`,
  `non_canonical_form`, `genesis_invalid_signature`; then per succession
  `payload_invalid`, `unknown_field` or `invalid_signature`,
  `non_canonical_form`, `succession_sovereign_mismatch`,
  `succession_chain_break`, `succession_key_reused` (also the root key),
  `succession_backdated`, `succession_not_increasing`,
  `succession_after_expiry`, `succession_invalid_root_signature`,
  `succession_invalid_new_key_signature`,
  `succession_invalid_previous_signature`. Given the history, exports,
  anchors, decisions and records accept an NA signature only by the key
  valid at the record's own time (in the store, also at the latest earlier
  entry's time), with the 300-second hand-over (`na_key_not_valid_at_time`);
  a decision may not outlive its key by more than the hand-over and the
  300-second lifetime cap (`decision_outlives_key`); entries are in time
  order within 300 seconds (`recorded_at_out_of_order`); key succession
  entries must be the history's (`succession_not_in_history`) and recorded
  60 seconds ahead (`succession_backdated`). Executor and observer keys are
  placed where the store registered and retired them
  (`evidence_unknown_executor`, `evidence_executor_key_retired`), and a record
  read alone is placed at its own time (`key_history::NA_RECORD_TIME_FIELDS`).
- **Audit packs.** `audit_pack::verify_audit_pack` checks a pack offline as
  the reference does, its check groups in order with their reason codes
  (among them `manifest_unknown_file`, `manifest_backdated`,
  `cited_entry_mismatch`, `report_mismatch`, `pack_period_not_covered`, and
  the warnings `cited_entry_unanchored`, `changes_outside_period`,
  `change_duplicate`); `render_report` renders `report.md` byte for byte;
  `check_completeness` matches a pack against a log of changes kept
  elsewhere (strict RFC 3339 times, duplicates set aside, the best overall
  pairing).
- **Store anchors, as the reference checks them.**
  `verify::verify_store_anchors`, `verify::check_events_against_anchors`,
  `verify::parse_anchors`, `verify::check_anchors`, `verify::export_checkpoint`,
  `canonical::anchor_canonical` and `canonical::anchor_digest`, with the
  reference's reason codes (`anchor_invalid_signature`,
  `anchor_sovereign_mismatch`, `anchor_sequence_gap`, `anchor_chain_break`,
  `anchor_not_increasing`, `anchor_mismatch`, `anchor_entry_missing`,
  `export_not_linked_to_anchors`, `export_ends_before_anchor`), checked
  against vectors the reference generated (`tests/fixtures/anchors.json`).
