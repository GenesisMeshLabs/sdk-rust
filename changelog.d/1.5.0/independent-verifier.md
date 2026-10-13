### Added

- **`genesis-mesh-verify`, the independent offline verifier.** A binary built
  from this crate verifies an audit pack as `genesis-mesh audit verify` does
  (`pack <dir> --anchor <root key>`, with `--known-anchors`,
  `--executor-keys`, `--changes` and `--tolerance-seconds`, and the
  differences from the pack's own `checks.json` and `report.md`), one signed
  record of any kind (`record <kind> <file>`), an evidence export (`export
  <file>`, with `--key-history`/`--root-key` or `--na-key`,
  `--executor-keys`, `--known-anchors`, `--checkpoint`, `--partial` and
  `--from-anchor`) and a key history (`key-history <file> --root-key`), with
  the Python reference's verdicts and reason codes, as readable text or JSON
  (`--json`), and one exit code per verdict: 0 verified, 1 not verified, 2
  usage error, 3 unreadable input. It passes the core's verification corpus
  (115 cases) and verifies the frozen 1.5.0 pack. It never needs a private
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
  genesis block and the key successions from the root key held, with the
  reference's checks and reason codes in its order (`genesis_invalid`,
  `genesis_root_mismatch`, `genesis_invalid_signature`, `payload_invalid`,
  `invalid_signature`, `unknown_field`, `non_canonical_form`,
  `succession_sovereign_mismatch`, `succession_chain_break`,
  `succession_key_reused`, `succession_not_increasing`,
  `succession_after_expiry`, `succession_invalid_root_signature`,
  `succession_invalid_previous_signature`). Given the history, exports,
  anchors, decisions and records accept an NA signature only by the key
  valid at the record's own time, with the 300-second hand-over
  (`na_key_not_valid_at_time`); key succession entries must be the history's
  (`succession_not_in_history`). Archive and key succession entries verify.
- **Audit packs.** `audit_pack::verify_audit_pack` checks a pack offline as
  the reference does, the six check groups in order with their reason codes;
  `check_completeness` matches it against a log of changes kept elsewhere.
- **Store anchors, as the reference checks them.**
  `verify::verify_store_anchors`, `verify::check_events_against_anchors`,
  `verify::parse_anchors`, `verify::check_anchors`, `verify::export_checkpoint`,
  `canonical::anchor_canonical` and `canonical::anchor_digest`, with the
  reference's reason codes (`anchor_invalid_signature`,
  `anchor_sovereign_mismatch`, `anchor_sequence_gap`, `anchor_chain_break`,
  `anchor_not_increasing`, `anchor_mismatch`, `anchor_entry_missing`,
  `export_not_linked_to_anchors`, `export_ends_before_anchor`), checked
  against vectors the reference generated (`tests/fixtures/anchors.json`).
