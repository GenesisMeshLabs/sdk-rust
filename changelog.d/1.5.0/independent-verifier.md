### Added

- **`genesis-mesh-verify`, the independent offline verifier.** A binary built
  from this crate's `verify` module verifies one signed record of any kind
  (`record <kind> <file>`) or an evidence export (`export <file>`, with
  `--na-key`, `--executor-keys`, `--known-anchors`, `--checkpoint`,
  `--partial` and `--from-anchor`), with the Python reference's verdicts and
  reason codes, as readable text or JSON (`--json`), and one exit code per
  verdict: 0 verified, 1 not verified, 2 usage error, 3 unreadable input, 4
  not available (`pack`, until the audit pack format is final). It never
  needs a private key and never contacts a network: clippy rules, tests and
  CI enforce both. See `docs/verifier.md`.
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
- **Store anchors, as the reference checks them.**
  `verify::verify_store_anchors`, `verify::check_events_against_anchors`,
  `verify::parse_anchors`, `verify::check_anchors`, `verify::export_checkpoint`,
  `canonical::anchor_canonical` and `canonical::anchor_digest`, with the
  reference's reason codes (`anchor_invalid_signature`,
  `anchor_sovereign_mismatch`, `anchor_sequence_gap`, `anchor_chain_break`,
  `anchor_not_increasing`, `anchor_mismatch`, `anchor_entry_missing`,
  `export_not_linked_to_anchors`, `export_ends_before_anchor`), checked
  against vectors the reference generated (`tests/fixtures/anchors.json`).
