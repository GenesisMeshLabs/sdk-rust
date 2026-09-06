# Launch review - 2026-09-05

The local release checks passed. Changes remain uncommitted and unpublished.

## Fixes

- Correct Python-compatible canonical JSON for Unicode, control characters,
  supplementary Unicode characters, and floating-point notation.
- Redact the configured signing seed from debug output.
- Validate URL, key ID, timeout, and raw route configuration before requests.
- Prevent signed requests from following redirects and encode revocation IDs.
- Preserve HTTP status/error types for non-JSON and empty error responses.
- Reduce temporary allocations during canonical serialization and successful
  response decoding, while keeping existing domain method signatures.
- Restore the documented Rust 1.85 baseline with an MSRV-aware resolver and
  committed dependency lockfile.
- Replace incomplete examples with compiled examples and README doctests; add
  release metadata checks, explicit package contents, and CI for three platforms.

## Verified locally

| Check | Result |
|---|---|
| Rust 1.85.1, Linux Docker | 38 unit/integration tests and 2 README doctests passed |
| Rust 1.98.0 stable, Linux Docker | Same 40 tests passed; both examples compiled |
| Protocol coverage | All 22 domain methods covered by HTTP contract tests |
| Canonical JSON | 1,004 Python reference cases passed |
| Ed25519 | Python reference signature matched; transmitted signatures verified |
| Formatting and Clippy | Passed, warnings denied |
| Documentation | Built with rustdoc warnings denied |
| Release declarations | VERSION, manifest, lockfile, changelog agree at 0.56.0; invalid tag rejected |
| Packaging | 31 files; extracted crate builds; 27 packaged source/document/fixture files match the working tree |
| cargo-audit 0.22.2 | Passed against 1,239 advisories; 167 dependencies scanned; no reported vulnerabilities |
| Local NA smoke check | Runnable get_policy example reached the existing NA and returned typed NotFound/no_policy |
| Whitespace review | git diff --check passed |

Review artifact: `target/genesis-mesh-sdk-0.56.0.crate` (ignored build output).
SHA-256: `28b20543d7e58b1e57618c95dd23f0ecdbe3cfe046f36adbf9c1515871e820ac`.
The package was verified with `--allow-dirty` because this is an uncommitted
review snapshot. Rebuild from the clean release commit before publication.

## Outstanding launch actions

- Review and commit the changes, then obtain green Windows/macOS/Linux hosted CI.
- Verify authenticated workflows against the intended production NA and its
  actual keys, treaties, and policies. Mock HTTP and Python fixture tests do not
  establish production acceptance.
- Finalize the Unreleased changelog, confirm registry ownership/availability,
  and follow RELEASING.md for publication and post-publication verification.

No commits, pushes, release tags, or registry publication were performed.
