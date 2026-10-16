## What changed

<!-- What this pull request changes and why, in 2-4 sentences. Title it with a
conventional prefix (feat:, fix:, docs:, test:, ci:, chore:). Keep it to one
concern: a stage that spans the SDK, the verifier and the edge agent goes in
stacked pull requests. -->

## How it was tested

<!-- Commands you ran and what they showed (see CONTRIBUTING.md): cargo fmt,
cargo clippy --workspace, cargo test --workspace, the build without the
client feature, and the live tests (--include-ignored with GM_E2E_PYTHON) if
you changed a client method, the live lifecycle or the edge agent. -->

## Bug fix

Bug fix: the test that fails without this change is ___

<!-- Name the test and say how you saw it fail without the fix. A pull request
titled "fix: ..." that changes source files must change a test (under a
tests/ directory, or a #[test] in the module), or carry the label
no-test-needed, which only the Maintainer adds. Write "not a bug fix"
otherwise. -->

## Changelog

- [ ] A fragment `changelog.d/<version>/<short-name>.md` describes the change
      for users (see `changelog.d/README.md`), or the change needs none
      (CI, tests, repository docs).
- [ ] `CHANGELOG.md` is not edited (only a `release/<version>` pull request
      folds the fragments into it).

## Breaking change

- [ ] No public API or behaviour changes for callers.
- [ ] Callers see a change (a new field in a public struct, a new enum
      variant, a changed signature or default): the fragment has an
      `### Upgrading` section that says what changes for them and what to do.

## Flagged paths

These need the Maintainer's review and merge. Tick any this pull request touches:

- [ ] Contract: the public API (`src/lib.rs` exports, `src/client.rs`,
      `src/errors.rs`, the sub-clients) or the wire format of a request or
      response
- [ ] Vectors and registry: `tests/fixtures/`, `src/canonical_registry.json`
- [ ] Signing and verification: `src/auth.rs`, `src/canonical.rs`,
      `src/verify.rs`, `src/strict.rs`, `src/strict_json.rs`,
      `src/key_history.rs`, `src/audit_pack.rs`, `src/grants.rs`,
      `src/node_auth.rs`, `src/execution.rs`, `verifier/`,
      `edge/src/decision.rs`, the `clippy.toml` deny-lists
- [ ] Edge agent storage: `edge/src/db.rs` (the on-device database)
- [ ] Workflows: `.github/`
- [ ] `SECURITY.md`
- [ ] Packaging and release: `Cargo.toml` files, `Cargo.lock`, `VERSION`,
      `scripts/build_*.sh`, `scripts/check_release.py`, `edge/packaging/`,
      `edge/Dockerfile`

## Related issues

<!-- Closes #, Fixes #, or "None". -->
