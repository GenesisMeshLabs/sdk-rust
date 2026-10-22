# Contributing to sdk-rust

Thank you for your interest in contributing to the Genesis Mesh Rust SDK.

## Prerequisites

| Tool | Minimum version |
|---|---|
| Rust | 1.85 (the SDK and the verifier); 1.89 for the edge agent (`edge/`, Unix only) |
| Python | 3.11+, for `scripts/` and, with the Genesis Mesh core installed, the live tests |

## Set Up

```sh
git clone https://github.com/GenesisMeshLabs/sdk-rust.git
cd sdk-rust
cargo fetch
```

## Validate

The workspace holds the SDK, `genesis-mesh-verify` (`verifier/`) and
`genesis-mesh-edge` (`edge/`); check all three, and the SDK without its
default `client` feature (the offline modules the verifier builds on):

```sh
cargo fmt --all -- --check
cargo clippy --locked --workspace --all-targets -- -D warnings
cargo test --locked --workspace --all-targets
cargo test --locked --doc
cargo doc --locked --workspace --no-deps
cargo check --locked -p genesis-mesh-sdk --no-default-features --all-targets
cargo test --locked -p genesis-mesh-sdk --no-default-features
cargo package --locked
python scripts/check_release.py
python scripts/changelog.py check --base origin/main --branch "$(git branch --show-current)"
```

On Windows, add `--exclude genesis-mesh-edge` to the workspace clippy, test
and doc commands, before any `--` (the edge agent is Unix only):
`cargo clippy --locked --workspace --exclude genesis-mesh-edge --all-targets -- -D warnings`,
`cargo test --locked --workspace --exclude genesis-mesh-edge --all-targets`
and `cargo doc --locked --workspace --exclude genesis-mesh-edge --no-deps`.

The tests against a live Network Authority (`tests/live_na.rs`) and the edge
agent's scenarios (`edge/tests/scenario.rs`) are `#[ignore]`d in a plain
run. Run them with a Python that has the Genesis Mesh core installed:

```sh
GM_E2E_PYTHON=python cargo test --locked --test live_na -- --include-ignored
GM_E2E_PYTHON=python cargo test --locked -p genesis-mesh-edge --test scenario -- --include-ignored
```

CI sets `GM_E2E_REQUIRED=1`, which turns every skip (no NA, or a part the NA
cannot exercise) into a failure.

## Pull Requests

Fill in the pull request template. A pull request titled `fix: ...` that
changes source files carries the test that fails without the fix (the
`Regression test` check), and every change for users adds a changelog
fragment (`changelog.d/README.md`) instead of editing `CHANGELOG.md`.

## Project Structure

[docs/architecture.md](docs/architecture.md) maps the modules and their
layers (which module may use which; `tests/architecture.rs` enforces it) and
lists, for the common changes (a record kind, a sub-client method, an error
code, a conformance suite, an edge endpoint or setting), the files to touch
and the test that fails when one is missed. Read it, and
[AGENT.md](AGENT.md), before changing source files.

## Commit Messages

Use Conventional Commits:

```text
feat(auth): support raw ed25519 seed signing
fix(errors): map nested NA validation errors
docs(readme): add disclosure example
```

## Security

Do not open public issues for vulnerabilities. Follow [SECURITY.md](SECURITY.md).

The committed lockfile supports reproducible CI. Run `cargo update` with the
MSRV-aware resolver and test Rust 1.85 before dependency updates. Python 3.11+
is needed for `python scripts/check_release.py`.
