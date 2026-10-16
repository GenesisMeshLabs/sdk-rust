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
cargo check --locked -p genesis-mesh-sdk --no-default-features --all-targets
cargo test --locked -p genesis-mesh-sdk --no-default-features
cargo package --locked
python scripts/check_release.py
python scripts/changelog.py check --base origin/main --branch "$(git branch --show-current)"
```

On Windows, add `--exclude genesis-mesh-edge` to the workspace test (the edge
agent is Unix only).

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

Read [AGENT.md](AGENT.md) before changing source files. The short version:

| File | What goes here |
|---|---|
| `src/auth.rs` | Crypto only: canonical JSON, Ed25519 signing, admin headers |
| `src/canonical.rs`, `src/verify.rs`, `src/strict.rs`, ... | Offline modules: no network, built without the `client` feature |
| `src/client.rs` | HTTP transport and client composition |
| `src/errors.rs` | Typed SDK errors |
| `src/{domain}.rs` | Route wrappers over the transport (sub-clients) |
| `src/governance.rs`, `src/grant_holder.rs` | Orchestration over the sub-clients |
| `verifier/` | The offline verifier binary |
| `edge/` | The edge agent (beta) |

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
