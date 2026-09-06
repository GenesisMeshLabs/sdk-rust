# Contributing to sdk-rust

Thank you for your interest in contributing to the Genesis Mesh Rust SDK.

## Prerequisites

| Tool | Minimum version |
|---|---|
| Rust | 1.85 |

## Set Up

```sh
git clone https://github.com/GenesisMeshLabs/sdk-rust.git
cd sdk-rust
cargo fetch
```

## Validate

```sh
cargo fmt --all -- --check
cargo clippy --locked --all-targets -- -D warnings
cargo test --locked --all-targets
cargo test --locked --doc
cargo package --locked
```

## Project Structure

Read [AGENT.md](AGENT.md) before changing source files. The short version:

| File | What goes here |
|---|---|
| `src/auth.rs` | Crypto only: canonical JSON, Ed25519 signing, admin headers |
| `src/client.rs` | HTTP transport and client composition |
| `src/errors.rs` | Typed SDK errors |
| `src/{domain}.rs` | Thin route wrappers |

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
