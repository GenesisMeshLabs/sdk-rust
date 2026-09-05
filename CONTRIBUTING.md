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
cargo clippy --all-targets -- -D warnings
cargo test --all
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
