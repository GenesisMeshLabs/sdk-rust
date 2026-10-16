# AGENT.md - sdk-rust

Guidance for AI coding agents and human contributors working inside the
Genesis Mesh Rust SDK.

This SDK is a standalone crate. It does not import from the Python main repo.
It wraps the Network Authority HTTP API surface documented in:

- `genesismesh/docs/sdk/rust/` (`index.md`, `sdk.md`, `auth.md`, `usage.md`)
- `genesismesh/docs/api/trust-http.md` for stable HTTP routes

## Repo Layout

```text
sdk-rust/
  src/             # the crate: module map and layers in docs/architecture.md
  verifier/        # genesis-mesh-verify (1.5.0): the offline verifier binary, a workspace member
    src/           # command line only; verification is the crate's verify module
    clippy.toml    # refuses network and signing code in the binary
    tests/         # CLI tests and the differential harness (adapter/ reads reference vectors)
  edge/            # genesis-mesh-edge (1.7.0, beta): the edge agent, a workspace member
    src/           # config, state files, SQLite outboxes, the decision order, the local API
    clippy.toml    # refuses the SDK's admin signing: no operator key on the device
    tests/         # scenario.rs against a live NA (enrolment, offline, stale, local auth)
    packaging/     # the systemd unit and the example configuration
  scripts/build_verifier.sh  # the reproducible static release build
  scripts/build_edge.sh      # the edge agent's static release build
  Cargo.toml
```

## Layer Rule

[docs/architecture.md](docs/architecture.md) is the module map: eight
layers, from errors and strict JSON up to the orchestration over the
sub-clients, and the rule that a module uses only its own layer and those
below it, with no import cycle. `tests/architecture.rs` enforces the same
table; a new module must be placed there. The page also lists where each
common change goes and the test that catches a missed file.

Do not mix layers. Domain clients must not contain signing logic. Auth code must
not make HTTP calls. The offline layers (everything below the transport)
build without the `client` feature, which CI checks. Shared helpers go down
to a lower module (`rules`, `shape`, `outbox_entry`), never sideways.

## MVP Scope

The MVP intentionally uses `serde_json::Value` for request and response bodies.
This keeps the crate aligned with the live JSON protocol while the Rust-specific
typed model layer is still being hardened.

Do not add custom typed structs casually. Add them only when the corresponding
wire contract is stable and covered by tests.

## Protocol Constraints

| Constraint | Detail |
|---|---|
| Evidence verdict | Must be `"allow"` \| `"block"` \| `"escalate"` \| `"warn"`. |
| Role prefixes | Roles must start with `role:anchor`, `role:bridge`, `role:client`, `role:operator`, or `role:service:<name>`. |
| Agreement accept | Requires the NA to hold an active recognition treaty for the responder. |
| Data source descriptors | `source_id`, `source_type`, and `owner_sovereign_id` are required. |

## Development

Run before committing:

```sh
cargo fmt --all -- --check
cargo clippy --locked --workspace --all-targets -- -D warnings
cargo test --locked --workspace --all-targets
cargo test --locked --doc
```

The live tests (`tests/live_na.rs`, `edge/tests/scenario.rs`) are
`#[ignore]`d in a plain run; CONTRIBUTING.md shows how to run them.

The default feature `client` (1.7.0) gates the HTTP client and every module
that calls the NA; the offline modules (`verify`, `canonical`, `strict`,
`strict_json`, `auth`, `errors`, `execution`, `out_of_band`, `outbox`,
`grants`, `key_history`, `audit_pack`, `remediation`, `node_auth`) build
without it. Check both:
`cargo test --locked -p genesis-mesh-sdk --no-default-features`.

`genesis-mesh-verify` never needs a private key and never contacts a network:
keep the binary's code to the crate's offline modules (`verify`, `canonical`,
`strict`, strict JSON); `verifier/clippy.toml` and its tests refuse the rest.

Rust can be validated through Docker when native tooling is unavailable.
Record the actual toolchain and platform used; Linux container checks do not
establish Windows or macOS compatibility. CI covers all three platforms.

## Agent Behavior Rules

1. Read this file before making changes.
2. Preserve layer boundaries.
3. Match the Network Authority wire format exactly; JSON fields are snake_case.
4. Keep security-sensitive code boring and explicit.
5. Do not log or print from SDK source.
6. Do not add routes that the Network Authority does not expose.
7. Add tests for every new public method or auth/error behavior.
