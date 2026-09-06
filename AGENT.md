# AGENT.md - sdk-rust

Guidance for AI coding agents and human contributors working inside the
Genesis Mesh Rust SDK.

This SDK is a standalone crate. It does not import from the Python main repo.
It wraps the Network Authority HTTP API surface documented in:

- `genesismesh/docs/sdk/rust.md` when available
- `genesismesh/docs/api/trust-http.md` for stable HTTP routes

## Repo Layout

```text
sdk-rust/
  src/
    auth.rs        # canonical_json, load_signing_key, build_admin_headers
    client.rs      # ClientOptions, HttpTransport, GenesisMeshClient
    errors.rs      # GenesisMeshError and HTTP error mapping
    agreement.rs   # AgreementClient
    attestation.rs # AttestationClient
    boundary.rs    # BoundaryClient
    consensus.rs   # ConsensusClient
    data_usage.rs  # DataUsageClient
    disclosure.rs  # DisclosureClient
    evidence.rs    # EvidenceClient
    lib.rs         # public exports
  Cargo.toml
```

## Layer Rule

Mirror the other official SDKs:

```text
auth.rs      = pure crypto: canonical JSON, Ed25519 seed loading, admin headers
client.rs    = HTTP transport and client composition
errors.rs    = typed SDK errors only
{domain}.rs  = thin route wrappers over HttpTransport
```

Do not mix layers. Domain clients must not contain signing logic. Auth code must
not make HTTP calls.

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
cargo clippy --locked --all-targets -- -D warnings
cargo test --locked --all-targets
cargo test --locked --doc
```

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
