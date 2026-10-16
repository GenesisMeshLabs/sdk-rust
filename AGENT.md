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
    evidence.rs    # EvidenceClient (trust evidence)
    evidence_store.rs # EvidenceStoreClient, ResourceHead
    policy.rs      # PolicyClient (boundary policies)
    health.rs      # HealthClient
    canonical.rs   # canonical bodies, digests, Pydantic timestamps (pure)
    verify.rs      # offline verification, Python reason codes (pure)
    strict.rs      # strict verification: every signed field is in the registry (1.2.0, pure)
    strict_json.rs # strict JSON input: what parsers read differently is refused (1.2.0, pure)
    canonical_registry.json # the field registry, generated from the core's vector
    key_history.rs # NA key history and succession, which key is valid when (1.5.0, pure)
    audit_pack.rs  # audit pack verification and the completeness check (1.5.0, pure)
    execution.rs   # ExecutionRecorder, secret-material guard
    out_of_band.rs # ObservationRecorder, break-glass records (1.3.0)
    remediation.rs # remediation records, review checks, plans and the state table (1.4.0, pure)
    grants.rs      # pre-issued grants: envelopes, number rules, use rules, signing (1.6.0, pure)
    grant_client.rs # GrantClient: grant routes, time tokens, uses, the revocation feed (1.6.0)
    grant_holder.rs # GrantHolder: acts within a grant offline, uploads, falls back (1.6.0)
    node_auth.rs   # node request signatures, the edge join co-signature (1.7.0, pure)
    node.rs        # NodeClient, NodeIdentity, NodeJoin: a node's routes (1.7.0)
    outbox.rs      # evidence and record outboxes
    governance.rs  # governed_action, governed_action_with_break_glass, rotate_forward_then_disable, summarize_decision
    lib.rs         # public exports
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

Mirror the other official SDKs:

```text
auth.rs      = pure crypto: canonical JSON, digests, Ed25519 signing and verification, admin headers
canonical.rs = model canonical forms and digests (pure, no keys)
strict.rs, strict_json.rs = the field registry and strict JSON input (pure)
verify.rs, key_history.rs, audit_pack.rs = offline verification (pure, no network)
execution.rs, out_of_band.rs, remediation.rs, grants.rs, node_auth.rs, outbox.rs
             = records: build, sign and check them offline (no network)
errors.rs    = typed SDK errors only
client.rs    = HTTP transport and client composition (feature `client`)
{domain}.rs  = route wrappers over HttpTransport (feature `client`)
governance.rs, grant_holder.rs = orchestration over the sub-clients (feature `client`)
```

Do not mix layers. Domain clients must not contain signing logic. Auth code must
not make HTTP calls. Nothing above `client.rs` in this list may use the
network: they build without the `client` feature, which CI checks.

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
