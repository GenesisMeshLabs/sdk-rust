# Genesis Mesh Rust SDK

Async Rust client for the Genesis Mesh Network Authority HTTP API, with
Ed25519 admin authentication, shared connection pooling, Rustls TLS, and typed errors.
Requires **Rust 1.85 or newer** and a Tokio runtime.

## Install

Install from the source repository; commit your application's `Cargo.lock` to
keep the selected revision reproducible:

```toml
[dependencies]
genesis-mesh-sdk = { git = "https://github.com/GenesisMeshLabs/sdk-rust" }
tokio = { version = "1", features = ["macros", "rt-multi-thread"] }
```

## Quick start: read the active policy

This public route requires a running Network Authority with an active data usage
policy. A server with no configured policy can return `NotFound`.

```no_run
use genesis_mesh_sdk::{ClientOptions, GenesisMeshClient};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let url = std::env::var("NA_URL")
        .unwrap_or_else(|_| "http://127.0.0.1:9443".into());
    let client = GenesisMeshClient::new(ClientOptions::new(url))?;
    let policy = client.data_usage.get_policy().await?;
    println!("{policy:#}");
    Ok(())
}
```

Run the equivalent checked example with `cargo run --example get_policy`.
Use HTTPS when connecting to a remote Network Authority.

## Local Network Authority

To develop against a governed Network Authority on your machine (policies
required, a privileged key for setup and a standard key for your controller),
see [Develop Against a Local Network Authority](https://docs.genesismesh.org/sdk/local-network-authority.html).
It needs `genesis-mesh` 1.1.0 or later from PyPI.

## Admin requests

Register the operator public key with the Network Authority first (for a local
Network Authority, `genesis-mesh keygen operator --env-file` does it). `OPERATOR_KEY`
is the standard base64 encoding of the **32-byte Ed25519 seed**, with or without
padding; PEM files and 64-byte keypairs are not accepted. Keep the seed in a secret
store or environment variable, outside source control.

```no_run
use genesis_mesh_sdk::{json, ClientOptions, GenesisMeshClient};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let client = GenesisMeshClient::new(
        ClientOptions::new(std::env::var("NA_URL")?)
            .with_signing_key(std::env::var("OPERATOR_KEY")?)
            .with_key_id("operator-local"),
    )?;
    let attestation = client.attestation.issue(json!({
        "subject_id": "node-example",
        "roles": ["role:client"],
        "validity_hours": 24
    })).await?;
    println!("{attestation:#}");
    Ok(())
}
```

Run `cargo run --example issue_attestation` with `NA_URL`, `OPERATOR_KEY`, and
optionally `OPERATOR_KEY_ID` set. This example creates an attestation on your NA.

## API coverage

Request and response bodies use `serde_json::Value` (also exported as `Value`),
retaining the server's snake_case wire fields. Decisions, policies and evidence
can also be verified locally (see [Governed actions](#governed-actions)).

| Client | Admin methods | Public methods |
|---|---|---|
| `agreement` | `offer`, `counter`, `accept` | `verify` |
| `attestation` | `issue`, `revoke`, `save_policy` | |
| `boundary` | `evaluate`, `decide` | `verify` |
| `consensus` | `vote`, `proof` | `verify` |
| `data_usage` | `create_policy`, `create_intent` | `get_policy`, `verify` |
| `disclosure` | `commit`, `nullifier` | `prove`, `verify` |
| `evidence` | `build` | `verify` |
| `policy` | `validate`, `publish`, `list`, `active`, `history`, `activate`, `deactivate` | `verify` |
| `evidence_store` | `search`, `search_all`, `status`, `verify`, `resource_history`, `vendor_history`, `resource_head`, `export_text`, `export`, `export_all`, `list_executor_keys`, `register_executor_key`, `retire_executor_key`, `apply_retention`, `latest_checkpoint` | `submit` (executor-signed) |
| `health` | | `liveness`, `readiness`, `health` |

`evidence.build(decision)` wraps its argument as `{"decision": decision}`.
`attestation.revoke(id, None)` sends an empty JSON object; pass `Some(json!(...))`
to include a reason. IDs are encoded as single URL path segments; resource IDs
such as `kv:vault/secret` span segments, and `.` or `..` segments are refused
before anything is sent. Admin reads are signed GETs over an empty body `{}`.
`boundary.evaluate` takes exactly one basis (`attestation_id` or `agreement`) and
returns `{decision, justification_proof}`; a denial is a signed decision, not an
error. `evidence_store.resource_head` reads `/admin/evidence/resource-heads`
(NA 0.63.1+) and falls back to the resource history on older NAs.

Consult the [Trust HTTP API contract](https://github.com/GenesisMeshLabs/genesismesh/blob/main/docs/api/trust-http.md)
for complete request fields and prerequisites. In particular, boundary decisions
require an `agreement` and `requested_capability`; agreement acceptance requires
an active recognition treaty. Disclosure proofs require the original capability
set, commitment, and prover identity.

## Governed actions

`governed_action` evaluates a request, verifies the decision offline (signature,
expiry, context, attestation and exact policy bindings), runs your action only on
ALLOW, then signs execution evidence with an `ExecutionRecorder` and submits it,
linked to the resource's chain head:

```no_run
use genesis_mesh_sdk::{
    governed_action, json, ActionError, ActionReport, ClientOptions, ExecutionRecorder,
    GenesisMeshClient, GovernedActionParams, GovernedVerification, Value,
};

async fn rotate(gm: &GenesisMeshClient, attestation: Value, policy: Value, na_key: String)
    -> Result<(), Box<dyn std::error::Error>> {
    let recorder = ExecutionRecorder::new("controller", "controller", &std::env::var("EXECUTOR_KEY")?)?;
    let result = governed_action(&gm.boundary, &gm.evidence_store, &recorder, GovernedActionParams {
        evaluate: json!({"attestation_id": attestation["attestation_id"],
                         "requested_capability": "sp-secret.rotate",
                         "context": {"request_parameters": {"app_id": "billing"}}}),
        resource_id: Some("kv:pilot-vault/billing-api".into()),
        resource_action: Some("rotate".into()),
        prior_resource: None,
        verify: GovernedVerification {
            operator_public_keys: vec![na_key],
            expected_policies: vec![policy],
            expected_attestation: Some(attestation),
            ..Default::default()
        },
    }, |_decision| async move {
        Ok::<_, ActionError>(ActionReport::<()> {
            execution_parameters: Some(json!({"secret_version": "v3"})),
            ..Default::default()
        })
    }).await?;
    println!("authorized: {}", result.authorized);
    Ok(())
}
```

A denial returns `authorized: false` without running the action. A failed action
is recorded as a `failure` record without its error text (`ActionFailed`).
Metadata that looks like secret material, or exceeds 16 KiB, is refused before
signing (`SecretMaterial`). `verify::verify_evidence_events` checks an export
offline with the same reason codes as the Python reference, and
`verify::verify_boundary_decision` checks one decision.

## Transport and errors

Construct one client and clone it for concurrent work. Clones and sub-clients share
the connection pool and parsed signing key. No runtime is created by the SDK.

- The request timeout defaults to 10 seconds. Override it with
  `ClientOptions::with_timeout(Duration::from_secs(30))`.
- Key IDs must be ASCII header values without surrounding whitespace.
- Base URLs must be absolute HTTP(S) URLs without embedded credentials, query
  strings, or fragments. Reverse-proxy base paths are supported.
- Redirects are returned as HTTP errors, so signed requests stay at their configured
  endpoint. Set the final NA URL directly.
- Requests are not automatically retried. A timed-out mutation may have completed
  on the server; check its state before retrying.
- `GenesisMeshError` distinguishes configuration, missing/invalid signing keys,
  transport, JSON, and HTTP failures. HTTP 400, 401, 404, 422, and 429 map to
  `BadRequest`, `Unauthorized`, `NotFound`, `Validation`, and `RateLimit`.
  Other statuses retain their numeric code in `Http`.
- Non-JSON error responses preserve the HTTP status and response text. Empty
  successful responses deserialize from `{}`; malformed success JSON is an error.

For additional routes, `HttpTransport` exposes generic `admin_post`, `public_post`,
and `public_get` methods. Route paths start with `/`.

## Authentication contract

| Header | Value |
|---|---|
| `X-Admin-Key-Id` | Registered operator key identifier (default `operator-local`) |
| `X-Admin-Signature` | Base64 Ed25519 signature over the canonical payload |
| `X-Admin-Timestamp` | UTC ISO 8601 timestamp with milliseconds |
| `X-Admin-Nonce` | Fresh UUID v4 for each signed request |

The signed payload (signature version 2, 1.0.2) is
`{v: 2, method, path, query, audience, body, key_id, timestamp, nonce}`: the HTTP
method, the decoded request path, the query parameters, the target NA's public
key and the JSON body, serialized to match the server's Python
`json.dumps(..., sort_keys=True, separators=(",", ":"))`, including ASCII escaping
and float formatting. The client reads the NA's public key
(`network_authority.public_key`) once from its public `/sovereign.json`, or uses `ClientOptions::with_audience`. Tests include
Python-generated fixtures and the shared `admin_auth.json` vectors. Maintain an
accurate system clock so the server accepts timestamps.

`load_signing_key`, `canonical_json`, `admin_signing_payload`, and
`build_admin_headers` (with an `AdminRequest`) are available for custom
integrations. When using raw headers, send the same JSON body that was
signed. `ClientOptions` debug output redacts the seed.

## Development and release

```sh
python scripts/check_release.py
cargo fmt --all -- --check
cargo clippy --locked --all-targets -- -D warnings
cargo test --locked --all-targets
cargo test --locked --doc
cargo doc --locked --no-deps
cargo package --locked
```

CI tests stable Rust on Linux, Windows, and macOS plus Rust 1.85 on Linux, checks
release metadata and packaging, and audits dependencies with `cargo audit`.
See [CONTRIBUTING.md](https://github.com/GenesisMeshLabs/sdk-rust/blob/main/CONTRIBUTING.md), [RELEASING.md](https://github.com/GenesisMeshLabs/sdk-rust/blob/main/RELEASING.md), and
[SECURITY.md](https://github.com/GenesisMeshLabs/sdk-rust/blob/main/SECURITY.md).

## License

[MIT](https://github.com/GenesisMeshLabs/sdk-rust/blob/main/LICENSE)
