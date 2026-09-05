# sdk-rust

Rust SDK for the Genesis Mesh Network Authority HTTP API.

**Rust >= 1.85 required. Async HTTP via `reqwest` with Rustls TLS.**

## Install

```toml
[dependencies]
genesis-mesh-sdk = { git = "https://github.com/GenesisMeshLabs/sdk-rust" }
```

## Quick Start

```rust
use genesis_mesh_sdk::{json, ClientOptions, GenesisMeshClient};

#[tokio::main]
async fn main() -> genesis_mesh_sdk::Result<()> {
    let client = GenesisMeshClient::new(
        ClientOptions::new("http://127.0.0.1:9443")
            .with_signing_key(std::env::var("OPERATOR_KEY").unwrap())
            .with_key_id("operator-local"),
    )?;

    let decision = client
        .boundary
        .decide(json!({
            "requesting_agent_id": "agent-a",
            "capability": "transactions.read"
        }))
        .await?;

    println!("{decision:#}");
    Ok(())
}
```

## Sub-Clients

The MVP uses `serde_json::Value` for request and response bodies so it can cover
the live Trust API quickly while preserving exact wire-format fields.

### Agreement

```rust
let offer = client.agreement.offer(json!({
    "responder_sovereign_id": "BETA-NA",
    "capabilities": ["read:data", "write:log"],
    "valid_from": "2026-01-01T00:00:00Z",
    "valid_until": "2026-12-31T00:00:00Z",
    "expires_at": "2026-01-15T00:00:00Z"
})).await?;

let agreement = client.agreement.accept(json!({ "offer": offer })).await?;
let check = client.agreement.verify(json!({ "agreement": agreement })).await?;
```

### Boundary

```rust
let decision = client.boundary.decide(json!({
    "agreement": agreement,
    "requested_capability": "read:data"
})).await?;

let verified = client.boundary.verify(json!({ "decision": decision })).await?;
```

### Evidence

```rust
let evidence = client.evidence.build(json!({
    "source_sovereign_id": "ALPHA",
    "target_sovereign_id": "BETA",
    "verdict": "allow",
    "reason": "long-standing member"
})).await?;

let verified = client.evidence.verify(json!({ "evidence": evidence })).await?;
```

### Attestation

```rust
let attestation = client.attestation.issue(json!({
    "subject_id": "node-xyz",
    "roles": ["role:client"],
    "validity_hours": 8760
})).await?;

client.attestation
    .revoke("attestation-id", Some(json!({ "reason": "key compromised" })))
    .await?;

client.attestation.save_policy(json!({
    "recognition_policy": {
        "local_sovereign_id": "MY-NA",
        "recognized_issuers": []
    }
})).await?;
```

### Disclosure

```rust
let commitment = client.disclosure.commit(json!({
    "capabilities": ["read:data", "write:log"]
})).await?;

let proof = client.disclosure.prove(json!({
    "commitment": commitment,
    "capability": "read:data"
})).await?;

let verified = client.disclosure.verify(json!({ "proof": proof })).await?;
```

### Consensus

```rust
let vote = client.consensus.vote(json!({
    "justification_proof": { "proof_id": "jp-001", "decision_id": "dec-001" },
    "vote": true,
    "reason": "evidence satisfactory"
})).await?;

let proof = client.consensus.proof(json!({
    "votes": [vote],
    "required_threshold": 1
})).await?;

let verified = client.consensus.verify(json!({ "proof": proof })).await?;
```

### Data Usage

```rust
let policy = client.data_usage.create_policy(json!({
    "licensee_sovereign_id": "BETA",
    "allowed_source_ids": ["src-a"],
    "allowed_access_types": ["read", "aggregate"],
    "valid_from": "2026-01-01T00:00:00Z",
    "valid_until": "2026-12-31T00:00:00Z"
})).await?;

let intent = client.data_usage.create_intent(json!({
    "sources": [{
        "source_id": "src-a",
        "source_type": "public",
        "owner_sovereign_id": "MY-NA"
    }],
    "access_types": ["read"]
})).await?;

let verified = client.data_usage.verify(json!({ "intent": intent, "policy": policy })).await?;
```

## Raw Admin Headers

For Network Authority routes not yet covered by a sub-client, use
`build_admin_headers` directly:

```rust
use genesis_mesh_sdk::{build_admin_headers, json, load_signing_key};

let body = json!({
    "subject_sovereign_id": "BETA-NA",
    "scope": { "allowed_roles": ["role:client"] },
    "validity_hours": 24
});
let key = load_signing_key(&std::env::var("OPERATOR_KEY").unwrap())?;
let headers = build_admin_headers(&body, "operator-local", &key)?;
```

## Admin Authentication

Admin routes are authenticated with four HTTP headers built from an Ed25519
operator key:

| Header | Description |
|---|---|
| `X-Admin-Key-Id` | Key identifier registered with the NA |
| `X-Admin-Signature` | Ed25519 signature over `canonicalJSON({body, key_id, nonce, timestamp})` |
| `X-Admin-Timestamp` | ISO 8601 UTC timestamp |
| `X-Admin-Nonce` | UUID v4 replay-protection token |

## Build And Test

```sh
cargo fmt --all -- --check
cargo clippy --all-targets -- -D warnings
cargo test --all
```

## License

MIT
