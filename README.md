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
| `evidence_store` | `search`, `search_all`, `status`, `verify`, `resource_history`, `vendor_history`, `resource_head`, `export_text`, `export`, `export_all`, `list_executor_keys`, `register_executor_key`, `retire_executor_key`, `apply_retention`, `latest_checkpoint`, `judge_observation`, `judge_break_glass`, `resource_changes`, `operator_holders`, `propose_holder`, `approve_holder` | `submit` (executor-signed), `submit_observation`, `submit_observations` (observer-signed), `submit_break_glass` (executor-signed) |
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
linked to the resource's chain head. Give the client an evidence outbox
(`ClientOptions::new(url).with_outbox(Arc::new(FileOutbox::new("/var/lib/controller/gm-outbox")))`)
so no signed record is lost when the NA is unreachable after an action:

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

### Evidence outbox

Since 1.2.0 a client can keep signed evidence in an outbox: `governed_action`
writes each record there before submitting it and removes it once the NA admits
it. `FileOutbox` keeps one JSON file per record in a directory, written to a
temporary file, synced and renamed into place, in the format the TypeScript SDK
uses. It reads the directory once and keeps it in memory, so one process uses a
directory at a time, and recovers what a crash left on that first read. A
directory it creates is `0700` and its files `0600` on Unix; on Windows, or for
a directory that already exists, restrict access to it yourself. Implement the
`EvidenceOutbox` trait (its methods return boxed futures) to keep records in a
database instead. The outbox holds signed metadata, never secret values, but
must be durable and private. `MemoryOutbox` is for tests only.

With an outbox, a failed submission is not an error. `result.submission` is the
NA's acknowledgement when it admitted the record; otherwise `result.queued` is
the outbox entry: `OutboxState::Pending` after a failure a later attempt can
overcome (network, timeout, `5xx`, `429`, an executor key not registered yet, a
chain gap, a disabled store, a proxy's error page), or `OutboxState::DeadLetter`
after a refusal no retry can overcome (`PERMANENT_REFUSALS`), or when a record it
chains from was refused (`evidence_predecessor_dead_lettered`), with the code in
`last_error`. Dead letters are kept, never dropped. Without an outbox,
`governed_action` behaves as in 1.1.

`gm.evidence_store.flush_pending(FlushOptions::default())` submits pending
records in the order they were added; run it at startup and on a timer, one run
at a time (`FlushInProgress` otherwise). A record waits behind a pending
predecessor. Retries back off from 5 s to 15 minutes;
`FlushOptions { ignore_backoff: true }` retries at once. A transient error ends
the run. A resource with pending records chains from the newest of them, not
from the NA's head, and the next action on it submits them first (up to 100),
unless `prior_resource` is set. Two controllers with separate outboxes that
change one resource while the NA is away fork its chain; the record that loses
is dead-lettered with `evidence_conflict`.

With an outbox, two errors mean the action ran; do not run it again.
`MetadataRefused` (`governed_action_metadata_refused`): the secret guard refused
metadata the action reported, and the outcome was recorded without the refused
fields (`dropped`, also named in `outcome_detail`). `EvidenceNotKept`
(`governed_action_evidence_unkept`): the evidence could not be signed or the
outbox failed; it carries the signed `evidence` when there is one. Both carry
the action's value: `err.take_action_value::<T>()`. A failed action's
`ActionFailed` carries its failure record and, with an outbox, its entry.

## Changes outside the controlled path

From Genesis Mesh 1.3.0 the Network Authority (NA) records changes that did
not go through `governed_action`, and judges each one once, as of the time it
happened:

- an **observation**: a change an observer saw at its source (a cloud
  activity log entry, or a reconciliation finding), signed by an observer key;
- a **break-glass record**: a change a controller made while the NA could not
  be reached, with its caller's justification, signed by the executor key.

The NA must run with `EVIDENCE_STORE=on` and `EVIDENCE_OUT_OF_BAND=on`. Until
then the routes answer `404 out_of_band_disabled`, and records in the record
outbox wait. The operator's side is described in *Changes Outside the
Controlled Path* in the NA runbooks.

### Record outbox

Observations and break-glass records are kept in a record outbox until the NA
admits them, as `FileOutbox` keeps execution records. Give it a directory of
its own (`FileRecordOutbox`, format `gm.evidence.record-outbox.v1`, shared with
the TypeScript SDK):

```no_run
use std::sync::Arc;
use genesis_mesh_sdk::{ClientOptions, FileRecordOutbox, FlushOptions, GenesisMeshClient};

async fn start(url: &str) -> Result<GenesisMeshClient, Box<dyn std::error::Error>> {
    let records = Arc::new(FileRecordOutbox::new("/var/lib/controller/gm-records"));
    let gm = GenesisMeshClient::new(ClientOptions::new(url).with_record_outbox(records))?;
    // At startup and on a timer.
    gm.evidence_store.flush_records(FlushOptions::default()).await?;
    Ok(gm)
}
```

`enqueue_record` keeps a record and submits it; a transient failure leaves it
pending, and a refusal no retry can overcome (`RECORD_PERMANENT_REFUSALS`)
keeps it as a dead letter. `flush_records` submits pending records in order,
observations up to 100 per request. A record the NA admits outside its time
bounds is kept by the NA as a quarantine entry and is listed in the run's
`quarantined`. Implement the `RecordOutbox` trait to keep records elsewhere;
`MemoryRecordOutbox` is for tests only.

### Observers

Register the observer's key with `"role": "observer"`, scoped to the
resources it watches (privileged operator key), then sign each change it sees
with an `ObservationRecorder` holding that key:

```no_run
use genesis_mesh_sdk::{json, GenesisMeshClient, ObservationInput, ObservationRecorder};

async fn observe(gm: &GenesisMeshClient, observer_public_key: &str, observer_seed: &str)
    -> Result<(), Box<dyn std::error::Error>> {
    gm.evidence_store.register_executor_key(json!({
        "key_id": "activity-log-observer", "public_key": observer_public_key,
        "executor_sovereign_id": "cloud-observer", "role": "observer", "resource_prefix": "kv:prod/",
    })).await?;
    let observer = ObservationRecorder::new("cloud-observer", "activity-log-observer", observer_seed)?;
    let observation = observer.record(ObservationInput {
        resource_id: "kv:prod/api-key".into(),
        action: "rotate".into(),
        capability: "secret.rotate".into(),
        changed_at: Some(chrono::Utc::now()),
        source: "cloud-activity-log".into(),
        source_event_id: "event-7".into(),
        actor: Some("principal-7f3a".into()),
        version_id: Some("v8".into()),
        metadata: Some(json!({"lifetime_days": 30})),
        ..ObservationInput::default()
    })?;
    gm.evidence_store.enqueue_record(observation).await?;
    Ok(())
}
```

`actor` is recorded as the source reported it and is not authenticated: use a
pseudonymous identifier, never a credential. `metadata` passes the secret
guard (`observation_secret_material`): names, versions and times, never
values. Name the version (`version_id`) when the source reports one: the NA
matches the observation to execution evidence for the same resource, action
and capability that reports the same `execution_parameters.version_id`, and
the change is then governed by that evidence's decision, unless the
observer's own facts are denied by the policies active then. A second
observer's report of the same version is the same change. A reconciliation
finding knows only that a resource
changed between two scans: `observation_from_finding` turns one (the JSON the
other SDKs' reconciliation returns) into an observation input with that
window, which the NA judges at both ends, and returns `None` for a resource in
sync.

### Break-glass

`governed_action_with_break_glass` runs the action even when the evaluation
fails transiently (network error, timeout, `5xx`, `429`; see
`evaluation_failure`), and keeps a break-glass record signed by the executor
key in the record outbox. The action then gets no decision (`None`), and the
outcome is `GovernedActionOutcome::BrokeGlass`:

```no_run
use genesis_mesh_sdk::{
    governed_action_with_break_glass, ActionError, ActionReport, BreakGlassOptions,
    ExecutionRecorder, GenesisMeshClient, GovernedActionOutcome, GovernedActionParams,
};

async fn rotate(gm: &GenesisMeshClient, recorder: &ExecutionRecorder, params: GovernedActionParams)
    -> Result<(), Box<dyn std::error::Error>> {
    let justification = BreakGlassOptions::new("incident 42: rotate the leaked key now");
    let outcome = governed_action_with_break_glass(
        &gm.boundary, &gm.evidence_store, recorder, params, justification,
        |_decision| async move { Ok::<_, ActionError>(ActionReport::<()>::default()) },
    ).await?;
    if let GovernedActionOutcome::BrokeGlass(result) = outcome {
        eprintln!("ran without a decision ({}); recorded as {}",
                  result.failure.as_str(), result.record["break_glass_id"]);
    }
    Ok(())
}
```

A DENY never breaks the glass, nor does a decision that fails verification,
the NA throttling failed operator signatures (`429 admin_auth_throttled`), an
evaluation it could not store (`503 evidence_store_unavailable`), or any other
error. It needs a record outbox (`RecordOutboxRequired`), `resource_id` and an
attestation-based evaluation (`attestation_id`: an agreement-based one cannot
be judged after the fact), and checks the justification (1 to 1024
characters) and the evaluation context against the secret guard before
anything is evaluated or run (`OutOfBandRecord` with `break_glass_malformed`
or `break_glass_secret_material`). A failed action is recorded as a `failure`
record (`ActionFailed`, whose `queued_record` holds its entry while the NA is
away). Reported metadata the guard refuses is left out of the record and named
in `dropped`. `ExecutionRecorder::sign_break_glass` signs a record directly.
`governed_action` itself never breaks the glass. Every use shows in the
resource's changes, with its justification; a policy can forbid it for a
capability (a `denylist.v1` gate on `parent_kind` with the value
`break_glass`).

### Judgements and the state of a resource

The NA judges each record at admission unless that is turned off; the
operator judges the rest with `judge_observation` and `judge_break_glass`.
`resource_changes` lists every change to a resource, with how it was governed
(`prior_decision` or `after_the_fact`) and its state (`recorded`, `matched`,
`judged_allowed`, `judged_denied`, `indeterminate`, `observed`,
`quarantined`). A judgement has no `authorized` field: it is never an
approval, and `verify_evidence_events` refuses execution evidence that cites
one (`evidence_cites_judgement`). `operator_holders`, `propose_holder` and
`approve_holder` record which holder each operator key belongs to.

`verify::verify_evidence_events` verifies the new entry kinds offline:
observations under observer keys and break-glass records under executor keys
(`list_executor_keys` returns each key's `role`; an execution record signed by
an observer key does not verify); judgements, quarantine and registry entries
under the NA keys; each resource's observation positions
(`observation_chain_break`), one judgement per record (`duplicate_judgement`)
that names it as stored (`judgement_subject_mismatch`,
`judgement_subject_missing`), and execution evidence matched once
(`match_reused`). The result counts them in `observations`, `break_glass`,
`judgements` and `quarantined`. `canonical::out_of_band_canonical`,
`canonical::out_of_band_digest` and `verify::verify_out_of_band_record` give
one record's signed form and check its signature.

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
