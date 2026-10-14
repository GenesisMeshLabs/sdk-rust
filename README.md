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
| `evidence_store` | `search`, `search_all`, `status`, `verify`, `resource_history`, `vendor_history`, `resource_head`, `export_text`, `export`, `export_all`, `list_executor_keys`, `register_executor_key`, `retire_executor_key`, `apply_retention`, `latest_checkpoint`, `judge_observation`, `judge_break_glass`, `resource_changes`, `operator_holders`, `propose_holder`, `approve_holder`, `remediations`, `remediations_all`, `remediation`, `mark_notified`, `request_review`, `review`, `decide_review` | `submit` (executor-signed), `submit_observation`, `submit_observations` (observer-signed), `submit_break_glass`, `submit_remediation` (executor-signed) |
| `grants` (1.6.0, beta) | `issue`, `list`, `get`, `revoke` | `request_time_token`, `submit_use` (bearer-signed), `revocation_feed` |
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
signing (`SecretMaterial`), as is a resource action other than `create`,
`rotate`, `revoke`, `update` or `delete` (`Configuration`). Since 1.3.1 a record
no reader would take, nested more than 64 deep as it is submitted or kept in an
outbox, is refused before signing as `StrictJson` (`invalid_json`); after an
action has run, its outcome is then recorded without the parameters nested too
deep (`MetadataRefused`). `verify::verify_evidence_events` checks an export
offline with the same reason codes as the Python reference, and
`verify::verify_boundary_decision` checks one decision.

### Evidence outbox

Since 1.2.0 a client can keep signed evidence in an outbox: `governed_action`
writes each record there before submitting it and removes it once the NA admits
it. `FileOutbox` keeps one JSON file per record in a directory, written to a
temporary file, synced and renamed into place, in the format the TypeScript SDK
uses. It reads the directory once and keeps it in memory, so one process uses a
directory at a time, and recovers what a crash left on that first read. Nothing
enforces that: two processes sharing a directory submit each other's records
and overwrite each other's changes, so give each process a directory of its
own. An entry file that cannot be read is moved aside as `<name>.unreadable`
(1.3.1): the read that finds it fails once (`Outbox`, code
`outbox_file_unreadable`) and the record it held is not submitted. A
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
after a refusal no retry can overcome (`PERMANENT_REFUSALS`; since 1.3.1 also
`invalid_json`, the NA's strict reader refusing the request), with the code in
`last_error`. A record that chains from a dead letter is still submitted
(1.3.1), so the NA can quarantine it when it refuses it for good on its own
account; refused for the gap the dead letter left, it is a dead letter with
`evidence_predecessor_dead_lettered`. Dead letters are kept, never dropped.
Without an outbox, `governed_action` behaves as in 1.1.

`gm.evidence_store.flush_pending(FlushOptions::default())` submits pending
records in the order they were added; run it at startup and on a timer, one run
at a time (`FlushInProgress` otherwise). A record waits behind a pending
predecessor. Retries back off from 5 s to 15 minutes, and wait at least as
long as the NA's `Retry-After` asks (1.3.1, at most 15 minutes);
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
keeps it as a dead letter. `flush_records` submits pending break-glass
records first (1.3.1), then observations, each in the order they were added,
observations up to 100 per request. A batch the NA refuses as a whole (one
record its strict reader cannot read, `invalid_json`) or finds too large is
split in halves until the record it refuses is tried alone (1.3.1). A batch it
throttles (`429`) halves the batches the client sends after it, and no
record is due again until the NA's `Retry-After` has passed, so a submission
rate (`NA_RATE_LIMIT_OBSERVATIONS_PER_MINUTE`) below 100 a minute still drains
the backlog. A record the NA admits outside its time
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
pseudonymous identifier, never a credential. `metadata`, and the `actor`,
source event and version strings, pass the secret guard as the NA applies it
(`observation_secret_material`): names, versions and times, never values, at
most 16 KiB together as the NA counts them (since 1.3.1: text outside ASCII
escaped, as `é`). A record the NA would find malformed is not signed
either (`observation_malformed`): an action other than `create`, `rotate`,
`revoke`, `update` or `delete`, a field of the wrong length, or a time outside
the years 1 to 9999. Name the version (`version_id`) when the source reports one: the NA
matches the observation to execution evidence for the same resource, action
and capability that reports the same `execution_parameters.version_id`, and
the change is then governed by that evidence's decision, unless the
observer's own facts are denied by the policies active then. A second
observer's report of the same version is the same change. A reconciliation
finding knows only that a resource
changed between two scans: `observation_from_finding` turns one (the JSON the
other SDKs' reconciliation returns) into an observation input with that
window, which the NA judges at both ends, and returns `None` for a resource in
sync. An observation's id defaults to one derived from its observer, source and
source event (`observation_id`, 1.3.1), so the same finding signed again is
the same record, which the NA answers as a `duplicate`.

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
evaluation it could not store (`503 evidence_store_unavailable`), an answer
whose body could not be read (`ResponseBodyUnreadable`: the NA may have
decided, even denied), or any other error. It needs a record outbox
(`RecordOutboxRequired`), `resource_id` and an attestation-based evaluation
(`attestation_id`: an agreement-based one cannot be judged after the fact)
naming its `requested_capability`. Before anything is evaluated or run it
checks the justification (1 to 1024 characters), that the context's
`request_parameters` and `attributes` are objects that, with the
justification, leave room for the record (counted as the NA counts it, since
1.3.1), and the context and justification against the secret guard
(`OutOfBandRecord` with `break_glass_malformed` or
`break_glass_secret_material`). A failed action is recorded as a `failure`
record (`ActionFailed`, whose `queued_record` holds its entry while the NA is
away). Once the action ran a record is always kept: an outcome detail is cut
to 1024 characters, and reported metadata the guard refuses is left out of the
record and named in `dropped` (the whole report, when the rest is still
refused). `ExecutionRecorder::sign_break_glass` signs a record directly.
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
`quarantined`); since 1.4.0 it follows the NA's pages
(`resource_changes_page` reads one: `limit`, `after_sequence`). A judgement
has no `authorized` field: it is never an
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
`judgements` and `quarantined`. Since 1.3.1 it verifies an export as the
reference does: a record's id appears once per kind (`duplicate_record`); a
Stage 2 entry's envelope names what its record says (`envelope_mismatch`); a
judgement's matched record is in an export from entry 1
(`judgement_match_missing`); a retention checkpoint removed as many entries as
positions (`retention_count_mismatch`); and an export that starts after entry 1
(a later page) takes the first record it holds of each resource as that
chain's start, so it no longer reports `resource_chain_break` there. `canonical::out_of_band_canonical`,
`canonical::out_of_band_digest` and `verify::verify_out_of_band_record` give
one record's signed form and check its signature.

## Remediation and reviews

From Genesis Mesh 1.4.0 a change judged DENY after the fact leads somewhere:
the NA states what is to be done and by when, the controller does it and
records it, and the change's author is told. A second person can review a
judgement, or a decision made under a policy that requires it, and uphold,
deny or waive the change. The NA never changes a resource itself, and a
credential is never rolled back. The NA must run with
`EVIDENCE_REMEDIATION=on` (with `EVIDENCE_OUT_OF_BAND=on`); until then these
routes answer `404 remediation_disabled`. The operator's side is described in
*Remediation and Reviews* and *Emergency Changes and Break-Glass* in the NA
runbooks. The routes are beta until 1.5.0; the records' signed forms are
stable.

### The due queue and notices

`remediations` reads one page of the due queue (`state`, `limit` 1 to 500,
`after` the previous page's `next_after`), and `remediations_all` follows the
pages. `state` is a stored state or `review_pending`
(`remediation::QUEUE_FILTERS`); without it, the due, overdue and waived
changes and every change with a pending review. Each item is a remediation
state:

- **the judged change**: `subject_kind`, `subject_id`, `change_kind`,
  `change_id`, `change_version_id` (the version it made), `resource_id`,
  `actor` and `actor_holder`;
- **where it stands**: `state` (`remediation_due`, `overdue`, `remediated`,
  `upheld`, `waived`, or `judged_allowed`, `matched` or `recorded` for an
  allowed change under review or with a lifetime running) and
  `review_pending`, a flag beside the state: a pending review stops no clock;
- **the plan**: `mode` (`cancel` or `alert_only`), `steps`, `fallback`
  (`not_executed` for a decision whose change never ran), `grace_seconds`,
  `guidance_source`;
- **its times**: `remediation_due_at`, `overdue_since`, `waived_until`,
  `lifetime_ends_at`.

`remediation(subject_id)` reads one with its newest 100 reviews and stored
records (`reviews_truncated`, `records_truncated`). Tell
the actor before `remediation_due_at`, then record the notice with
`mark_notified(subject_id, Some("email"))`. The actor is what the source
reported, not proof of who acted.

### Carrying out a remediation

`ExecutionRecorder::sign_remediation` signs a `RemediationRecord` with the
executor key; `RemediationSubject::from_state` takes the subject from a due
queue item (a decision never executed names itself as its change), and
`RemediationSteps` says what was done: `Disable` or `Delete` (a resource
nothing reads yet), `RotateForwardThenDisable`, or `Alerted` (`alert_only`:
nothing changed). A remediation is recorded only for a change that is
`remediation_due` or `overdue`. Before signing it refuses what the NA would
refuse, with its code (`OutOfBandRecord`): `remediation_malformed`, or
`remediation_secret_material` for secret material in its versions or detail.
Submit it with `submit_remediation`, or keep it in the record outbox with
`enqueue_record`: a remediation whose subject or forward rotation the NA does
not hold yet is retried, and a refusal no retry can overcome
(`REMEDIATION_PERMANENT_REFUSALS`) keeps it as a dead letter. `flush_records`
submits remediation records last, one at a time.

`rotate_forward_then_disable` cancels a denied change to a versioned resource
without breaking its readers: it rotates forward to a new version under a
governed decision (the version recorded as `execution_parameters.version_id`),
disables the denied version, and keeps a remediation record linked to the
rotation's evidence:

```no_run
use genesis_mesh_sdk::{
    rotate_forward_then_disable, ActionError, ExecutionRecorder, GenesisMeshClient,
    GovernedActionParams, RemediationSubject, RotateForwardParams, RotatedVersion, Value,
};

async fn cancel(gm: &GenesisMeshClient, recorder: &ExecutionRecorder, state: &Value,
                governed: GovernedActionParams) -> Result<(), Box<dyn std::error::Error>> {
    let params = RotateForwardParams {
        governed, // the rotation's evaluation, resource and verification
        subject: RemediationSubject::from_state(state).ok_or("no change named")?,
        state: Some(state.clone()), // its plan, state and version, checked first
        disabled_version_id: "v8".into(),
        detail: None,
    };
    let done = rotate_forward_then_disable(
        &gm.boundary, &gm.evidence_store, recorder, params,
        |_decision| async { Ok::<_, ActionError>(RotatedVersion::<()>::new("v9")) },
        |_denied_version| async { Ok::<_, ActionError>(()) },
    ).await?;
    if let Some(record) = done.record {
        eprintln!("remediated: {}", record["remediation_id"]);
    }
    Ok(())
}
```

The record is kept in the record outbox when there is one (pending until the
NA holds the rotation's evidence: flush the evidence outbox first), and
submitted directly otherwise. A DENY of the rotation stops it with nothing
disabled. Once the rotation ran, a disable that fails, or a record that cannot
be signed, submitted or kept, returns `RemediationNotRecorded`
(`remediation_not_recorded`) with the rotation's evidence and the record when
it was signed: do not rotate again. Given the remediation `state`, it refuses
before anything runs what the NA would refuse: another plan
(`remediation_steps_mismatch`), a change that is not due or overdue
(`remediation_not_due`, `remediation_already_recorded`), or another denied
version than the change made (`remediation_subject_mismatch`). The NA admits
only a rotation by the remediation's own executor, made after the change, and
cited by no other remediation. `remediation::check_remediation` names the
refusal the NA would answer for a signed record and a registered key.

### Reviews

`request_review(subject_kind, subject_id, justification)` asks for a review
(the operator key's holder must be named in the store, and must not be the
change's actor: `review_requested_by_actor`). A privileged key of
another holder decides it with `decide_review(review_id, &decision)`:
`ReviewDecision::Uphold`, `Deny` (remediation becomes due) or `WaiveUntil`
(the change stands until a time the NA bounds), each with an optional note.
The NA refuses a decider who holds the requester's key or holder
(`review_same_holder_as_requester`) or the actor's
(`review_same_holder_as_actor`). `review(review_id)` reads it, with its signed
record once decided. Both requests are embedded in the review as signed, so
the request body is exactly what the record proves; the review routes take
no query string, and `waive_until` and the admin timestamps are strict
RFC 3339 (`remediation::rfc3339`: `YYYY-MM-DDTHH:MM:SS`, a fraction of 1 to
6 digits, `Z` or `+HH:MM`).

### Urgent changes

`urgent_action` takes an urgent change through the path that applies; none is
blocked, and each is judged and reviewed (`UrgentActionResult::path`):

- **`Ordinary`**: the ordinary capability is allowed; the change runs under it.
- **`Emergency`**: on an ordinary DENY, or when that evaluation gets no
  answer, the emergency capability (`EmergencyOptions`: a capability of its
  own, selected by a policy with an `emergency` section) is requested with the
  justification in its justification parameter. The NA decides it under the
  emergency policy before the change, and opens a review of the decision.
- **`BreakGlass`**: the NA does not answer for it either (a network error, a
  timeout, `5xx` or `429`): the change runs under break-glass naming the
  emergency capability, and the NA judges it under the emergency policy when
  the record arrives.

It checks what break-glass needs before anything is evaluated (a record
outbox, an attestation-based evaluation, `resource_id`, the justification).
The same paths can be taken by hand with `governed_action` and
`governed_action_with_break_glass`.

### Policies and offline verification

A boundary policy may carry `remediation` guidance (per gate, or `"*"`),
`review_required: true` and an `emergency` section; absent or `null`, they are
left out of its signed form, so a policy without them keeps its 1.3 digest.
`remediation::policy_section_issues` names the issues the NA would find in
them. `verify::verify_evidence_events` verifies the two new entry kinds:

- **Remediation records**, under executor keys:
  - once per subject (`duplicate_remediation`);
  - naming their judgement's change, resource and the version it made
    (`remediation_subject_mismatch`);
  - after a forward rotation of the same resource
    (`remediation_rotation_missing`, `remediation_rotation_mismatch`), by
    their own executor (`remediation_rotation_other_executor`), made after
    the change (`remediation_rotation_before_change`) and cited once
    (`remediation_rotation_reused`).
- **Reviews**, under the NA keys:
  - their embedded approvals verify offline (`review_approval_invalid`,
    `remediation::review_approval_problem`);
  - against the holder registry records the NA signed
    (`review_approval_key_mismatch`);
  - decided by a second holder (`review_same_holder`);
  - naming their subject's digest (`review_subject_mismatch`);
  - no waiver after a remediation (`review_waiver_after_remediation`).
- **In a run from its start** (entry 1, or right after the checkpoint
  passed): `remediation_subject_missing`, `remediation_rotation_missing` and
  `review_subject_missing`.

The result counts them in `remediations` and `reviews`. The reference's pure
rules are in `remediation` (`remediation_plan`, `decision_plan`,
`next_state` with the review flag, `due_after_denial`, `due_after_waiver`,
`steps_problem`, `review_holder_problem`, `review_request_problem`,
`rfc3339`, `emergency_map`), checked by the shared conformance suite
`remediation`.

## Pre-issued grants

*Unreleased.*

A grant (1.6.0) is an authorisation the NA signs in advance, so a device can
make a known, bounded kind of change while it cannot reach the NA. Where
break-glass records a change and has it judged afterwards, a grant authorises
it beforehand: the NA checks, when it issues the grant, that every policy that
applies allows every request the grant permits. The NA issues grants only with
`EVIDENCE_GRANTS=on` (every grant route answers `404 grants_disabled`
otherwise); the routes are beta, the records stable. See the core's
*Pre-Issued Grants* operations page for the rules in full and the limits of
offline trust.

### Issuing and revoking

`grants.issue` names one bearer (a registered executor key), the
capabilities, the basis (`attestation_id` or `agreement`), a validity of at
most 24 hours, a budget (`max_uses`), the uses one time token may anchor
(`max_uses_per_time_token`) and a closed `parameter_envelope`: each parameter
`one_of` a set of scalars, `subset_of` a set of strings, or a
`number_range` (`integer` or `number`, inclusive or exclusive bounds). The NA
answers with the signed grant and its first time token, or refuses naming the
first problem (`grants::ISSUANCE_REFUSALS`, such as `grant_gate_may_deny`
when a value of the envelope may be denied). `grants.list`, `grants.get` and
`grants.revoke` read and revoke grants; a use made before a revocation
stands, one at or after it is refused.

### Acting within a grant

A `GrantHolder` holds one grant for the device whose `ExecutionRecorder`
signs with the bearer key. `act` checks each use offline, in the NA's order:
the capability, the envelope (`grants::envelope_problem`: closed, numbers
compared exactly, booleans never numbers, `true` is not `1`), revocation (the
feed the holder last read), the validity, the budget, and the uses its latest
time token may still anchor. It then runs the action, signs a
`GrantExecutionEvidence` chained to the previous use and citing the time
token, keeps it in the record outbox and submits it:

```no_run
use genesis_mesh_sdk::{
    json, ActionError, ActionReport, GenesisMeshClient, GovernedVerification, GrantActionOutcome,
    GrantFallback, GrantHolder, GrantRequest,
};

async fn rotate(gm: &GenesisMeshClient, holder: &mut GrantHolder, na_key: String)
    -> Result<(), Box<dyn std::error::Error>> {
    let verify = GovernedVerification { operator_public_keys: vec![na_key], ..Default::default() };
    let request = GrantRequest::new("secret.manage", json!({"lifetime_days": 30}))
        .on("kv:site-7/api-key", "rotate")
        .with_fallback(GrantFallback::new("the credential must rotate now", verify));
    match holder.act(gm, request, |_authority| async move {
        Ok::<_, ActionError>(ActionReport::<()> {
            execution_parameters: Some(json!({"version_id": "v9"})),
            ..ActionReport::default()
        })
    }).await? {
        GrantActionOutcome::Used(used) => eprintln!("use {}", used.record["use_sequence"]),
        GrantActionOutcome::FellBack { unusable, .. } => eprintln!("fell back: {}", unusable.code),
    }
    // Persist the holder after every use: `holder.state()`, `GrantHolder::restore`.
    Ok(())
}
```

A request the grant does not cover (`grant_capability_mismatch`,
`grant_envelope_mismatch`), a grant not valid yet, and secret material in the
parameters are refused before anything runs (`GrantRefused`,
`OutOfBandRecord` with `grant_use_secret_material`). A use is dated no
earlier than its time token and the previous use. Metadata the secret guard
refuses after the action ran is left out of the use and named in `dropped`;
a failed action is recorded as a use with outcome `failure` (`ActionFailed`).
`ExecutionRecorder::sign_grant_use` and `sign_time_token_request` sign the
records directly. Keep `GrantHolder::state` durably: a holder that forgets its
uses signs a second use at a position it already used, which the NA refuses.

### Uploading, and the fallback

On reconnecting, `holder.sync` reads and verifies the revocation feed
(`revoked_grant_ids`), uploads the record outbox (the grant's uses one at a
time in their chain's order, before observations; the NA gives each use the
next position of its resource's chain) and asks for a new time token naming
the head of the holder's chain. A use behind one the NA refused for good is a
dead letter (`evidence_predecessor_dead_lettered`); the NA's final refusals
are `GRANT_USE_PERMANENT_REFUSALS`. Execution evidence made online afterwards
links to the last use, which the NA's resource head names.

When the grant has ended, its budget or its time token is spent (and no new
one came), it is revoked or its bearer key is retired, `act` falls back with
the request's `GrantFallback` to `governed_action_with_break_glass` with the
grant's capability: the NA's decision when it answers (a DENY does not run
the action), break-glass when it does not, so an urgent change is recorded
and judged, never blocked. Pending uses are uploaded first. Without a
fallback the request is refused (`GrantRefused` with the reason). A grant on
an agreement needs `GrantFallback::evaluate`.

### Verifying grants

`verify_evidence_events`, `verify_record` and `verify_audit_pack` check the
three new entry kinds (`grant`, `grant_execution`, `grant_revocation`) and a
time token: each record's signature (a use by its grant's bearer key, its
time token by the NA), the store's grant rules (`grant_missing`,
`grant_bearer_mismatch`, `grant_mismatch`, `grant_use_chain_break`,
`duplicate_grant_revocation`; in a pack a missing grant is
`cited_record_missing`), then the use rules with the NA's codes
(`grants::use_problem`), the resource position the NA assigned
(`resource_chain_break`, `envelope_mismatch`), a judgement `governed_by:
grant`, a quarantined use, and the revocation feed's `revoked_grant_ids`
(`verify::verify_revocation_feed`). An audit pack's report gains *Grants* and
*Grant revocations* sections when it holds them. Turn grants on only once
every verifier that reads your exports, packs and feed runs 1.6: a 1.5
verifier refuses the new kinds and the feed's field.

## Independent verification

From Genesis Mesh 1.5.0 an auditor verifies records, evidence exports and
audit packs on its own machines, years later, with `genesis-mesh-verify`: a
static Linux binary built from this crate's `verify`, `key_history` and
`audit_pack` modules, released with checksums and Sigstore bundles, and
reproducible from source. It never needs a private key and never contacts a
network. "Independent" means separate code by the same project: a difference
from the Python reference is a bug in one of them.

```sh
genesis-mesh-verify pack pack-2026 --anchor root.pub --known-anchors /audit/anchors
genesis-mesh-verify export export.jsonl --key-history key-history.json --root-key root.pub \
    --executor-keys executor-keys.json --known-anchors /audit/anchors --json
genesis-mesh-verify record decision decision.json --key-history key-history.json --root-key root.pub
genesis-mesh-verify key-history key-history.json --root-key root.pub
```

Exit codes: 0 verified, 1 not verified, 2 usage error, 3 an input could not
be read. [docs/verifier.md](https://github.com/GenesisMeshLabs/sdk-rust/blob/main/docs/verifier.md)
says what is checked, how to rebuild a release and compare digests, and how to
read a mismatch.

### In the library

- **Key succession** (`key_history`): `verify_key_history` verifies a genesis
  block and its `KeySuccessionRecord`s (each signed by the root key, the new
  key and the outgoing key) from the root key held, in the
  reference's order and with its reason codes, and gives the `NaKeyHistory`:
  which NA key is valid when (`NaKey::accepts`, with the 300-second
  hand-over). `NaKeys` is either keys valid at every time or the history.
- **NA signatures at the record's time**: `VerifyEvidenceOptions::key_history`,
  `VerifyDecisionOptions::key_history` and `VerifyRecordOptions::key_history`
  accept an NA signature only by the key valid at the record's own time
  (`na_key_not_valid_at_time` for another key of the history), and
  `verify_store_anchors` takes `NaKeys`. Without a history every key given is
  valid at every time, as before.
- **Decisions as of their own time**: `VerifyDecisionOptions::at_record_time`
  judges a decision as of its `decision_made_at` instead of now, so an
  archived decision verifies at any later audit. It is off by default: a
  decision about to be acted on is still judged as of now.
- **Audit packs** (`audit_pack`): `verify_audit_pack` checks a pack as
  `genesis-mesh audit verify` does, `render_report` renders its `report.md`
  byte for byte, and `differences_from_pack_checks` compares the result with
  the pack's own `checks.json`; `parse_changes` and `check_completeness` are
  the completeness check.
  `VerifyEvidenceOptions::prior` verifies a range with a pack's cited records
  as its predecessors (`cited_record_missing`).
- **New entry kinds**: `key_succession` and `archive` entries verify in an
  export (counted in `key_successions` and `archives`).
- `verify::verify_record(kind, record, options)` verifies one record as an
  export verifies it, with the same reason codes: every entry kind, a policy
  or an attestation.
- Store anchors, as the reference checks them: `verify::verify_store_anchors`
  (signatures, chain, positions), `verify::check_events_against_anchors` (an
  export tied to the anchors held at both ends), `verify::parse_anchors` and
  `verify::export_checkpoint`; `canonical::anchor_canonical`,
  `canonical::anchor_digest`, `canonical::received_canonical` and
  `canonical::key_succession_canonical`.

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
  Other statuses retain their numeric code in `Http`. A response whose body
  could not be read is `ResponseBodyUnreadable` (`response_body_unreadable`),
  not `Network`: the request reached the NA.
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
cargo clippy --locked --workspace --all-targets -- -D warnings
cargo test --locked --workspace --all-targets
cargo test --locked --doc
cargo doc --locked --workspace --no-deps
cargo package --locked
```

The workspace holds the crate and `genesis-mesh-verify` (`verifier/`, not
published to crates.io). CI tests stable Rust on Linux, Windows, and macOS plus
Rust 1.85 on Linux, checks release metadata and packaging, and audits
dependencies with `cargo audit`. The `Verifier` workflow builds the static
binaries twice and compares them, checks they need no shared library, and runs
the verifier's tests against them without a network.
See [CONTRIBUTING.md](https://github.com/GenesisMeshLabs/sdk-rust/blob/main/CONTRIBUTING.md), [RELEASING.md](https://github.com/GenesisMeshLabs/sdk-rust/blob/main/RELEASING.md), and
[SECURITY.md](https://github.com/GenesisMeshLabs/sdk-rust/blob/main/SECURITY.md).

## License

[MIT](https://github.com/GenesisMeshLabs/sdk-rust/blob/main/LICENSE)
