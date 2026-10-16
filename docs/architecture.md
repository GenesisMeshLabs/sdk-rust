# Architecture

How the Rust SDK is built, which module may use which, and where a change
goes. The layer table below is the one `tests/architecture.rs` enforces; a
module it does not place fails that test.

## Crates

| Crate | Path | What it is |
|---|---|---|
| `genesis-mesh-sdk` | `src/` | The library: offline verification, canonical forms, signing, records and outboxes, and (feature `client`, default) the HTTP client. |
| `genesis-mesh-verify` | `verifier/` | The offline verifier binary ([docs/verifier.md](verifier.md)). Uses only the SDK's verification modules: `verifier/clippy.toml` denies network and signing APIs, and `verifier/tests/cli.rs` allows only `verify`, `canonical`, `strict`, `key_history`, `audit_pack` and `parse_strict_json`. |
| `genesis-mesh-edge` | `edge/` | The edge agent, beta, Unix only ([docs/edge.md](edge.md)). Uses the SDK with `client`; `edge/clippy.toml` denies the admin signing APIs. |

## Layers

The table lists the layers lowest first. A module may use modules of its own
layer and of the layers listed before it, never of a later one, and the
modules form no import cycle. The
first four layers build without the `client` feature (CI checks that build,
and that it pulls in no HTTP, async, TLS or database crate); the rest are
behind it.

| Layer | Modules | Holds |
|---|---|---|
| 1. foundation | `errors`, `strict_json`, `rules`, `outbox_entry` | Typed errors; strict JSON input; value rules shared by the records (metadata limit, secret-material guard, number normalization); the outboxes' entry types. |
| 2. canonical | `auth`, `canonical`, `strict`, `shape` | Canonical JSON, Ed25519 signing and verification, admin headers; canonical forms and digests of each model; the field registry; structural checks of signed JSON. |
| 3. records | `execution`, `out_of_band`, `remediation`, `grants`, `node_auth`, `outbox` | Building, signing and checking records offline; the evidence and record outboxes. |
| 4. verification | `verify`, `key_history`, `audit_pack` | Offline verification of NA-signed artifacts, exports, key histories and audit packs. |
| 5. transport (`client`) | `transport` | `ClientOptions`, `HttpTransport`: admin request signing, retries, error mapping, path segment encoding. |
| 6. sub-clients (`client`) | `agreement`, `attestation`, `boundary`, `consensus`, `data_usage`, `disclosure`, `evidence`, `evidence_store`, `grant_client`, `health`, `node`, `policy` | One sub-client per NA route group, over the transport. |
| 7. client (`client`) | `client` | `GenesisMeshClient`: one transport shared by every sub-client. |
| 8. orchestration (`client`) | `governance`, `grant_holder` | `governed_action` and its variants, `GrantHolder`: flows over several sub-clients. |

`lib.rs` declares the modules and re-exports the public API; the public
paths are the crate root plus the `pub mod`s (`audit_pack`, `canonical`,
`grants`, `key_history`, `node_auth`, `remediation`, `strict`, `verify`).

Shared code goes down, never sideways into a cycle: when two modules of a
layer need the same helper, it moves to a lower module (`rules`, `shape`,
`outbox_entry` hold such helpers). `tests/architecture.rs` keeps an
`ALLOWED` list for edges that break these rules; it is empty and may only
shrink.

## Modules

| Module | One line |
|---|---|
| `errors` | `GenesisMeshError`, its `code()`, the HTTP error mapping. |
| `strict_json` | `parse_strict_json`/`check_strict_json`: refuses what parsers read differently (duplicate keys, out-of-range integers, lone surrogates). |
| `rules` | `MAX_METADATA_BYTES`, the secret-material guard, `normalize_number`. |
| `outbox_entry` | `OutboxEntry`, `RecordOutboxEntry`, `RecordKind`, `SubmissionFailure`. |
| `auth` | Canonical JSON (Python's `json.dumps` form), digests, signing, admin headers. |
| `canonical` | Each model's canonical body and digest, Pydantic timestamps. |
| `strict` | The embedded field registry (`src/canonical_registry.json`): unknown fields, non-canonical forms. |
| `shape` | Structural check combinators and the `validator!` macro. |
| `execution` | `ExecutionRecorder`: execution records, metadata-only guard. |
| `out_of_band` | `ObservationRecorder`, break-glass records. |
| `remediation` | Remediation records, review checks, plans and the state table. |
| `grants` | Pre-issued grants: envelopes, number rules, use rules, signing. |
| `node_auth` | Node request signatures, the edge join co-signature. |
| `outbox` | Evidence and record outboxes (memory and file), retry and refusal rules. |
| `verify` | Offline verification of decisions, exports, records and anchors (Python reason codes). |
| `key_history` | NA key history and succession: which key was valid when. |
| `audit_pack` | Audit pack verification and the completeness check. |
| `transport` | `ClientOptions`, `HttpTransport`, `segment`/`resource_path`. |
| `client` | `GenesisMeshClient`. |
| `agreement` ... `policy` | One sub-client each (see the README's "API coverage"). |
| `evidence_store` | `EvidenceStoreClient`: evidence, records, judgements, remediations, reviews, outbox flushes. |
| `grant_client`, `node` | Grant routes and the revocation feed; a node's own routes, signed by its node key. |
| `governance` | `governed_action`, break-glass, `rotate_forward_then_disable`, `summarize_decision`. |
| `grant_holder` | `GrantHolder`: acts within a grant offline, uploads, falls back. |

## Flow

**A governed action** (`governance::governed_action`): the boundary
sub-client asks the NA for a decision (`POST /admin/boundary/evaluate`, or
`/node/boundary/evaluate` with a node identity); `verify` checks the
decision offline against the NA key; the caller's action runs;
`execution::ExecutionRecorder` signs the execution record, which goes to the
evidence outbox first when one is configured and is then submitted by
`evidence_store`; a submission that fails stays pending (`flush_pending`
retries it), and one the NA refuses for good is kept as a dead letter.

**A request**: a sub-client builds the path with `transport::segment` or
`resource_path` (every caller-supplied identifier is percent-encoded and
`.`/`..` refused) and calls `HttpTransport`, which signs admin requests over
the decoded path, retries, and maps NA errors to `GenesisMeshError`.

**Offline verification** (library or `genesis-mesh-verify`): input is read
with `parse_strict_json`; `verify`, `key_history` and `audit_pack` check
signatures over canonical forms (`canonical`, `auth`), refuse unknown fields
(`strict`), and return reason codes that match the Python reference.

## Where a change goes

Each recipe lists the files to touch and the test that fails when one is
missed.

**A record kind verified offline.** Copy the core's suite and
`field_registry.json` into `tests/fixtures/` and run
`python scripts/sync_canonical_registry.py`; in `verify.rs`: `RECORD_KINDS`,
the id and envelope tables (`OUT_OF_BAND_IDS` or `GRANT_MODELS`,
`ENVELOPE_FIELDS`), the model, payload and record-id arms, and the arms in
`verify_evidence_events` and `verify_record`; `key_history.rs`
`NA_RECORD_TIME_FIELDS` if NA-signed; `audit_pack.rs` counts; `strict.rs` if
the canonical form has rules of its own; `outbox.rs`/`outbox_entry.rs`
(`RecordKind`, `RecordOutboxEntry::new`, a refusal list) if submittable;
`evidence_store.rs` routes; the verifier adapter
(`verifier/tests/adapter/mod.rs` `COUNTS`); a fragment. Fails if missed:
`tests/field_registry_conformance.rs` (registry not synced), the suite's
harness in `tests/`, the differential corpus in CI (`GM_VERIFY_CORPUS_STRICT=1`:
a case without an adapter), `tests/record_outbox.rs` (refusal list length).

**An HTTP sub-client method.** The method in `src/<domain>.rs`, with every
identifier in the path through `segment`/`resource_path`; for a new
sub-client also a `client.rs` field, a `lib.rs` re-export, a layer in
`tests/architecture.rs`; a test in `tests/http_contract.rs` (method, path
and admin signature against the mock server); the README's "API coverage";
a fragment. Fails if missed: `tests/architecture.rs` (unplaced module),
`tests/http_contract.rs`.

**An SDK error code.** A `GenesisMeshError` variant and its `code()` arm in
`errors.rs`; the outbox refusal lists in `outbox.rs` if the NA refuses a
record with it for good. Fails if missed: the build (`code()` has no
wildcard arm); `tests/record_outbox.rs` for the list lengths.

**A verification reason code.** The string at the `fail()` site in
`verify.rs` (or `audit_pack.rs`, `key_history.rs`), the same as the
reference's. Fails if missed: the core's vector or corpus case that covers
it; there is no registry yet.

**A conformance suite.** The JSON in `tests/fixtures/` (unchanged), its name
in the vector compare loop in `.github/workflows/ci.yml`, a harness
`tests/<suite>.rs`, an arm in `verifier/tests/adapter/mod.rs` if the
verifier covers it, a paragraph in `tests/fixtures/README.md`. Fails if
missed: CI "SDK against core main" (a listed suite that differs from or is
missing in the core).

**A public API change.** Add, never change or remove, within a major
version. Fails if missed: CI "API compatibility" (cargo-semver-checks
against the latest `v*` tag); an incompatible change needs the label
`breaking` and a fragment with an `### Upgrading` note.

**An edge local-API endpoint.** The `route()` match and its body reader in
`edge/src/api.rs`, the method on `Agent` in `edge/src/agent.rs`, a section of
`docs/edge.md`, a unit test in `api.rs` or a scenario in
`edge/tests/scenario.rs`. Fails if missed: those tests (the scenarios run
against a live NA in the Edge workflow).

**An edge configuration key.** The file-section struct, the `Config` field
and the environment merge in `edge/src/config.rs`,
`edge/packaging/edge.toml.example`, `docs/edge.md`. Fails if missed: the
config tests in `config.rs` for the merge order; nothing checks the example
and the docs yet.

**A shared helper.** Put it in the lowest layer that every user can reach
(`rules` for value rules, `shape` for structural checks); never import a
module above you to reach one. Fails if missed: `tests/architecture.rs`.
