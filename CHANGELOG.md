# Changelog

## 1.2.0 - Unreleased

### Changed (breaking)

- **Verifiers refuse signed fields they do not know.** This crate used to
  copy every received field into the signed form, so a field a newer signer
  covered verified here and could change what a record means. It now embeds
  the field registry of signed records (generated from the Python reference,
  shipped in the shared conformance suite `field_registry`). Verifiers check
  the signature over the record as received first; an authentic record with a
  signed field the registry does not list is then refused as `unknown_field`,
  meaning this crate must be upgraded: `verify_boundary_decision` (also for
  the expected policies and attestation), the signature helpers (which return
  `false`) and `verify_evidence_events`. Only the signed projection is
  checked; free-form fields (`claims`, `execution_parameters`, ...) stay open.
- `verify_evidence_events` names an entry of an unknown kind
  (`unknown_entry_kind`, previously `payload_invalid`) and keeps it in the
  chain; `parse_export_lines` accepts entries of any kind. A field outside a
  stored record's signature (records stored before 1.1.1) is reported in the
  new `EvidenceVerification::warnings` as `unsigned_field` and the record is
  verified without it. `EvidenceVerification` gains the `warnings` field.

- **Records are valid only in their canonical form.** `verify_boundary_decision`
  refuses a decision signed over a timestamp the reference does not write
  (`+00:00` rather than `Z`, a fraction `.000`) as `non_canonical_form`.
  Records the NA signs are always canonical.
- **JSON is read strictly.** HTTP responses and `parse_export_lines` refuse
  JSON every implementation would not read alike with the new
  `GenesisMeshError::StrictJson` (`code()` is the reason): `duplicate_key`,
  `non_finite_number` (`1e400`), `integer_out_of_range` (outside
  `-2**63 .. 2**64 - 1`; `serde_json` read a larger integer as a float),
  `negative_zero`, `lone_surrogate` or `invalid_json` (not JSON, a byte
  order mark, text that is not UTF-8, or arrays and objects nested more than
  64 deep). A malformed response is now `StrictJson` rather than `Json`.
  The new variant is a breaking change for an exhaustive `match` on
  `GenesisMeshError`; the enum becomes `#[non_exhaustive]` with the outbox
  (*Changed (breaking)*), so later variants are not.
- **A decision without `denial_reason` or `freshness_proof` is no longer
  `payload_invalid`.** The NA signs both as `null`, so one received without
  them fails as `invalid_signature`, as in every implementation.
- `parse_export_lines` strips only JSON whitespace around a line (`trim`
  also removed other Unicode spaces, which every other implementation
  refuses).

### Added

- `check_strict_json`, `parse_strict_json`, `strict::canonical_timestamp`
  and `strict::non_canonical_timestamps`; the shared conformance suite
  `canonical`, compared with the core's in CI.
- `genesis_mesh_sdk::strict::{unknown_fields, is_known_entry_kind}` and
  `canonical::DECISION_OMITTED_WHEN_ABSENT`;
  `scripts/sync_canonical_registry.py` regenerates the embedded registry from
  a new copy of the suite, and CI checks the suite against the core's.

## 1.1.1 - 2026-10-09

Coordinated Genesis Mesh v1.1.1 release: security fixes in the Network
Authority. No API change in this SDK.

### Changed

- A 1.1.1 Network Authority decides under an agreement only if two parties it
  recognises signed it, binds the requester and provider to the agreement's
  parties, needs a privileged key to counter an offer, and admits execution
  evidence only in its exact signed form with UTC timestamps. Requests this
  SDK builds are unchanged; see *Upgrading to 1.1.1* in the core upgrade
  guide.

## 1.1.0 - 2026-10-08

Coordinated Genesis Mesh v1.1.0 release: signed container images and a local
governed Network Authority. No API change in this SDK.

### Fixed

- `ExecutionRecorder` no longer stamps evidence before its decision. Evidence
  recorded in the decision's millisecond, or on a host whose clock is behind
  the Network Authority's, could come out before `decision_made_at`, and the
  NA refused it with `evidence_outside_decision_window`. Without an explicit
  `executed_at`, the recorder now uses the later of the clock and the
  decision time. An explicit `executed_at` is signed unchanged.

### Changed

- The README links *Develop Against a Local Network Authority*: a governed
  Network Authority on a developer's machine, with a privileged setup key and
  a standard controller key (`genesis-mesh` 1.1.0).
- CI pins its actions to commits and runs with a read-only token; the
  security policy follows the core.

## 1.0.2 - 2026-10-05

Coordinated Genesis Mesh v1.0.2 release: fixes from external testing.

### Changed

- **Admin signatures cover the whole request (signature version 2):** the
  client signs the HTTP method, the decoded path, the query parameters and the
  target NA's public key, read once from `/sovereign.json` or given with
  `ClientOptions::with_audience`. Network Authorities from 1.0.2 accept only
  version 2 by default.
- **Breaking:** `build_admin_headers` takes an
  `AdminRequest` (`method`, `path`, `query`, `audience`, `body`) instead of a
  body, and `ClientOptions` has a new public `audience` field. New:
  `admin_signing_payload`, `build_admin_headers_at`, `ADMIN_SIGNATURE_VERSION`.
  Shared conformance vectors: `tests/fixtures/admin_auth.json`.

## 1.0.1 - 2026-10-04

Coordinated Genesis Mesh v1.0.1 release: gateway console fixes. No changes in
this SDK.

## 1.0.0 - 2026-10-04

Coordinated Genesis Mesh v1.0.0 release: the public contract is stable for
the 1.x line and Genesis Mesh is ready for an independently operated pilot.
No functional changes in this SDK; its documented stable surface follows the
1.x compatibility rules.

## 0.65.0 - 2026-10-04

Coordinated Genesis Mesh v0.65.0 release. No functional changes.

## 0.64.1 - 2026-10-03

Coordinated Genesis Mesh v0.64.1 release. No functional changes.

## 0.64.0 - 2026-10-03

Governed-action parity with the TypeScript SDK.

- `policy`: boundary policy lifecycle (validate, publish, list, active,
  history, activate, deactivate, verify).
- `boundary.evaluate`: policy-aware evaluation under one basis
  (`attestation_id` or `agreement`).
- `evidence_store`: submission, search (paged), status, verification,
  resource and vendor histories, resource heads (with the fallback for NAs
  before 0.63.1), JSON Lines export (paged), executor keys and retention.
- `health`: liveness and readiness (a not-ready NA is `ready: false`).
- `ExecutionRecorder` and `governed_action`: verify the decision offline, act
  only on ALLOW, sign and submit execution evidence linked to the resource
  chain; failures are recorded without their error text.
- `verify` and `canonical`: offline verification and canonical digests ported
  from the Python reference with the same reason codes, tested against
  Python-produced vectors.
- Transport: signed admin GETs, query parameters, text responses, and
  identifiers encoded once per path segment (dot segments refused).
- `tests/live_na.rs`: the governed lifecycle against a live NA; CI runs it
  against core main.

## 0.63.1 - 2026-10-02

Coordinated Genesis Mesh v0.63.1 release. No functional changes.

## 0.63.0 - 2026-10-02

Coordinated Genesis Mesh v0.63.0 release (pilot readiness). No functional
changes.

## 0.62.0 - 2026-10-02

Coordinated Genesis Mesh v0.62.0 release (v1 public contract and security
review). No functional changes; this crate is classified beta in the v1
contract.

## 0.61.1 - 2026-10-02

Coordinated Genesis Mesh v0.61.1 release. No functional changes; the Go, .NET
and TypeScript SDKs fix their consensus types, and the core revises its
formal models and RFCs.

## 0.61.0 - 2026-10-02

Coordinated Genesis Mesh v0.61.0 release. No functional changes; the core adds
the cross-language interoperability proof, in which the Go, TypeScript and .NET
SDKs verify Network Authority records offline. This SDK is not a leg of that
scenario yet.

## 0.60.0 - 2026-10-01

Coordinated Genesis Mesh v0.60.0 release. No functional changes; the core adds
optional high availability for the Network Authority (PostgreSQL, several
instances behind a load balancer). This SDK keeps using one NA URL, which can
be the load balancer.

## 0.59.1 - 2026-10-01

Coordinated Genesis Mesh v0.59.1 release. No functional changes; the TypeScript
SDK adds attestation-backed evaluation, the boundary policy lifecycle and the
evidence store client. This SDK does not wrap them yet.

## 0.59.0 - 2026-10-01

Coordinated Genesis Mesh v0.59.0 release. No functional changes; the core adds
the Network Authority evidence store, which this SDK does not wrap yet.

## 0.58.1 - 2026-09-29

Coordinated Genesis Mesh v0.58.1 release. No functional changes; the core adds
attestation-backed boundary evaluation, which this SDK does not wrap yet.

## 0.58.0 - 2026-09-29

First release in the coordinated Genesis Mesh train (0.57 was skipped across the
train; see the core `docs/development/versioning.md`).

- CI and publishing now fail if this component's version is ahead of the Genesis Mesh core version.

- Match server canonical JSON for Unicode, DEL, and floating-point values.
- Reduce temporary allocations in canonical serialization and response decoding.
- Redact signing seeds from client option debug output.
- Validate URLs, key IDs, timeouts, and route paths before requests.
- Disable HTTP redirects and encode attestation IDs as path segments.
- Preserve HTTP errors when the response body is plain text, HTML, or empty.
- Resolve and lock Rust 1.85-compatible dependencies.
- Add Python interoperability fixtures, HTTP contract tests for all 22 domain
  methods, compiled examples, and README doctests.
- Add multi-platform CI, dependency auditing, and release metadata/package checks.

## 0.56.0

- Initial Rust MVP SDK for the Genesis Mesh Network Authority HTTP API.
- Added admin Ed25519 request signing.
- Added async HTTP transport with typed SDK errors.
- Added Agreement, Attestation, Boundary, Consensus, DataUsage, Disclosure, and
  Evidence sub-clients over JSON request and response bodies.
