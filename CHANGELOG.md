# Changelog

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
