# Security Policy

## Supported Versions

Only the latest minor release of the 1.x line receives security fixes, as
for the Genesis Mesh core it is released with. Releases before 1.0.0 are
unsupported.

| Version | Supported |
|---------|-----------|
| Latest 1.x minor | Yes |
| Older 1.x minors | No: upgrade |
| < 1.0 | No |

## Scope

This policy covers the `genesis-mesh-sdk` Rust crate, the offline
verifier `genesis-mesh-verify` and the edge agent `genesis-mesh-edge`
(beta, 1.7.0: its binaries and its container image). It does not cover the
Genesis Mesh Network Authority server or the protocol itself.

Vulnerabilities in scope:

- Incorrect Ed25519 signature construction
- Incorrect canonical JSON output for admin signatures
- Admin header construction that leaks key material
- Error handling that leaks unexpected internal details
- Incorrect node request signatures (`node_auth`)
- An edge agent that admits an unauthenticated local client, uses a grant
  outside its envelope, its budget or a fresh snapshot, breaks the glass
  when the NA answered (a refusal, a 429 or a 5xx with the NA's error body),
  lets one local client report another's outcome or take the local API down,
  or writes a key, token or parameter value where it should not (state
  files, logs)
- A verifier (`genesis-mesh-verify`, or the crate's `verify`, `key_history`
  and `audit_pack` modules) that accepts a record, export or pack the
  Python reference refuses, or reports a different reason code
- Dependency vulnerabilities in the SDK crate, the verifier or the agent

The edge agent assumes the device's clock is within 5 minutes of the NA's
(docs/edge.md, "The device's clock"): a clock that runs slow while offline
is not detected, and the hard bound on a grant offline is its uses per time
token.

Not a vulnerability by itself: the SDK's break-glass
(`governed_action_with_break_glass`, the grant holder's fallback and
`urgent_action`) counts any `429` or `5xx` from the NA as no answer, apart
from `429 admin_auth_throttled`, `503 evidence_store_unavailable` and an
unreadable body, even when the NA's own error body comes with it. That rule
is deliberate (README, "Break-glass"); the edge agent applies a stricter one.

## Reporting A Vulnerability

Do not open a public GitHub issue for security vulnerabilities.

Use GitHub private vulnerability reporting from the repository Security tab
([github.com/GenesisMeshLabs/sdk-rust/security/advisories/new](https://github.com/GenesisMeshLabs/sdk-rust/security/advisories/new)).
Include a description, reproduction steps and the version (the crate's
version or commit, or `genesis-mesh-verify --version` or
`genesis-mesh-edge --version`).

- You should receive an acknowledgement within **5 business days**.
- Expect a remediation plan within **30 days** for confirmed issues, longer
  for cryptographic findings that require a redesign.

Coordinated disclosure is preferred. If you publish before a fix exists,
please give the project a reasonable window first.
