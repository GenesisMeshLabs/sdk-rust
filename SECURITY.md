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

This policy covers the `genesis-mesh-sdk` Rust crate, the independent
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
- Dependency vulnerabilities in the SDK crate, the verifier or the agent

The edge agent assumes the device's clock is within 5 minutes of the NA's
(docs/edge.md, "The device's clock"): a clock that runs slow while offline
is not detected, and the hard bound on a grant offline is its uses per time
token.

## Reporting A Vulnerability

Do not open a public GitHub issue for security vulnerabilities.

Use GitHub private vulnerability reporting from the repository Security tab.
You will receive a response within 72 hours.
