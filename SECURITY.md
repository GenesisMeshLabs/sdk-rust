# Security Policy

## Supported Versions

| Version | Supported |
|---|---|
| 0.56.x | Yes |
| < 0.56 | No |

## Scope

This policy covers the `genesis-mesh-sdk` Rust crate. It does not cover the
Genesis Mesh Network Authority server or the protocol itself.

Vulnerabilities in scope:

- Incorrect Ed25519 signature construction
- Incorrect canonical JSON output for admin signatures
- Admin header construction that leaks key material
- Error handling that leaks unexpected internal details
- Dependency vulnerabilities in the SDK crate

## Reporting A Vulnerability

Do not open a public GitHub issue for security vulnerabilities.

Use GitHub private vulnerability reporting from the repository Security tab.
You will receive a response within 72 hours.
