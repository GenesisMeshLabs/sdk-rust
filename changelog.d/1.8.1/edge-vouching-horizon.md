### Changed

- **The edge agent follows the vouching horizon (Genesis Mesh 1.8.0).**
  - The CRL and the attestations it relies on must be signed by an NA key
    valid at their own time that still vouches now: their key's end, the
    300-second hand-over and the grace, which the NA's published
    `vouching_grace_seconds` may only shorten.
  - Grant holders get the NA's key history and its grace instead of a flat
    list of keys: a grant past its key's horizon ends as `grant_expired`, and
    revocation feeds are ordered by their signer's key, then by `sequence`.
  - A sync that brings a new succession, or a new grace, rebuilds every
    holder with the NA's keys. A holder built before a succession refused
    the time tokens and feeds the new key signed.
  - After a succession takes effect, the agent renews a certificate the
    succeeded key signed: at its own share of the 10 minutes after the
    succession (from its node key), and within half the grace, as Genesis
    Mesh nodes do. It renewed only before expiry.
