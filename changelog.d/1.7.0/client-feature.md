### Changed

- **The HTTP client is the default feature `client`.** `reqwest`,
  `percent-encoding`, every client that calls the NA (`GenesisMeshClient`,
  the sub-clients, `governed_action` and the rest of the governance
  composition, `GrantHolder`), and the error variants that hold a transport
  error (`GenesisMeshError::Network`, `GenesisMeshError::ResponseBodyUnreadable`)
  need it. Without it the crate is its offline modules only: verification,
  canonical forms, signing, the outboxes, the grant rules, audit packs and
  node request signatures, with no HTTP stack, no `tokio` and no TLS.
  `genesis-mesh-verify` now depends on the SDK without it, so its build no
  longer compiles the HTTP stack at all. With the default features the API is
  unchanged (apart from `GovernedVerification`, see below).
- **`ResourceHead` is defined with the offline modules.** It is still
  `genesis_mesh_sdk::ResourceHead`; only its source module moved, so it is
  available without the `client` feature.

### Upgrading

- `default-features = false` now drops the HTTP client. If you turned the
  default features off for another reason and call the NA, add
  `features = ["client"]`.
