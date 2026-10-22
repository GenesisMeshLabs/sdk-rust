### Added

- **Two walkthroughs, each with a recorded run.** `docs/examples/edge-agent.md`
  takes `genesis-mesh-edge` from a bound invite through a decision, an
  outage (a grant, then break-glass) and the uploads afterwards;
  `docs/examples/verify-audit-pack.md` verifies the frozen audit pack, the
  same pack with one byte changed, and compares the Python reference's
  verdict. The new `edge_site` example issues the walkthrough's policy,
  attestation and grant. `edge/` and `verifier/` gained a README.

### Changed

- **Documentation corrected against the code.** `enroll --reset` is
  documented as unusable with an invite bound to a node key (reset, `init`,
  a new invite, then `enroll`). The edge agent's "throttled or failing"
  class covers any `429` or `5xx` that is not a gateway's page, with or
  without the NA's body, and exit 5 covers an NA that answers `429` or
  `5xx` during `enroll`. The README states that the SDK's break-glass counts
  a `429` or `5xx` as no answer while the edge agent does not; both are
  deliberate. The API table lists `node`, `grants.uses` and the outbox
  methods; the verifier page pins 1.7.0, describes itself as a port of the
  Python reference rather than an independent implementation, and names the
  functions its clippy rules refuse. `edge.toml.example` shows
  `rate_limit_per_minute` and says the allow-lists must not both be empty.
- **Security policy.** Acknowledgement within 5 business days and a
  remediation plan within 30 days for confirmed issues, as for the core; a
  verifier that accepts what the reference refuses is in scope.
