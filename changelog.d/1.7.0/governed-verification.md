### Changed (breaking)

- **`GovernedVerification.any_bound_policies` (beta, default `false`).** When
  `true`, a governed action accepts whatever policy versions the NA's
  decision binds instead of comparing them with `expected_policies`; the
  NA's signature, the context and the attestation are still checked. A
  device that holds no policies, such as the edge agent, sets it. Code that
  builds `GovernedVerification` with a struct literal naming every field must
  add the field, or use `..GovernedVerification::default()`.
