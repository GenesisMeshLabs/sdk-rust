### Added

- **`verify::verify_boundary_decision_expecting` checks an expected
  attestation or subject.** With an `ExpectedBinding` built by
  `ExpectedBinding::new().attestation_id(..).subject_id(..)`, the decision's
  signed `attestation_binding` must name that attestation and subject: another
  one fails with `attestation_binding_mismatch`, and a decision without an
  attestation binding with `attestation_binding_missing`. A relying party that
  does not hold the attestation can now check that a decision was made for the
  subject it expects. From 1.9.2 the Network Authority makes attestation-basis
  decisions only for the attestation's subject (core 1.9.2).
  `ExpectedBinding` is `#[non_exhaustive]`, so later releases can add
  expectations without breaking callers; `VerifyDecisionOptions` is unchanged.
