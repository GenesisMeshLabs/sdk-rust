### Added

- **Expected policy IDs (1.10.0).** `ExpectedBinding::policy_id` names a
  policy an ALLOW must rest on, at whatever version the NA signed, for
  `verify_boundary_decision_expecting`. Each must be in the decision's policy
  binding with at least one enforce-mode gate of that version evaluated, so
  an ALLOW left when a policy was deactivated or its selector stopped
  matching is refused (`policy_binding_mismatch`; `policy_binding_missing`
  without a binding). A DENY is reported as it is. A governed action's
  callback can run the check on the decision it is given before it changes
  anything; `GovernedVerification` is unchanged. A 1.10.0 Network Authority
  can also deny such requests itself (`BOUNDARY_POLICY_COVERAGE=required`);
  the denial arrives as `unauthorized_policy_resolution_failed`.
- **The shared decision vectors run here too.** `tests/fixtures/interop.json`
  is the core's `interop` suite, and `tests/decision_vectors.rs` checks every
  boundary decision vector (`bd-001` to `bd-017`) against the reference's
  answer.
