### Added

- **The operator key that asked is checked offline (1.10.0).** A Network
  Authority 1.10.0 names the key that asked for an attestation-basis decision
  in `attestation_binding.requester_key_id`, under the decision's signature.
  `ExpectedBinding::requester_key_id` makes
  `verify_boundary_decision_expecting` accept only a decision that key asked
  for: another key is `attestation_binding_mismatch`, and a decision without
  the field (a 1.9.x NA) is `attestation_binding_missing` only when it is set.
  The decision shape and the canonical registry read the field, omitted when
  absent.

### Upgrading

- **Upgrade this crate before, or with, a 1.10.0 Network Authority.** Earlier
  releases refuse a decision that names its requester as `unknown_field`.
