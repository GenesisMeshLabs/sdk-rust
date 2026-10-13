### Added

- **A decision judged as of its own time.**
  `VerifyDecisionOptions::at_record_time` (the reference's name) judges a
  decision as of its `decision_made_at` instead of now, so an archived
  decision still verifies when it is audited years later. It is off by
  default: a decision about to be acted on is judged as of now, as before.
  `verify_record` and `genesis-mesh-verify record decision` judge as of the
  decision's own time unless given one.

### Fixed

- **A record with a field outside its signature is refused.** A retention
  checkpoint, and every record kind from 1.3.0 on, holding one is
  `payload_invalid`, as the reference refuses it; this crate warned
  `unsigned_field` for a checkpoint and verified the rest. Justifications and
  execution evidence keep the warning.

### Upgrading

- `VerifyDecisionOptions` gains `at_record_time` and `key_history`;
  `VerifyEvidenceOptions` gains `key_history` and `prior`; and
  `EvidenceVerification` gains the counts `key_successions` and `archives`:
  code that builds them field by field must name the new fields (`false` and
  `None` keep the behaviour of 1.4). `VerifyEvidenceOptions::new` sets them.
