### Added

- **A decision judged as of its own time.**
  `VerifyDecisionOptions::as_of_record_time` judges a decision's expiry as of
  its `decision_made_at` instead of now, so an archived decision still
  verifies when it is audited years later. It is off by default: a decision
  about to be acted on is judged as of now, as before. `verify_record` and
  `genesis-mesh-verify record decision` judge as of the decision's own time
  unless given one.

### Upgrading

- `VerifyDecisionOptions` gains `as_of_record_time`: code that builds it
  field by field must name it (`false` keeps the behaviour of 1.4).
