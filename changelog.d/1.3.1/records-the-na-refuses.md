### Fixed

- **A record the NA would refuse as malformed is not signed.**
  `ObservationRecorder::record` and `ExecutionRecorder::sign_break_glass`
  refuse the following before signing (`observation_malformed`,
  `break_glass_malformed`): an action other than `create`, `rotate`,
  `revoke`, `update` or `delete`; a field longer or shorter than the reference
  takes (`resource_id`, `capability`, `source`, `actor`, ...); and a time
  outside the years 1 to 9999. `ExecutionRecorder::record` and
  `governed_action` refuse an unknown `resource_action` or a `resource_id` over
  256 characters (`Configuration`) before anything is evaluated or run.
  Before, these records were signed and then refused for good after the
  action had run.
- **A record no reader would take is not signed.** A record nested more than
  64 deep where it is submitted or kept in an outbox file is refused as
  `StrictJson` (`invalid_json`). Such a record was signed, then refused by the
  NA's strict reader on every attempt. After an action has run, its outcome
  is recorded without the parameters nested too deep: `MetadataRefused`, or
  `dropped` under break-glass.
