### Fixed

- **An observation of one source event always has the same id.**
  `ObservationRecorder::record` used a random `observation_id`, so recording
  one finding again (`observation_from_finding` after a restart, a second run
  over one scan) signed a different record for the same source event. The NA
  refused it for good as `observation_conflict` and it was dead-lettered. The
  default id is now `observation_id(observer, source, source_event_id)`: the
  SHA-256, in hex, of the observer sovereign, source and source event id
  joined by NUL characters, as in the TypeScript SDK. The same record signed
  again is a `duplicate`. An id you give is kept.
