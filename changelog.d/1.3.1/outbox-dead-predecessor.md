### Fixed

- **A record behind a dead letter no longer waits forever.** When a record's
  predecessor had been dead-lettered by an earlier run (or its dead-lettering
  was not stored), `flush_pending` submitted the record. The NA answered
  `resource_chain_gap`, which was retried on every run, and the record held
  back its resource. A record that chains from a dead letter is still
  submitted, as in the TypeScript SDK, so the NA can quarantine it when it
  refuses it for good on its own account. When the NA refuses it for the gap
  (`evidence_chain_gap`, `resource_chain_gap`), it becomes a dead letter with
  `evidence_predecessor_dead_lettered` and the NA's answer in its message.

### Changed

- `enqueue` and `flush_pending` no longer dead-letter the records behind a
  refused record without submitting them. Each is submitted in turn and
  settled by the NA's answer.
