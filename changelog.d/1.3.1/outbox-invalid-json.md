### Fixed

- **One record the NA cannot read no longer blocks an outbox.** The NA's
  strict JSON reader refuses a whole request with `400 invalid_json`. The
  outboxes retried that answer, and `flush_records` sent the same batch of up
  to 100 observations every time, so one such record held back every
  observation behind it. `invalid_json` is now a refusal no retry can
  overcome (`PERMANENT_REFUSALS`, `RECORD_PERMANENT_REFUSALS`). A batch the NA
  refuses as a whole is split in halves until the record it refuses is tried
  alone; that record becomes a dead letter and the rest are admitted. A
  response this crate cannot read is not the NA's refusal and is still
  retried.

### Upgrading

- `PERMANENT_REFUSALS` is now a `[&str; 14]` and `RECORD_PERMANENT_REFUSALS` a
  `[&str; 15]`. Code that names their array types changes with them.
