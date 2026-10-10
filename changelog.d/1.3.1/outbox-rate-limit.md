### Fixed

- **A rate-limited record backlog drains.** `flush_records` sent batches of
  100 observations, and the NA counts each observation in a batch against
  `NA_RATE_LIMIT_OBSERVATIONS_PER_MINUTE`. With a limit below 100 every batch
  was refused with `429` and sent again unchanged, so the backlog never
  drained. A batch answered `429` now halves the batches the client sends
  after it.
- **Outboxes wait as long as the NA asks.** After a refusal with a
  `Retry-After` header (seconds or an HTTP date), the next attempt of the
  record waits at least that long, at most 15 minutes. This holds for
  `flush_pending`, `flush_records`, `enqueue` and `enqueue_record`.
