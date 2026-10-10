### Fixed

- **A record outbox no longer deletes an execution outbox's crash
  leftovers.** Opened on a directory of the other outbox's files,
  `FileRecordOutbox` (or `FileOutbox`) removed that outbox's temporary files
  before refusing the directory. A crash during an add leaves such a file, so
  a signed record that its own outbox would have recovered was lost. A
  directory with a temporary file of the other format is now refused before
  anything in it changes.
- The outbox documentation says plainly that nothing stops two processes from
  sharing one outbox directory. Two processes that share one submit each
  other's records and overwrite each other's changes, so give each process a
  directory of its own.
