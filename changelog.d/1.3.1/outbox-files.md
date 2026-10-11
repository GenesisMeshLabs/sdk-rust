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

### Changed

- **An outbox file that cannot be read no longer stops every action.**
  `FileOutbox` and `FileRecordOutbox` failed every read, and so every governed
  action, while one entry file was not readable. They now move the file aside
  as `<name>.unreadable` and fail the read that found it, once
  (`GenesisMeshError::Outbox`, code `outbox_file_unreadable`), as the
  TypeScript SDK does. The record it held is not submitted, so inspect the
  file. A file of the other outbox's format is still refused, and left where
  it is.
