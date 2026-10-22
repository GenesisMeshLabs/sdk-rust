### Security

- **The edge agent checks each record with the NA keys valid at its time.**
  The agent flattened the NA's key history into every key it ever had, valid
  at any time. After a key succession, whoever still held the outgoing key
  could sign a CRL, a join certificate or an attestation the agent accepted.
  Each of these is now checked with the keys valid at its own `issued_at`.
  Decisions are checked with the keys valid now. A grant holder gets the
  keys of its grant's issue time and of now.
