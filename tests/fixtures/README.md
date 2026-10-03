# Python interoperability fixtures

Generated with CPython 3.14 `json.dumps(value, sort_keys=True, separators=(",", ":"))`.
The canonical corpus includes nested Unicode, control characters, surrogate pairs,
integer bounds, float threshold cases, and 1,000 deterministic random IEEE 754
bit patterns (`random.Random(56).randbytes(8)`, big-endian doubles; nonfinite values
excluded). JSON parsing in Rust enables `float_roundtrip` to preserve those values.

The signature fixture uses Python cryptography Ed25519 with the public test seed
`bytes(range(32))`. It is a test vector, never an operator credential.

`python-vectors.json` (shared with the TypeScript SDK) holds artifacts signed by
the Python core: an attestation, a boundary policy, allowed and denied decisions
with justification proofs, execution evidence on one resource chain, a retention
checkpoint, a JSON Lines export of the store and the NA's own verification of it.
Its keys are test keys generated for the fixture.
