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

`anchors.json` (1.5.0) holds store anchors over that export, signed with the public
test seed `bytes(range(32))`, and the reference's answers: `verify_store_anchors` for
runs of anchors, and the whole `genesis-mesh evidence verify-export --known-anchors
--format json` output for exports checked against them. Regenerate it with
`python scripts/generate_anchor_vectors.py` (the core installed); the core's
verification corpus supersedes it once that covers anchors.

`audit.json` (1.5.0) is the core's `audit` conformance suite (key histories, key
windows, exports and anchors across a key succession, decisions at their own
time, packs and the completeness check), copied unchanged; so is
`audit-pack-1.5.0/`, the frozen 1.5.0 pack with its root key and the anchors an
auditor holds. Its files are byte-exact (`.gitattributes`): its manifest holds
their digests.
