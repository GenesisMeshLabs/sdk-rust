# genesis-mesh-verify: independent verification

`genesis-mesh-verify` verifies Genesis Mesh records and evidence exports
offline, on the auditor's own machines, from keys and anchors the auditor
holds. It is built from this crate's `verify` module, the code the Rust SDK
verifies with, and ships from Genesis Mesh 1.5.0 as static Linux binaries
(x86-64 and arm64) with checksums, Sigstore bundles and a documented
reproducible build.

"Independent" means separate code by the same project: the Python reference
(`genesis-mesh evidence verify-export`, `genesis-mesh audit verify`) and this
verifier are two implementations of one specification. Each verdict and
reason code is the reference's; a difference between them is a bug in one of
them, resolved against the specification (see
[Reading a mismatch](#reading-a-mismatch)).

## What it never does

The verifier never needs a private key and never contacts a network. Every
key, record, export and anchor is given on the command line, as a file or a
value. This is enforced, not only intended:

- `verifier/clippy.toml` refuses, in the binary's code, the SDK's HTTP
  clients, network sockets (`std::net`), the recorders that sign and every
  function that reads a private key or signs; CI runs clippy with
  `-D warnings`.
- A test refuses any mention of an HTTP or network crate, a socket, a signing
  key, or an `allow` of those clippy rules in the binary's sources.
- The released binary is checked to link no HTTP or network crate (the SDK's
  HTTP client is a dependency of the library, never called by the binary,
  and left out at link time).
- CI runs the verifier's tests against each released binary inside a network
  namespace with no network.

## Install

Each release attaches, per architecture:

| File | What it is |
|---|---|
| `genesis-mesh-verify-<version>-x86_64-unknown-linux-musl` | The binary for x86-64 Linux |
| `genesis-mesh-verify-<version>-aarch64-unknown-linux-musl` | The binary for arm64 Linux |
| `<binary>.sha256` | Its SHA-256 |
| `<binary>.sigstore.json` | Its Sigstore bundle |
| `<binary>.buildinfo` | The commit, toolchain, compiler and linker that built it |
| `SHA256SUMS`, `SHA256SUMS.sigstore.json` | Every binary's digest, signed |

The binaries are statically linked (musl): they run on any Linux of their
architecture and need no shared library. Check the signature and the digest
before you use one:

```sh
version=1.5.0
binary=genesis-mesh-verify-$version-x86_64-unknown-linux-musl
cosign verify-blob --bundle "$binary.sigstore.json" \
  --certificate-identity "https://github.com/GenesisMeshLabs/sdk-rust/.github/workflows/verifier.yml@refs/tags/v$version" \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com "$binary"
sha256sum --check "$binary.sha256"
chmod +x "$binary"
```

For a stronger check, rebuild it from source and compare digests
([Rebuild and compare](#rebuild-and-compare)).

## Usage

```text
genesis-mesh-verify record <kind> <file> [options]
genesis-mesh-verify export <file> [options]
genesis-mesh-verify pack <dir> --anchor <root key> [options]
genesis-mesh-verify key-history <file> --root-key <key>
```

A key is a base64 Ed25519 public key, given inline or as a file holding it
(`#` lines ignored), as `genesis-mesh` reads one. `--json` prints the result
as JSON; without it the result is readable text.

### One record

```sh
genesis-mesh-verify record decision decision.json --na-key na.pub
genesis-mesh-verify record execution evidence.json --executor-keys executor-keys.json
```

`<kind>` is one of the kinds in [What is checked](#what-is-checked)
(`checkpoint` for a retention checkpoint; `break-glass` and `break_glass`
alike; `key-succession` and `archive` from 1.5.0). The NA's keys come from
`--key-history <file> --root-key <key>` (the NA's key history, `GET
/na/key-history`, verified from the root key you hold: each NA key verifies
only what it signed while it was valid) or, before 1.5.0 or for one key,
`--na-key` (repeatable; valid at every time). `--executor-keys` gives the
JSON from `GET /admin/evidence/executor-keys` (or a list of its keys). A
decision as the NA returns it (`{"decision": ..., ...}`) is read as the
decision it holds.

For a decision only: `--at <time>` judges its expiry at an RFC 3339 time
instead of its own; `--freshness-key` (repeatable) checks its freshness proof;
`--expect-policy <file>` (repeatable) and `--expect-attestation <file>` check
that it binds exactly those policy versions and that attestation.

### An evidence export

```sh
genesis-mesh-verify export export.jsonl --na-key na.pub \
    --executor-keys executor-keys.json --known-anchors /audit/anchors
```

The same checks, options and JSON as `genesis-mesh evidence verify-export`:

- `--key-history <file> --root-key <key>` or `--na-key`, and
  `--executor-keys`, as for a record;
- `--known-anchors <path>`: anchors held outside the NA, a directory written
  by `genesis-mesh evidence anchors fetch` or a JSON or JSON Lines file;
- `--checkpoint <file>`: the retention checkpoint the export continues from
  (by default the one the export holds, if it starts right after one);
- `--partial`: the export is a deliberate slice, so its ends are not checked
  against the anchors;
- `--from-anchor`: the export starts right after a held anchor;
- `--cited <file>`: the entries before the export that its records rest on
  (a pack's `cited.jsonl`): the export is then verified as a pack's range,
  every chain from its start, and a record it cites that neither holds is
  `cited_record_missing`. No checkpoint is taken from the export then; give
  one with `--checkpoint`.

### An audit pack

```sh
genesis-mesh-verify pack pack-2026 --anchor root.pub \
    --known-anchors /audit/anchors --changes cloud-log.csv
```

The checks, reason codes and JSON of `genesis-mesh audit verify` (the core's
`docs/reference/audit-pack-format.md` is the normative description):

- `--anchor <key>`: the root public key you hold (required): the NA's keys
  are accepted only through the key history, from the root key down;
- `--known-anchors <path>`: the anchors you hold. Without them the pack proves
  its integrity, not that nothing was removed: the result carries the
  warning `no_held_anchors`, and `--require-anchors` makes their absence fail;
- `--prior <dir>` (repeatable): a pack verified before, from the same root key
  and anchors; it must verify itself, and the entries this pack cites must
  equal the ones it holds (`cited_entry_mismatch`). `--prior-entries <file>`
  gives the same as JSON (`{"<store position>": "<entry digest>"}`). A cited
  entry that neither a prior pack nor a held anchor covers is a warning,
  `cited_entry_unanchored`: its signature verifies, its place in the store
  is not proven;
- `--period <from> <until>`: two RFC 3339 times; the pack must cover them
  (`pack_period_not_covered`);
- `--report <file>`: writes the report this verification renders, from what
  it verified;
- `--executor-keys <file>`: executor keys you hold, for a store without
  registry records (the pack's own `keys/executor-keys.json` is never
  trusted, and a key the pack's registry records place wins). A key supplied
  this way is not placed in the store: only registry records the NA signed
  say when a key was registered and retired;
- `--changes <file>`: changes from a log outside Genesis Mesh (CSV with a
  header row, or JSON; times in strict RFC 3339, fields strings or null),
  matched against the pack (`change_unmatched`; warnings
  `changes_outside_period` and `change_duplicate`); `--tolerance-seconds`
  (default 300) bounds how far apart a change and its record may be.

`report.md` is normative: the verifier renders the report from the pack's
files (the manifest, the entries, `checks.json`, `states.json`) byte for byte
and fails a pack whose report says anything else (`report_mismatch`); the
lines that differ are in `report_differences`. `check_differences` lists where
this verification differs from the NA's own checks in `checks.json`
(`verified`, the sorted reason codes, a count): not a failure by itself, since
the NA checked the pack against its own anchors.

### A key history

`key-history <file> --root-key <key>` verifies a genesis block and its key
successions (`{"genesis": ..., "successions": [...]}`, as `GET
/na/key-history` serves them) from the root key you hold, and lists each NA
key's validity: the genesis key until the first succession takes effect, each
later key from its `effective_at` until the next succession and never at or
after its own `new_valid_to`, and a succeeded key for 300 seconds more (the
hand-over).

### Output and exit codes

| Code | Meaning |
|---|---|
| 0 | Verified |
| 1 | Not verified: each failure names its reason code |
| 2 | Usage error: an unknown option, kind or command, or a key that is not one |
| 3 | An input could not be read: missing, not UTF-8, not strict JSON, or not the document it should be |
| 4 | Not available in this version (no command uses it in 1.5.0) |

`pack` also exits 1 when `--require-anchors` is given without anchors, or a
`--prior` pack does not verify.

Anything but 0 means the input is not verified. A genuine decision that denies
its action is verified (0): `authorized` is `false` and the reason is the
reference's `unauthorized_...` code.

With `--json`, `record` prints `kind`, `record_id`, `verified`, `reason` (the
first failure's code, `verified`, or a decision's `authorized` or
`unauthorized_...`), `authorized` for a decision, `failures` and `warnings`;
`export` prints the reference CLI's JSON (`verified`, `checked_entries`, the
counts, `failures` with `store_sequence`, `reason` and `detail`, `warnings`,
and `anchors` with `--known-anchors`); `pack` prints the reference's
`audit verify --format json` (`verified`, `failures` and `warnings` with
`file`, `store_sequence`, `reason` and `detail`, `counts`, `range`, `keys`,
`anchors`, `period`, `completeness`, `report_differences` when the report
differs, and `check_differences`); `key-history` prints
`verified`, `failures` and `keys`. A key history given with `--key-history`
that does not verify fails the record or export (exit 1) with its reason. A
usage or input error prints `{"error": {"exit_code", "message"}}`.

## What is checked

### A single record

`record` checks a record as an export checks it as one of its entries, with
the same reason codes, in the same order: fields the crate does not know
(`unknown_field`), its form (`payload_invalid`), its signature
(`invalid_signature`) and the form the reference writes
(`non_canonical_form`). Each kind is signed by its own signer:

| Signed by | Kinds |
|---|---|
| The NA (`--key-history` or `--na-key`) | `decision`, `justification`, `checkpoint`, `judgement`, `quarantine`, `registry`, `review`, `archive`, `policy`, `attestation`, `grant`, `grant-revocation`, `time-token` (1.6.0) |
| The root key, the new key and the outgoing NA key (`--key-history`) | `key-succession` |
| An executor key of the record's sovereign (`--executor-keys`) | `execution`, `break-glass`, `remediation`, `grant-execution` (1.6.0: its grant's bearer key; its time token by the NA, `--na-key`) |
| An observer key of the record's sovereign (`--executor-keys`) | `observation` |

Some kinds carry checks of their own:

- a decision: expiry, its freshness proof and the bindings expected, as
  `verify_boundary_decision` checks them, then its verdict;
- a quarantine record: the digest of the record it holds
  (`quarantine_digest_mismatch`);
- a first retention checkpoint: the entries it removed
  (`retention_count_mismatch`);
- a review: its embedded admin approvals (`review_approval_invalid`) and a
  second holder (`review_same_holder`);
- a grant use (1.6.0): its time token, signed by the NA for its grant
  (`grant_time_token_invalid`), issued before it (`grant_time_token_mismatch`)
  and not after it was made (`grant_use_before_time_token`).

What needs the rest of the store (chains, the subject of a judgement,
remediation or review, matched evidence, a use's grant) is checked in an
export.

### As of the record's own time

A decision's expiry is judged as of its own time, `decision_made_at`, not as
of the day of the audit: an archived decision verifies years later. `--at`
judges it at another time. Its freshness proof is judged at
`decision_made_at`, and execution evidence must fall within its decision's
validity (`evidence_outside_decision_window`). Nothing else depends on the
time the verifier runs.

With the NA's key history, an NA signature must be made by the key valid at
the record's own time; a signature by another key of the history is
`na_key_not_valid_at_time`. In the store every entry is placed at its
`recorded_at`, and its key must also be valid at the latest `recorded_at`
before it in store order. Read alone, a record is placed at its own time:

| Record | Placed at |
|---|---|
| Decision | `decision_made_at` |
| Policy, attestation, treaty | `issued_at` |
| Grant, time token (1.6.0) | `issued_at` |
| Grant revocation (1.6.0) | `revoked_at` |
| Retention checkpoint, audit pack manifest | `created_at` |
| Justification | `proof_issued_at` |
| Judgement | `judged_at` |
| Quarantine record | `quarantined_at` |
| Registry record | `effective_at` |
| Review | `decided_at` |
| Archive record | `archived_at` |
| Store anchor | `anchored_at` |

A decision signed by a key that was later succeeded (or expired) may stay
valid no longer than that key's end, the 300-second hand-over and the
300-second lifetime cap of a decision (`decision_outlives_key`). In a
contiguous export each entry is recorded no more than 300 seconds before an
earlier one (`recorded_at_out_of_order`), except the registry, key succession
and archive entries retention carries forward after its checkpoint.

A key succession carries three signatures: the root key's, the new key's
(proof that the new key is held) and the outgoing key's. In the key history
it must name a key the history never held and not the root key
(`succession_key_reused`) and be issued no later than it takes effect
(`succession_backdated`); in the store it must also be one of the history's
successions (`succession_not_in_history`) and be recorded at least 60 seconds
before it takes effect (`succession_backdated`). The genesis block is held to
the rules of every signed record (`unknown_field`, `non_canonical_form`).

Executor and observer keys verify only records after their registration and
before their retirement, where the registry records the NA signed placed them
(in a pack; a key given with `--executor-keys` is not placed)
(`evidence_unknown_executor`, `evidence_executor_key_retired`). A retention
checkpoint, and every record kind from 1.3.0 on, with a field outside its
signature is `payload_invalid`; a justification or execution evidence only
warns `unsigned_field`.

### An export

`export` checks every line's envelope, digests and the store chain; every
record's signature under the keys its kind needs; the decision, resource and
observation chains; judgements, matches, remediations and reviews against
what they cite; retention checkpoints. The reason codes are the reference's
(`verify_evidence_events`).

Pre-issued grants (1.6.0): a grant use and a grant revocation name an
authentic grant the export holds from its start (`grant_missing`) with its
digest (`grant_mismatch`); a use takes its place in the grant's use chain
(`grant_use_chain_break`; a quarantined use that continued the chain is its
head), is signed by the grant's bearer key (`grant_bearer_mismatch`), within
the key's `resource_prefix` (`grant_use_out_of_scope`), at the position the
NA gave it in its resource's chain (`resource_chain_break`; a position
without a resource is `envelope_mismatch`), with a `use_id` no execution or
break-glass record holds (`duplicate_record`), and is checked by the use
rules with the NA's codes, in its order (`grant_capability_mismatch`,
`grant_envelope_mismatch`, `grant_budget_exhausted` over the admitted uses,
the time token's `grant_time_token_*`, the times' `grant_use_*` and
`grant_revoked`); a grant is revoked once (`duplicate_grant_revocation`). A
judgement may match a use (`governed_by: grant`) and a quarantine entry may
hold a refused one. The readable output counts grants, uses and revocations.

With `--known-anchors` the export is also checked against anchors held
outside the NA: the anchors' signatures, chain and positions
(`anchor_invalid_signature`, `anchor_chain_break`, `anchor_sequence_gap`,
`anchor_not_increasing`); each anchored entry as anchored (`anchor_mismatch`,
`anchor_entry_missing`); and the export tied to the anchors at both ends
(`export_not_linked_to_anchors`, `export_ends_before_anchor`).

### An audit pack

`pack` runs the checks of `audit verify`, in order, with its reason codes:

1. the manifest (`manifest_missing`, `manifest_invalid`,
   `manifest_unknown_file`, `manifest_file_missing`,
   `manifest_digest_mismatch`, `manifest_unlisted_file`); a pack whose
   manifest fails is not checked further;
2. the key history from the root key (`key_history_invalid`,
   `genesis_invalid`, `genesis_root_mismatch`, `genesis_invalid_signature`,
   the succession reasons), then the manifest's signature as received, by the
   key valid at its `created_at` (`manifest_invalid_signature`,
   `na_key_not_valid_at_time`, `unknown_field`, `non_canonical_form`); a
   history that fails stops it;
3. the anchors (the anchor reasons, `pack_end_anchor_mismatch`,
   `pack_end_anchor_not_held`, `pack_start_not_tied`, `manifest_backdated`,
   and the range against the anchors held), then each cited entry against a
   prior pack or a held anchor (`cited_entry_mismatch`, warning
   `cited_entry_unanchored`);
4. the entries (`entries_invalid`, `pack_range_mismatch`,
   `cited_out_of_range`, then every export reason, with the cited records as
   the range's predecessors, the chains a cited retention checkpoint pruned
   continuing from its heads, and `cited_record_missing` for what neither
   holds; 1.6.0: a range's use or revocation whose grant neither holds);
5. what the records rest on outside the store, each checked as received
   (`cited_trust_invalid`, `policy_invalid_signature`,
   `treaty_invalid_signature`, `attestation_invalid_signature`,
   `feed_invalid_signature`, `cited_policy_missing`, `cited_policy_mismatch`,
   `cited_attestation_missing`, `cited_attestation_mismatch`; 1.6.0: a
   grant's policy binding and its basis, an attestation as a decision's, or
   an agreement in the optional `trust/agreements.jsonl`, the one the grant
   names, between its parties and signed by both with keys the pack vouches
   for: `cited_agreement_missing`, `cited_agreement_mismatch`,
   `agreement_invalid_signature`);
6. the report (`report_mismatch`; 1.6.0: with *Grants* and *Grant
   revocations* sections when the pack holds them, a grant use listed as a
   change `governed_by: grant`);
7. with `--period`, the period (`pack_period_not_covered`);
8. with `--changes`, the completeness check (`change_unmatched`; warnings
   `changes_outside_period`, `change_duplicate`). The period runs from the
   start anchor (or the checkpoint the range starts after, or its first
   entry) to the end anchor; repeated (source, event id) pairs are set aside;
   an event-id match must agree on resource and action; the rest are paired
   per resource and action, most pairs and then least total distance first.

The library offers the same as `audit_pack::verify_audit_pack`.

### What it does not prove

- Without anchors held outside the NA, an export proves the integrity of what
  it holds, not that nothing was removed: whoever controls the NA's database
  can rewrite and re-link its history. Keep anchors with
  `genesis-mesh evidence anchors fetch` on storage the NA's operators cannot
  change.
- Keys inside a pack or export prove nothing alone: the NA key, and the
  anchors, come from you.
- The verifier checks what the records say, not that the change they describe
  happened; the completeness check of an audit pack compares them with other
  logs.

## Rebuild and compare

The binaries are reproducible: the same commit, built by
`scripts/build_verifier.sh`, gives the same bytes in any directory. The script
pins the Rust toolchain (`RUST_TOOLCHAIN`), builds with `--locked`, sets
`SOURCE_DATE_EPOCH` to the commit's time, maps the source, Cargo home and
target paths to fixed names (`--remap-path-prefix`), and sets the release
profile (one codegen unit, LTO, symbols stripped). CI builds each binary twice,
in two directories, and fails unless they are identical.

To rebuild a release on Ubuntu 24.04 (x86-64 or arm64), as CI does:

```sh
git clone https://github.com/GenesisMeshLabs/sdk-rust && cd sdk-rust
git checkout v1.5.0
target=x86_64-unknown-linux-musl            # or aarch64-unknown-linux-musl
toolchain="$(sed -n 's/^RUST_TOOLCHAIN=//p' scripts/build_verifier.sh)"
rustup toolchain install "$toolchain" --profile minimal --target "$target"
sudo apt-get install -y musl-tools          # musl-gcc, for C code in the SDK's dependencies
CC_x86_64_unknown_linux_musl=musl-gcc CC_aarch64_unknown_linux_musl=musl-gcc \
  sh scripts/build_verifier.sh "$target" rebuilt
grep "genesis-mesh-verify-1.5.0-$target\$" SHA256SUMS   # from the release, signature checked
cat rebuilt/genesis-mesh-verify-1.5.0-$target.sha256
```

The two digests must be equal. The rebuild also writes a `.buildinfo` file:
the commit, `SOURCE_DATE_EPOCH`, toolchain, C compiler, linker and system that
built it, to compare with the release's.

Only the unsigned binaries are reproducible; the Sigstore bundles record when
and by which workflow run they were signed.

## Reading a mismatch

### A verdict that differs from the reference

Run both on the same inputs, with JSON output:

```sh
genesis-mesh evidence verify-export --file export.jsonl --na-public-key na.pub \
    --executor-keys executor-keys.json --known-anchors anchors/ --format json > python.json
genesis-mesh-verify export export.jsonl --na-key na.pub \
    --executor-keys executor-keys.json --known-anchors anchors/ --json > rust.json
```

Compare `verified`, then the failures' `store_sequence` and `reason`; the
`detail` text may differ. A failure only one of them reports names the entry
and the check: read that entry and the rule its reason code stands for in the
specification. Whichever implementation departs from the specification has
the bug; report it (a verifier that accepts what it should refuse is a
security issue: see `SECURITY.md`). Until it is fixed, treat the entry as not
verified.

### A digest that differs from the release

Compare your `.buildinfo` with the release's: the commit, the toolchain
(`rustc` must be the pinned version), and the target. Then check that you
built from a clean checkout of the tag (no local changes, no
`.cargo/config.toml` of your own, no `RUSTFLAGS` set) on Ubuntu 24.04 with its
`binutils`, which links the binary. If they all agree and the digests still
differ, compare the two binaries (`diffoscope` shows where) and report it: the
build is meant to be reproducible, and the signed binary is then not the one
the source describes.

## The differential harness

`cargo test -p genesis-mesh-verify --test differential` runs the binary on the
reference's vectors (`tests/fixtures`, the `audit` suite's packs, key
histories and exports among them) and compares each verdict and reason code
with the reference's. `GM_VERIFY_CORPUS=<dir>` also runs the core's
verification corpus: the `verification/` directory the core's
`scripts/export_reference_corpus.py --suite verification` writes (169 cases
in 1.5.0: one signed record of every kind, valid and in each way refused,
exports across a key succession, ranges with their cited entries, key
histories, packs, changes files and the time each record is read at), and
checks that
the suites it copies are this crate's fixtures. `GM_VERIFY_BINARY=<path>`
runs a release binary instead of the one cargo built:

```sh
python genesismesh/scripts/export_reference_corpus.py --suite verification --out corpus
GM_VERIFY_BINARY=./genesis-mesh-verify-1.5.0-x86_64-unknown-linux-musl \
GM_VERIFY_CORPUS=corpus/verification GM_VERIFY_CORPUS_STRICT=1 \
  cargo test -p genesis-mesh-verify --test differential
```

CI generates the corpus from the core revision it tests against and runs it
this way.

The vectors are read through a format adapter
(`verifier/tests/adapter/mod.rs`); a vector kind without one is reported as
skipped, and `GM_VERIFY_CORPUS_STRICT=1` fails the run on a skip.
