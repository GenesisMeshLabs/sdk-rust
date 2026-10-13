"""Generate tests/fixtures/anchors.json with the Python reference (1.5.0).

    python scripts/generate_anchor_vectors.py   # with the genesismesh core installed

Store anchors over the export in tests/fixtures/python-vectors.json, signed
with the public test seed ``bytes(range(32))`` (a test vector, never an
operator credential), and what the reference answers for each case:
``verify_store_anchors`` for a run of anchors, and the whole
``genesis-mesh evidence verify-export --known-anchors ... --format json``
output for an export checked against them. Deterministic: run it again and
the file is unchanged. The core's verification corpus
(``scripts/export_reference_corpus.py --suite verification``) supersedes it
once it covers anchors.
"""

from __future__ import annotations

import base64
import json
import tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path

import nacl.signing
from click.testing import CliRunner

from genesis_mesh.cli.evidence_store_ops import evidence
from genesis_mesh.models.evidence_store import StoreAnchor
from genesis_mesh.trust.evidence_store import sign_store_anchor, verify_store_anchors

ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ROOT / "tests" / "fixtures"
SOURCE = json.loads((FIXTURES / "python-vectors.json").read_text(encoding="utf-8"))
KEY = nacl.signing.SigningKey(bytes(range(32)))
OTHER = nacl.signing.SigningKey(bytes(range(1, 33)))
SOVEREIGN = "vectors"
START = datetime(2026, 10, 1, 10, 0, tzinfo=timezone.utc)

ANCHOR_PUBLIC_KEY = base64.b64encode(KEY.verify_key.encode()).decode()
LINES = [line for line in SOURCE["export"].split("\n") if line.strip()]
DIGESTS = {json.loads(line)["entry"]["store_sequence"]: json.loads(line)["entry_digest"] for line in LINES}


def anchors(positions: list[int], *, key=KEY, sovereign=SOVEREIGN, digests=None) -> list[dict]:
    """A chain of signed anchors naming the export's entries at these positions."""
    out: list[StoreAnchor] = []
    for n, seq in enumerate(positions, start=1):
        anchor = StoreAnchor(
            anchor_sequence=n,
            sovereign_id=sovereign,
            store_sequence=seq,
            entry_digest=(digests or DIGESTS).get(seq, "0" * 64),
            anchored_at=START + timedelta(minutes=n),
            previous_anchor_digest=out[-1].digest() if out else None,
            issued_by="anchor-key",
        )
        out.append(sign_store_anchor(anchor, key, "anchor-key"))
    return [a.to_wire() for a in out]


def resign(raw: dict, key=KEY) -> dict:
    anchor = StoreAnchor.model_validate({k: v for k, v in raw.items() if k != "signature"})
    return sign_store_anchor(anchor, key, "anchor-key").to_wire()


def run_cli(lines: list[str], held: list[dict], *flags: str) -> dict:
    """The reference CLI's JSON output and exit code."""
    with tempfile.TemporaryDirectory() as tmp:
        export = Path(tmp) / "export.jsonl"
        export.write_text("\n".join(lines) + "\n", encoding="utf-8")
        keys = Path(tmp) / "executor-keys.json"
        keys.write_text(json.dumps(SOURCE["executor_keys"]), encoding="utf-8")
        held_file = Path(tmp) / "anchors.json"
        held_file.write_text(json.dumps(held), encoding="utf-8")
        args = [
            "verify-export", "--file", str(export),
            "--na-public-key", SOURCE["na_public_key"], "--na-public-key", ANCHOR_PUBLIC_KEY,
            "--executor-keys", str(keys), "--known-anchors", str(held_file), "--format", "json", *flags,
        ]
        result = CliRunner().invoke(evidence, args)
    if result.exit_code not in (0, 1) or not result.output.startswith("{"):
        return {"exit_code": result.exit_code, "error": True}
    return {"exit_code": result.exit_code, "output": json.loads(result.output)}


def chain_case(case_id: str, description: str, held: list[dict], sovereign: str | None = None) -> dict:
    parsed = [StoreAnchor.model_validate(a) for a in held]
    result = verify_store_anchors(parsed, na_public_keys=[ANCHOR_PUBLIC_KEY], sovereign_id=sovereign)
    return {
        "id": case_id, "kind": "verify_anchors", "description": description,
        "input": {"anchors": held, "na_public_keys": [ANCHOR_PUBLIC_KEY], "sovereign_id": sovereign},
        "expected": {**result.to_dict(), "digests": [a.digest() for a in parsed]},
    }


def export_case(case_id: str, description: str, positions: list[int], held: list[dict], *flags: str) -> dict:
    lines = [line for line in LINES if json.loads(line)["entry"]["store_sequence"] in positions]
    return {
        "id": case_id, "kind": "verify_export_anchors", "description": description,
        "input": {
            "lines": "\n".join(lines) + "\n",
            "anchors": held,
            "na_public_keys": [SOURCE["na_public_key"], ANCHOR_PUBLIC_KEY],
            "executor_keys": SOURCE["executor_keys"],
            "partial": "--partial" in flags,
            "from_anchor": "--from-anchor" in flags,
        },
        "expected": run_cli(lines, held, *flags),
    }


def main() -> None:
    every = sorted(DIGESTS)
    good = anchors([3, 5, 8])
    gap = [good[0], good[2]]
    broken = [good[0], resign({**good[1], "previous_anchor_digest": "1" * 64}), good[2]]
    backwards = anchors([5, 3])
    late_first = [resign({**good[0], "previous_anchor_digest": "1" * 64})]
    offset = [{**good[0], "anchored_at": good[0]["anchored_at"].replace("Z", "+00:00")}]
    wrong_digest = anchors([3, 5, 8], digests={**DIGESTS, 5: "2" * 64})
    vectors = [
        chain_case("chain-valid", "Three chained anchors", good, SOVEREIGN),
        chain_case("chain-recent-only", "A run that starts after anchor 1", good[1:]),
        chain_case("chain-gap", "A missing anchor position", gap),
        chain_case("chain-break", "An anchor naming another previous digest", broken),
        chain_case("chain-not-increasing", "Store positions going backwards", backwards),
        chain_case("chain-first-names-previous", "Anchor 1 naming a previous anchor", late_first),
        chain_case("chain-other-key", "An anchor signed by another key", anchors([3], key=OTHER)),
        chain_case("chain-other-sovereign", "Anchors of another sovereign", anchors([3], sovereign="other"),
                   SOVEREIGN),
        chain_case("chain-offset-timestamp", "anchored_at written with +00:00 verifies", offset),
        chain_case("chain-tampered", "A changed store position", [{**good[0], "store_sequence": 4}]),
        export_case("export-anchored", "The whole export, anchored at three entries", every, good),
        export_case("export-wrong-digest", "An anchor naming another digest", every, wrong_digest),
        export_case("export-ends-before-anchor", "An export that stops before an anchor", every[:6], good),
        export_case("export-ends-partial", "A deliberate slice", every[:6], good, "--partial"),
        export_case("export-not-linked", "An export starting after an anchor", every[3:], good),
        export_case("export-from-anchor", "An export since a held anchor", every[3:], good, "--from-anchor"),
        export_case("export-missing-entry", "An anchored entry removed", [s for s in every if s != 5], good),
        export_case("export-bad-anchor-chain", "Held anchors with a gap", every, gap),
    ]
    out = {
        "suite": "anchors",
        "version": "1.5.0",
        "generated_by": "scripts/generate_anchor_vectors.py with the genesismesh core",
        "anchor_public_key": ANCHOR_PUBLIC_KEY,
        "vectors": vectors,
    }
    (FIXTURES / "anchors.json").write_text(json.dumps(out, indent=1, ensure_ascii=False) + "\n", encoding="utf-8")
    print(f"{len(vectors)} vectors")


if __name__ == "__main__":
    main()
