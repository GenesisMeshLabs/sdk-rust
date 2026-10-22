#!/usr/bin/env bash
# Records the session behind docs/assets/verifier/verifier.gif
# (docs/examples/verify-audit-pack.md): genesis-mesh-verify on the frozen
# 1.5.0 audit pack, the same pack with one byte changed, and the Python
# reference (`genesis-mesh audit verify`) on the changed pack. Prints the
# session on stdout.
#
#   BIN=<dir> bash docs/assets/verifier/record.sh > session.raw.txt
#
# BIN holds `genesis-mesh-verify` (scripts/build_verifier.sh, or
# cargo build --release -p genesis-mesh-verify), and `genesis-mesh`
# (core 1.5 or later) is on PATH. Run it from the repository's root.
#
# Then mark the colours (a prefix per line; the text stays as recorded) and
# render the GIF (Python with Pillow):
#
#   sed -E -f docs/assets/verifier/style.sed session.raw.txt > docs/assets/verifier/session.txt
#   python docs/assets/render_terminal_gif.py docs/assets/verifier/session.txt \
#       docs/assets/verifier/verifier.gif --title "Genesis Mesh -- Verifying an Audit Pack Offline"
set -euo pipefail

export PATH="$BIN:$PATH"
WORK="$(mktemp -d /tmp/gm-verify-walk.XXXXXX)"
cp -r tests/fixtures/audit-pack-1.5.0/. "$WORK"
cd "$WORK"

step() { echo "==> $*"; }
# Print a command as typed, then run it in this shell.
run() {
    echo "\$ $1"
    eval "$1" || true
}

step "1. The pack, the root key and the anchors the auditor holds"
run 'ls pack'
step "2. Verify it offline"
run 'genesis-mesh-verify pack pack --anchor root.pub --known-anchors anchors.json; echo "exit $?"'
step "3. Change one byte of one entry, and verify again"
run "sed -i '3s/\"exec_sequence_no\":1/\"exec_sequence_no\":2/' pack/entries.jsonl"
run 'genesis-mesh-verify pack pack --anchor root.pub --known-anchors anchors.json --json | jq -c ".verified, .failures[]"; echo "exit ${PIPESTATUS[0]}"'
step "4. The Python reference on the same pack"
run 'genesis-mesh audit verify pack --anchor root.pub --known-anchors anchors.json --format json | jq -c ".verified, .failures[]"; echo "exit ${PIPESTATUS[0]}"'
