#!/usr/bin/env bash
# Records the session behind docs/assets/edge-agent/edge-agent.gif
# (docs/examples/edge-agent.md): a local NA, an edge agent enrolled with a
# bound invite, a decision, the NA stopped (a grant, then break-glass), the
# NA back and the uploads drained. Linux; prints the session on stdout.
#
#   BIN=<dir> bash docs/assets/edge-agent/record.sh > session.raw.txt
#
# BIN holds `genesis-mesh-edge` and the `edge_site` example
# (cargo build --release -p genesis-mesh-edge; cargo build --example edge_site),
# and `genesis-mesh` (core 1.7) is on PATH. Needs curl and jq. The NA
# listens on PORT (default 18444) and is stopped at the end.
#
# Then mark the colours (a prefix per line; the text stays as recorded) and
# render the GIF (Python with Pillow):
#
#   sed -E -f docs/assets/edge-agent/style.sed session.raw.txt > docs/assets/edge-agent/session.txt
#   python docs/assets/render_terminal_gif.py docs/assets/edge-agent/session.txt \
#       docs/assets/edge-agent/edge-agent.gif --title "Genesis Mesh -- The Edge Agent, Online and Offline"
set -euo pipefail

PORT="${PORT:-18444}"
export PATH="$BIN:$PATH"
WORK="$(mktemp -d /tmp/gm-edge-walk.XXXXXX)"
cd "$WORK"
NA_PID=
AGENT_PID=
cleanup() {
    [ -n "$AGENT_PID" ] && kill "$AGENT_PID" 2>/dev/null || true
    [ -n "$NA_PID" ] && kill "$NA_PID" 2>/dev/null || true
    wait 2>/dev/null || true
}
trap cleanup EXIT

step() { echo "==> $*"; }
# Print a command as typed, then run it in this shell.
run() {
    echo "\$ $1"
    eval "$1"
}

# --- Setup, not shown: a local NA as docs/sdk/local-network-authority.md
# describes it, with the records of changes outside the controlled path and
# grants turned on.
genesis-mesh init --config local/genesis-mesh.toml --home local/.genesis-mesh \
    --network-name EDGE-WALKTHROUGH --na-endpoint "http://127.0.0.1:$PORT" \
    --na-port "$PORT" --env-file local/na.env >/dev/null 2>&1
printf 'EVIDENCE_OUT_OF_BAND=on\nEVIDENCE_GRANTS=on\n' >> local/na.env
start_na() {
    genesis-mesh na start --env-file local/na.env >>na.log 2>&1 &
    NA_PID=$!
    until curl -sf "http://127.0.0.1:$PORT/healthz" >/dev/null; do sleep 0.5; done
}
start_na
export NA_URL="http://127.0.0.1:$PORT"
OPERATOR_KEY="$(grep -v '^#' local/.genesis-mesh/keys/operator.key | tr -d '[:space:]')"
export OPERATOR_KEY
ROOT_KEY="$(jq -r .root_public_key local/.genesis-mesh/genesis.json)"
cat > edge.toml <<EOF
[authority]
url = "http://127.0.0.1:$PORT"
root_public_key = "$ROOT_KEY"

[node]
state_dir = "$WORK/state"
heartbeat_interval_seconds = 5

[snapshot]
retry_interval_seconds = 5

[local_api]
listen = "unix:$WORK/agent.sock"
allowed_uids = [$(id -u)]
EOF
export GM_EDGE_CONFIG="$WORK/edge.toml"
SOCK="$WORK/agent.sock"
# Ask the agent, and report a success when it allows.
ask() {
    local answer id
    answer="$(curl -s --unix-socket "$SOCK" -X POST http://agent/v1/authorize -d "$1")"
    echo "$answer" | jq -c '{allowed, authority, code}'
    if [ "$(echo "$answer" | jq -r .allowed)" = true ]; then
        id="$(echo "$answer" | jq -r .authorization_id)"
        curl -s --unix-socket "$SOCK" -X POST "http://agent/v1/authorizations/$id/outcome" \
            -d '{"outcome": "success"}' | jq -c '{record_kind, queued}'
    fi
}
status() { curl -s --unix-socket "$SOCK" http://agent/v1/status; }

# --- The session.
step "1. On the device: create the node and executor keys"
run 'genesis-mesh-edge init'
step "2. The operator: an edge invite bound to that node key"
run 'genesis-mesh admin invite --config local/genesis-mesh.toml --role client --node-sovereign-id site7-17 --executor-resource-prefix edge:site7-17/ --recipient-key "$(genesis-mesh-edge init)" > invite-token'
step "3. On the device: enrol"
run 'genesis-mesh-edge enroll --invite-token-file invite-token 2>enroll.log; echo "exit $?"'
run 'genesis-mesh-edge status --json | jq -c "{enrolled, node_sovereign_id, executor_key_id, resource_prefix}"'
step "4. The operator: an attestation, then a grant to the executor key"
run 'ATT=$(edge_site attest site7-17 secret.rotate secret.revoke)'
run 'KEY=$(genesis-mesh-edge status --json | jq -r .executor_key_id)'
run 'edge_site grant "$KEY" "$ATT" secret.rotate'
step "5. Run the agent; the NA decides"
run 'genesis-mesh-edge run 2>agent.log &'
AGENT_PID=$!
until [ "$(status 2>/dev/null | jq -r '.grants | length' 2>/dev/null)" = 1 ]; do sleep 0.5; done
ROTATE='{"capability": "secret.rotate", "request_parameters": {"lifetime_days": 30}, "resource_id": "edge:site7-17/kv/db", "resource_action": "rotate"}'
REVOKE='{"capability": "secret.revoke", "resource_id": "edge:site7-17/kv/old", "resource_action": "revoke"}'
GLASS='{"capability": "secret.revoke", "resource_id": "edge:site7-17/kv/old", "resource_action": "revoke", "justification": "incident 42: the old key leaked"}'
run 'ask "$ROTATE"'
step "6. The NA stops: the grant, then break-glass"
run 'kill $NA_PID'
wait "$NA_PID" 2>/dev/null || true
run 'ask "$ROTATE"'
run 'ask "$REVOKE"'
run 'ask "$GLASS"'
run 'status | jq -c "{na_state, pending_uploads}"'
step "7. The NA is back: the records upload in order"
run 'genesis-mesh na start --env-file local/na.env >>na.log 2>&1 &'
NA_PID=$!
run 'until [ "$(status | jq .pending_uploads)" = 0 ]; do sleep 1; done'
run 'status | jq -c "{connected, na_state, pending_uploads, dead_letters}"'
