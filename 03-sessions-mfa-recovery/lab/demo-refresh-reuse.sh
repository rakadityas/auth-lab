#!/usr/bin/env bash
# Demonstrates refresh token rotation and the reuse-detection kill switch.
# Requires: curl, jq. Service must be running (podman compose up).
set -euo pipefail
BASE="${BASE:-http://localhost:8080}"
hr() { printf '\n\033[1;36m── %s\033[0m\n' "$*"; }

EMAIL="rot-$RANDOM@example.com"
curl -fsS -X POST "$BASE/signup" -d "{\"email\":\"$EMAIL\",\"password\":\"correct horse battery staple\"}" >/dev/null

hr "Log in — receive access + refresh token"
LOGIN=$(curl -fsS -X POST "$BASE/login" -d "{\"email\":\"$EMAIL\",\"password\":\"correct horse battery staple\"}")
RT1=$(jq -r .refresh_token <<<"$LOGIN")
echo "refresh token #1: ${RT1:0:24}…"

hr "Refresh once — token rotates, #1 is now spent"
R2=$(curl -fsS -X POST "$BASE/token/refresh" -d "{\"refresh_token\":\"$RT1\"}")
RT2=$(jq -r .refresh_token <<<"$R2")
echo "refresh token #2: ${RT2:0:24}…"
echo "note #2 != #1 — that is rotation. A stolen #1 is now useless… unless it is replayed:"

hr "ATTACK: replay the already-used refresh token #1"
echo "This is what happens when an attacker stole #1 and the legit client already rotated it:"
curl -sS -X POST "$BASE/token/refresh" -d "{\"refresh_token\":\"$RT1\"}" | jq .

hr "Consequence: the WHOLE family is now revoked. Even the legit #2 is dead:"
curl -sS -X POST "$BASE/token/refresh" -d "{\"refresh_token\":\"$RT2\"}" | jq .

hr "Interpretation"
cat <<'EOF'
Reuse of a rotated token means two parties hold the same secret -> theft.
The server cannot tell the thief from the victim, so it revokes everything and
forces a fresh login. A forced re-login is a far better outcome than letting an
attacker silently mint access tokens forever. This is the core defense the
Module 3 ADR must account for.
EOF
