#!/usr/bin/env bash
# The account-linking account-takeover (ATO) demo — the module's security core.
#
# Setup: a victim has a normal local (password) account. An attacker controls a
# Google account whose profile email they set to the victim's address. In
# LINK_MODE=unsafe the service auto-links by email match and hands the attacker
# the victim's account. In LINK_MODE=safe the same request is refused.
#
# Requires: curl, jq. Service running. Toggle LINK_MODE in compose.yaml and
# `podman compose up -d --build app` to switch modes between runs.
set -euo pipefail
BASE="${BASE:-http://localhost:8080}"
hr() { printf '\n\033[1;33m── %s\033[0m\n' "$*"; }

MODE=$(curl -fsS "$BASE/healthz" >/dev/null; echo)  # noop reachability check
VICTIM="victim-$RANDOM@corp.com"
PW="victims real password"

hr "Victim creates a normal local account and verifies it"
curl -fsS -X POST "$BASE/signup" -d "{\"email\":\"$VICTIM\",\"password\":\"$PW\"}" >/dev/null
sleep 1
TOK=$(curl -fsS "http://localhost:8025/api/v1/messages?limit=20" \
  | jq -r '.messages[] | select(.Subject|test("Verify")) | .ID' | head -1 \
  | xargs -I{} curl -fsS "http://localhost:8025/api/v1/message/{}" \
  | jq -r '.Text' | grep -oE 'token=[A-Za-z0-9_-]+' | head -1 | cut -d= -f2)
curl -fsS "$BASE/verify-email?token=$TOK" >/dev/null
echo "victim account ready: $VICTIM"

hr "Attacker mints a Google assertion: sub=g-ATTACKER-*, email=<the victim's>"
echo "In a real attack the attacker sets this email on THEIR google account."
# Fresh subject each run: (provider,sub) is unique, so a reused sub from a prior
# run would just match case 1 (already linked) and hide the point.
SUB="g-ATTACKER-$RANDOM"
ASSERT=$(curl -fsS "$BASE/fake-idp/authorize?sub=$SUB&email=$VICTIM&email_verified=true" | jq -r .assertion)

hr "Attacker clicks 'Sign in with Google' — no password, just the assertion"
RESP=$(curl -sS -i -X POST "$BASE/login/google" -d "{\"assertion\":\"$ASSERT\"}")
echo "$RESP" | grep -iE '^HTTP|"path"|"status"|"error"' || echo "$RESP"

hr "What just happened"
cat <<'EOF'
LINK_MODE=unsafe -> response path was "AUTO-LINKED-BY-EMAIL (this is the vuln)"
   and Set-Cookie handed the attacker a session on the VICTIM's account. Game over:
   the attacker never knew the password.

LINK_MODE=safe   -> 409, refused: "log in with your password, then link from
   settings". The email claim alone can never prove control of a local account.

The root cause: (provider, sub) is the only safe join key for federated login.
Joining on email trusts the IdP's email claim, which the attacker controls.
EOF
