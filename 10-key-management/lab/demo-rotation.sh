#!/usr/bin/env bash
# Zero-downtime signing-key rotation: a token signed by the OLD key keeps
# verifying after rotation, because both keys are published in JWKS.
# Requires: curl, jq. Service running.
set -euo pipefail
BASE="${BASE:-http://localhost:8080}"
hr() { printf '\n\033[1;36m── %s\033[0m\n' "$*"; }

hr "1. Keys at start — one current signing key"
curl -sS "$BASE/keys" | jq -c '.[]'

hr "2. Issue a token (signed by the current key)"
T1=$(curl -sS -X POST "$BASE/token" -d '{"sub":"alice"}' | jq -r .token)
KID1=$(echo "$T1" | cut -d. -f1 | base64 -d 2>/dev/null | jq -r .kid || true)
echo "token #1 kid: $KID1"
echo "verifies now:"; curl -sS -X POST "$BASE/verify" -d "{\"token\":\"$T1\"}" | jq '{valid,kid}'

hr "3. ROTATE the signing key (new current; old one RETIRED, not removed)"
curl -sS -X POST "$BASE/keys/rotate" | jq .
curl -sS "$BASE/keys" | jq -c '.[]'

hr "4. The OLD token (#1) STILL verifies — zero downtime"
curl -sS -X POST "$BASE/verify" -d "{\"token\":\"$T1\"}" | jq '{valid,kid}'
echo "   -> it verifies against the retired key, which is still in JWKS."

hr "5. A NEW token is signed by the NEW key"
T2=$(curl -sS -X POST "$BASE/token" -d '{"sub":"alice"}' | jq -r .token)
curl -sS -X POST "$BASE/verify" -d "{\"token\":\"$T2\"}" | jq '{valid,kid}'

hr "6. JWKS currently publishes BOTH keys (verifiers need both during overlap)"
curl -sS "$BASE/.well-known/jwks.json" | jq '.keys[] | {kid,alg}'

hr "7. After all #1-era tokens EXPIRE, remove the retired key"
RETIRED=$(curl -sS "$BASE/keys" | jq -r '.[] | select(.retired==true) | .kid')
curl -sS -X POST "$BASE/keys/remove" -d "{\"kid\":\"$RETIRED\"}" | jq .
echo "now token #1 no longer verifies (its key is gone) — but by policy every"
echo "token it signed has already expired, so nothing legitimate breaks:"
curl -sS -X POST "$BASE/verify" -d "{\"token\":\"$T1\"}" | jq '{valid,error}'
