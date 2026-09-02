#!/usr/bin/env bash
# Enroll TOTP MFA and complete a two-step login. Requires: curl, jq, oathtool.
#   macOS:  brew install oath-toolkit
set -euo pipefail
BASE="${BASE:-http://localhost:8080}"
hr() { printf '\n\033[1;36m── %s\033[0m\n' "$*"; }
if ! command -v oathtool >/dev/null; then echo "install oathtool (brew install oath-toolkit)"; exit 1; fi

EMAIL="mfa-$RANDOM@example.com"
PASS="correct horse battery staple"
curl -fsS -X POST "$BASE/signup" -d "{\"email\":\"$EMAIL\",\"password\":\"$PASS\"}" >/dev/null

hr "Log in with password only (MFA not yet enabled) -> full tokens"
AT=$(curl -fsS -X POST "$BASE/login" -d "{\"email\":\"$EMAIL\",\"password\":\"$PASS\"}" | jq -r .access_token)
echo "access token: ${AT:0:24}…"

hr "Enroll TOTP"
ENROLL=$(curl -fsS -X POST "$BASE/mfa/enroll" -H "Authorization: Bearer $AT")
SECRET=$(jq -r .secret <<<"$ENROLL")
echo "otpauth URL (this is what a QR code encodes):"
jq -r .otpauth_url <<<"$ENROLL"
echo "shared secret: $SECRET"

hr "Activate with the current code (proves the secret transferred)"
CODE=$(oathtool --totp -b "$SECRET")
echo "current TOTP: $CODE"
ACT=$(curl -fsS -X POST "$BASE/mfa/activate" -H "Authorization: Bearer $AT" -d "{\"code\":\"$CODE\"}")
echo "recovery codes issued (shown once):"
jq -r '.recovery_codes[]' <<<"$ACT"

hr "Now log in again — password alone is no longer enough"
STEP1=$(curl -fsS -X POST "$BASE/login" -d "{\"email\":\"$EMAIL\",\"password\":\"$PASS\"}")
echo "$STEP1" | jq .
TICKET=$(jq -r .mfa_ticket <<<"$STEP1")

hr "Complete the second factor with the MFA ticket + a fresh code"
sleep 1
CODE2=$(oathtool --totp -b "$SECRET")
curl -fsS -X POST "$BASE/login/mfa" -d "{\"ticket\":\"$TICKET\",\"code\":\"$CODE2\"}" | jq '{token_type, expires_in, has_refresh: (.refresh_token != null)}'

hr "Replay guard: reuse the same code immediately -> rejected"
STEP1B=$(curl -fsS -X POST "$BASE/login" -d "{\"email\":\"$EMAIL\",\"password\":\"$PASS\"}")
TICKET2=$(jq -r .mfa_ticket <<<"$STEP1B")
curl -sS -X POST "$BASE/login/mfa" -d "{\"ticket\":\"$TICKET2\",\"code\":\"$CODE2\"}" | jq .
echo "The code was already burned. A phished/sniffed code cannot be reused."
