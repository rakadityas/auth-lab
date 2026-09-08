#!/usr/bin/env bash
# Email OTP login, end to end, reading the real code out of Mailpit.
# Requires: curl, jq.  App must be running in the default (safe) mode.
set -euo pipefail
BASE="${BASE:-http://localhost:8080}"
MAILPIT="${MAILPIT:-http://localhost:8025}"
hr() { printf '\n\033[1;36m── %s\033[0m\n' "$*"; }

EMAIL="otp-$RANDOM@example.com"

hr "1. Ask for a code (no password anywhere in this flow)"
START=$(curl -fsS -X POST "$BASE/otp/start" -d "{\"identifier\":\"$EMAIL\",\"channel\":\"email\"}")
echo "$START" | jq .
REQ=$(jq -r .request_id <<<"$START")
echo "Note what came back: a request_id, a TTL, a resend cooloff — and NOTHING"
echo "about whether $EMAIL has an account. Same response either way."

hr "2. Read the code out of the inbox (Mailpit — open $MAILPIT to see it)"
sleep 1
MSG_ID=$(curl -fsS "$MAILPIT/api/v1/search?query=to:$EMAIL" | jq -r '.messages[0].ID')
BODY=$(curl -fsS "$MAILPIT/api/v1/message/$MSG_ID" | jq -r .Text)
CODE=$(grep -oE '[0-9]{4,8}' <<<"$BODY" | head -1)
echo "delivered code: $CODE"

hr "3. Wrong code first — see the attempt budget shrink"
curl -sS -X POST "$BASE/otp/verify" -d "{\"request_id\":\"$REQ\",\"code\":\"000000\"}" | jq .

hr "4. Right code -> a session"
OK=$(curl -sS -X POST "$BASE/otp/verify" -d "{\"request_id\":\"$REQ\",\"code\":\"$CODE\"}")
echo "$OK" | jq .
SESS=$(jq -r .session <<<"$OK")
curl -fsS "$BASE/me" -H "Authorization: Bearer $SESS" | jq .

hr "5. Replay the SAME code -> dead"
curl -sS -X POST "$BASE/otp/verify" -d "{\"request_id\":\"$REQ\",\"code\":\"$CODE\"}" | jq .
echo "Single use. A code read over someone's shoulder, or sitting in a forwarded"
echo "email, is worthless the moment it has been spent once."
