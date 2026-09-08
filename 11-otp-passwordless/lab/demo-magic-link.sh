#!/usr/bin/env bash
# Magic-link login: same primitive as an OTP with the guessing surface removed,
# and the two failure modes that replaces it with.
set -euo pipefail
BASE="${BASE:-http://localhost:8080}"
MAILPIT="${MAILPIT:-http://localhost:8025}"
JAR=$(mktemp)
hr() { printf '\n\033[1;36m── %s\033[0m\n' "$*"; }
trap 'rm -f "$JAR"' EXIT

EMAIL="magic-$RANDOM@example.com"

hr "1. Request a link (cookie jar = the browser that asked)"
curl -fsS -c "$JAR" -X POST "$BASE/magic/start" -d "{\"identifier\":\"$EMAIL\"}" | jq .
echo "same-browser nonce dropped in a cookie:"
grep magic_nonce "$JAR" | awk '{print "  " $NF}'

hr "2. Pull the link out of the inbox"
sleep 1
MSG_ID=$(curl -fsS "$MAILPIT/api/v1/search?query=to:$EMAIL" | jq -r '.messages[0].ID')
URL=$(curl -fsS "$MAILPIT/api/v1/message/$MSG_ID" | jq -r .Text | tr -d '\r' | grep -oE 'http://[^ ]+' | head -1)
echo "$URL"

hr "3. Someone ELSE clicks it (forwarded mail, or a link scanner) — no cookie"
curl -sS "$URL" | jq .
echo "Rejected. The token alone is not enough; it is bound to the device that asked."

hr "4. The original browser clicks it -> signed in"
OK=$(curl -sS -b "$JAR" "$URL")
echo "$OK" | jq .
SESS=$(jq -r .session <<<"$OK")
curl -fsS "$BASE/me" -H "Authorization: Bearer $SESS" | jq .

hr "5. Click it again -> gone"
curl -sS -b "$JAR" "$URL" | jq .
echo "Consumed by an atomic DEL: whichever request deletes the key is the single"
echo "winner, so a scanner prefetching the URL cannot race the human to it."
