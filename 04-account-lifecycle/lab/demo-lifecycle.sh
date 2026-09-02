#!/usr/bin/env bash
# Walks a full account life: signup -> verify -> login -> change email ->
# deactivate/reactivate -> soft-delete -> purge (GDPR erasure).
# Magic links are printed here AND visible in Mailpit at http://localhost:8025.
# Requires: curl, jq. Service must be running (podman compose up).
set -euo pipefail
BASE="${BASE:-http://localhost:8080}"
JAR=$(mktemp)
hr() { printf '\n\033[1;36m── %s\033[0m\n' "$*"; }

# Pull the token out of the magic link the API logs. In a real app the user
# clicks it from their inbox; here we scrape Mailpit's API to stay scriptable.
latest_token() { # $1 = purpose substring to match in the subject
  curl -fsS "http://localhost:8025/api/v1/messages?limit=20" \
    | jq -r --arg p "$1" '.messages[] | select(.Subject|test($p)) | .ID' | head -1 \
    | xargs -I{} curl -fsS "http://localhost:8025/api/v1/message/{}" \
    | jq -r '.Text' | grep -oE 'token=[A-Za-z0-9_-]+' | head -1 | cut -d= -f2
}

EMAIL="life-$RANDOM@example.com"
PW="correct horse battery staple"

hr "1. Sign up (status = pending_verification)"
curl -fsS -X POST "$BASE/signup" -d "{\"email\":\"$EMAIL\",\"password\":\"$PW\"}" | jq .

hr "2. Login before verifying -> refused"
curl -sS -X POST "$BASE/login" -d "{\"email\":\"$EMAIL\",\"password\":\"$PW\"}" | jq .

hr "3. Click the verification magic link (from Mailpit)"
sleep 1
TOK=$(latest_token "Verify")
curl -fsS "$BASE/verify-email?token=$TOK" | jq .

hr "4. Now login works — keep the session cookie"
curl -fsS -c "$JAR" -X POST "$BASE/login" -d "{\"email\":\"$EMAIL\",\"password\":\"$PW\"}" | jq .
curl -fsS -b "$JAR" "$BASE/me" | jq '{email,status,email_verified}'

hr "5. Change email — requires password (step-up), confirmed at NEW address"
NEW="new-$RANDOM@example.com"
curl -fsS -b "$JAR" -X POST "$BASE/email/change" \
  -d "{\"new_email\":\"$NEW\",\"password\":\"$PW\"}" | jq .
sleep 1
TOK=$(latest_token "Confirm your new email")
curl -fsS "$BASE/email/confirm?token=$TOK" | jq .
echo "-> the OLD address just got a 'your email was changed' warning (check Mailpit)"
curl -fsS -b "$JAR" "$BASE/me" | jq '{email,status}'

hr "6. Deactivate (reversible) then log back in to reactivate"
curl -fsS -b "$JAR" -X POST "$BASE/deactivate" | jq .
echo "old session is now dead:"; curl -sS -b "$JAR" "$BASE/me" | jq .
curl -fsS -c "$JAR" -X POST "$BASE/login" -d "{\"email\":\"$NEW\",\"password\":\"$PW\"}" | jq .
curl -fsS -b "$JAR" "$BASE/me" | jq '{status}'

hr "7. GDPR data export (right of access)"
curl -fsS -b "$JAR" "$BASE/export" | jq '{user:.user.email, identities:(.identities|length), events:(.audit_log|length)}'

hr "8. Soft-delete (password step-up) -> status soft_deleted, sessions revoked"
curl -fsS -b "$JAR" -X POST "$BASE/delete" -d "{\"password\":\"$PW\"}" | jq .

hr "9. Purge job runs (retention=0 days) -> PII erased, tombstone kept"
curl -fsS -X POST "$BASE/admin/purge?days=0" | jq .
echo "-> the users row still exists (foreign keys stay valid) but email is NULL and status=purged"

rm -f "$JAR"
