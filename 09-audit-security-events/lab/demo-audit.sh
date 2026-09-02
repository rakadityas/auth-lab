#!/usr/bin/env bash
# Security events + a tamper-evident audit log. Notifications land in Mailpit
# (http://localhost:8025). Requires: curl, jq. Service running.
set -euo pipefail
BASE="${BASE:-http://localhost:8080}"
hr() { printf '\n\033[1;36m── %s\033[0m\n' "$*"; }

hr "1. alice logs in from a NEW device -> security notification fires"
curl -sS -X POST "$BASE/login" -d '{"user":"alice","device":"laptop-1"}' | jq .
echo "   -> check Mailpit: 'New sign-in to your account'"

hr "2. Same device again -> known, no notification"
curl -sS -X POST "$BASE/login" -d '{"user":"alice","device":"laptop-1"}' | jq '{result,new_device}'

hr "3. A DIFFERENT device -> new-device alert again"
curl -sS -X POST "$BASE/login" -H 'X-Forwarded-For: 66.66.66.66' -d '{"user":"alice","device":"unknown-phone"}' | jq '{result,new_device}'

hr "4. Password change + MFA disabled -> loud notifications + CAEP signals"
curl -sS -X POST "$BASE/password/change" -H 'X-Forwarded-For: 66.66.66.66' -d '{"user":"alice"}' | jq .
curl -sS -X POST "$BASE/mfa/disable"     -H 'X-Forwarded-For: 66.66.66.66' -d '{"user":"alice"}' | jq .

hr "5. alice's session inventory (where is she logged in?)"
curl -sS "$BASE/sessions?user=alice" | jq -c '.[]'

hr "6. The audit log (append-only, who/what/where)"
curl -sS "$BASE/audit" | jq -c '.[] | {seq,actor,action,target,ip}'

hr "7. VERIFY the hash chain -> valid"
curl -sS "$BASE/audit/verify" | jq .

hr "8. TAMPER: an insider edits a past audit row directly in the DB"
curl -sS -X POST "$BASE/audit/tamper" -d '{"seq":3,"new_detail":"nothing to see here"}' | jq .

hr "9. VERIFY again -> the chain now BREAKS, and points at the tampered row"
curl -sS "$BASE/audit/verify" | jq .

hr "10. CAEP shared-signal feed (what downstream systems would react to)"
curl -sS "$BASE/caep/feed" | jq '.events'
