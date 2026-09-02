#!/usr/bin/env bash
# Adaptive auth: the SAME credentials get allow / step-up / deny depending on
# the risk context, and a credential-stuffing burst gets shut down.
# Requires: curl, jq. Service running.
set -euo pipefail
BASE="${BASE:-http://localhost:8080}"
hr() { printf '\n\033[1;36m── %s\033[0m\n' "$*"; }
login() { curl -sS -X POST "$BASE/login" "$@"; }

curl -sS -X POST "$BASE/admin/reset" >/dev/null

hr "1. Returning user, known device, home country -> ALLOW (no friction)"
# First, establish a trusted device by logging in once (low risk to start).
login -H "X-Device: alices-laptop" -H "X-Geo: US" -H "X-Forwarded-For: 1.1.1.1" \
      -d '{"email":"alice@corp.com","password":"hunter2"}' | jq '{result, outcome:.risk.outcome, score:.risk.score}'
echo "   (that first login learned alices-laptop + US as trusted)"
login -H "X-Device: alices-laptop" -H "X-Geo: US" -H "X-Forwarded-For: 1.1.1.1" \
      -d '{"email":"alice@corp.com","password":"hunter2"}' | jq '{result, outcome:.risk.outcome, score:.risk.score}'

hr "2. Same user + password, but NEW device from a NEW country -> STEP-UP"
login -H "X-Device: unknown-phone" -H "X-Geo: RU" -H "X-Forwarded-For: 1.1.1.1" \
      -d '{"email":"alice@corp.com","password":"hunter2"}' \
  | jq '{result, outcome:.risk.outcome, score:.risk.score, signals:[.risk.signals[].signal]}'
echo "   -> credentials were fine, but the context is risky, so MFA is demanded (not a flat block)."

hr "3. CREDENTIAL STUFFING: one IP sprays 25 different accounts, one try each"
for i in $(seq 1 25); do
  login -H "X-Forwarded-For: 6.6.6.6" -H "X-Device: bot" -H "X-Geo: US" \
        -d "{\"email\":\"victim$i@corp.com\",\"password\":\"password\"}" >/dev/null
done
echo "attempt #26 from that same IP:"
login -H "X-Forwarded-For: 6.6.6.6" -H "X-Device: bot" -H "X-Geo: US" \
      -d '{"email":"victim26@corp.com","password":"password"}' \
  | jq '{result, outcome:.risk.outcome, score:.risk.score, signals:[.risk.signals[]|{signal,points}]}'
echo "   -> high IP-velocity + breached password + new device -> DENY. The botnet is walled off,"
echo "      while alice on her laptop (step 1) never felt a thing. That's the adaptive win."

hr "4. Clearing the step-up trusts the new device (step 2's phone), no more friction"
CH=$(login -H "X-Device: unknown-phone" -H "X-Geo: RU" -H "X-Forwarded-For: 1.1.1.1" \
      -d '{"email":"alice@corp.com","password":"hunter2"}' | jq -r .challenge_id)
curl -sS -X POST "$BASE/mfa" -H "X-Device: unknown-phone" -H "X-Geo: RU" \
     -d "{\"challenge_id\":\"$CH\",\"code\":\"123456\"}" | jq .
login -H "X-Device: unknown-phone" -H "X-Geo: RU" -H "X-Forwarded-For: 1.1.1.1" \
      -d '{"email":"alice@corp.com","password":"hunter2"}' | jq '{result, outcome:.risk.outcome, score:.risk.score}'
