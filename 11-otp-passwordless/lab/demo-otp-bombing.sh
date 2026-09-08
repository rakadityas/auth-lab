#!/usr/bin/env bash
# OTP bombing / SMS toll fraud: abusing the SEND side, which costs money and
# harasses a real human, without ever guessing a code.
#
#   ./demo-otp-bombing.sh            -> safe app: send quotas hold
#   MODE=unsafe podman compose up -d --build && ./demo-otp-bombing.sh
set -euo pipefail
BASE="${BASE:-http://localhost:8080}"
hr() { printf '\n\033[1;36m── %s\033[0m\n' "$*"; }

# Quotas are hourly windows in Redis, so each run uses fresh identifiers and a
# fresh attacker source — otherwise the second run is blocked by the first run's
# spending and the contrast disappears. (`podman compose down -v` also resets it.)
RUN=$RANDOM
VICTIM="+1555${RUN}111"
ATTACKER_IP="198.51.100.$(( RUN % 200 + 10 ))"
hr "Attack A — bombing: 25 codes at ONE phone, each from a different source IP"
SENT=0; BLOCKED=0
for i in $(seq 1 25); do
  R=$(curl -sS -o /dev/null -w '%{http_code}' -X POST "$BASE/otp/start" \
      -H "X-Demo-IP: 203.0.113.$i" -d "{\"identifier\":\"$VICTIM\",\"channel\":\"sms\"}")
  if [[ "$R" == "200" ]]; then SENT=$((SENT+1)); else BLOCKED=$((BLOCKED+1)); fi
done
echo "delivered: $SENT    rejected: $BLOCKED"
echo "Rotating the source IP defeats a per-IP limit. What stops this is the"
echo "per-IDENTIFIER quota: one phone can only be messaged N times an hour, no"
echo "matter who asks."

hr "Attack B — toll fraud: 25 DIFFERENT numbers from one source"
SENT=0; BLOCKED=0
for i in $(seq 1 25); do
  R=$(curl -sS -o /dev/null -w '%{http_code}' -X POST "$BASE/otp/start" \
      -H "X-Demo-IP: $ATTACKER_IP" -d "{\"identifier\":\"+1555${RUN}${i}22\",\"channel\":\"sms\"}")
  if [[ "$R" == "200" ]]; then SENT=$((SENT+1)); else BLOCKED=$((BLOCKED+1)); fi
done
echo "delivered: $SENT    rejected: $BLOCKED"
echo "Here the identifier quota never trips — every number is fresh. The per-SOURCE"
echo "quota is the one doing the work. You need both; they stop different attacks."

hr "The bill (sms_sent counts everything this app has ever delivered)"
curl -fsS "$BASE/metrics" | jq '{mode, sms_sent, sms_cost_usd}' 
echo
echo "Multiply sms_cost_usd by an attacker running this for a weekend against a"
echo "premium-rate range they own. This is revenue-share fraud: they are not"
echo "breaking into an account at all, they are billing you to text their friends."
