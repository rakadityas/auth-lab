#!/usr/bin/env bash
# What the attempt cap is actually worth: guess the code.
#
#   ./demo-otp-bruteforce.sh          -> against the SAFE app (cap holds)
#   MODE=unsafe OTP_DIGITS=4 podman compose up -d --build
#   ./demo-otp-bruteforce.sh unsafe   -> cap removed, code is guessed
#
# The shrunk 4-digit space is a demo convenience so this finishes in seconds; the
# script prints the real 6-digit arithmetic at the end.
set -euo pipefail
BASE="${BASE:-http://localhost:8080}"
MODE_ARG="${1:-safe}"
hr() { printf '\n\033[1;36m── %s\033[0m\n' "$*"; }

EMAIL="brute-$RANDOM@example.com"
START=$(curl -fsS -X POST "$BASE/otp/start" -d "{\"identifier\":\"$EMAIL\",\"channel\":\"sms\"}")
REQ=$(jq -r .request_id <<<"$START")
hr "Target request: $REQ  (attacker knows the identifier, not the code)"

if [[ "$MODE_ARG" == "safe" ]]; then
  hr "Guessing against the SAFE app"
  for i in $(seq 1 7); do
    R=$(curl -sS -X POST "$BASE/otp/verify" -d "{\"request_id\":\"$REQ\",\"code\":\"$(printf '%06d' $i)\"}")
    echo "guess $i -> $R"
  done
  echo
  echo "Guess 6 did not get a 'wrong code' answer — it got the request BURNED."
  echo "The attacker's budget is 5 draws from the space, not unlimited draws."
  exit 0
fi

# In unsafe mode /otp/start hands back the plaintext code. The attacker does NOT
# have this — we print it only so you can see the search is real and watch it
# converge on the right answer.
TRUTH=$(jq -r '.code_leaked_for_demo // "?"' <<<"$START")
hr "Guessing against the UNSAFE app (no cap, no burn)"
echo "ground truth (leaked by unsafe mode, not available to a real attacker): $TRUTH"
DIGITS=$(( ${OTP_DIGITS:-4} ))
MAX=$(( 10 ** DIGITS ))
START_TS=$(date +%s)
FOUND=""
for ((i=0; i<MAX; i++)); do
  C=$(printf "%0${DIGITS}d" "$i")
  R=$(curl -sS -X POST "$BASE/otp/verify" -d "{\"request_id\":\"$REQ\",\"code\":\"$C\"}")
  if grep -q '"session"' <<<"$R"; then FOUND="$C"; break; fi
  (( i % 250 == 0 )) && printf '\r  tried %d…' "$i"
done
END_TS=$(date +%s)
ELAPSED=$(( END_TS - START_TS + 1 ))
echo
echo "FOUND the code: $FOUND after $((i+1)) guesses in ${ELAPSED}s   (truth was $TRUTH)"
RATE=$(( (i+1) / ELAPSED ))
echo
hr "Now scale it to a real 6-digit code"
echo "observed rate    : ~${RATE} guesses/sec — ONE serial curl loop, the slowest"
echo "                   attacker imaginable"
echo "6-digit space    : 1,000,000, so ~500,000 guesses expected"
[[ $RATE -gt 0 ]] && echo "serial time      : ~$(( 500000 / RATE / 60 )) minutes, vs a 5-minute code TTL"
echo "with 200 parallel connections (trivial): ~$(( 500000 / (RATE * 200 + 1) / 60 + 1 )) min. Inside the TTL."
echo
echo "Read that carefully: without a cap, whether the account falls is decided by"
echo "how much bandwidth the attacker can buy. That is not a security control."
echo "A 5-attempt cap makes it 5-in-1,000,000 however much they buy — and burning"
echo "the request on the 6th try stops them re-rolling the same request forever."
echo
echo "Lengthening the code is the weak answer: 8 digits only buys 100x against an"
echo "attacker who can add 100x connections. The cap is the answer."
