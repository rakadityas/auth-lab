#!/usr/bin/env bash
# The FULL passkey ceremony needs a real authenticator (Touch ID / Windows Hello
# / a security key), which only a browser can drive — so the hands-on part is at
# http://localhost:8080 in your browser, not this script.
#
# What this script CAN show is the server half: the challenge-issuing "begin"
# endpoints, so you see exactly what the browser is handed. Requires curl, jq.
set -euo pipefail
BASE="${BASE:-http://localhost:8080}"
hr() { printf '\n\033[1;34m── %s\033[0m\n' "$*"; }

hr "register/begin — the server invents a one-time challenge + credential params"
curl -fsS -X POST "$BASE/register/begin?user=demo" | jq '{
  rp, user_handle_is_random: .publicKey.user.id,
  challenge: .publicKey.challenge,
  algs: [.publicKey.pubKeyCredParams[].alg],
  authenticatorSelection: .publicKey.authenticatorSelection
}'
cat <<'EOF'

  Notes:
  - rp.id = "localhost": the credential will be BOUND to this origin. A phishing
    site on evil.com can never trigger it — the browser refuses to use a
    localhost passkey for a different RP ID. This is WebAuthn's anti-phishing core.
  - user.id is a RANDOM handle, never the email/username (privacy: it may be
    stored on and synced across the user's devices).
  - challenge is fresh every call; the signed response is only valid for THIS one.
  - algs are COSE identifiers: -7 = ES256, -257 = RS256, etc.
EOF

hr "Now do the real thing in a browser"
cat <<EOF
  1. open  $BASE  in Chrome/Safari/Edge
  2. click "Register a passkey" and approve with Touch ID / Hello / your key
  3. click "Log in with passkey" — no password, a signed challenge instead
  4. watch the on-page log narrate each ceremony step

  Then read the README exercises: forge attempts, the counter/clone check, and
  what makes this unphishable where OTP and passwords are not.
EOF
