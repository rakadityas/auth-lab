#!/usr/bin/env bash
# Runs the demo OAuth client on http://localhost:9000
#
#   ./run-client.sh              # Authorization Code + PKCE (the correct way)
#   ./run-client.sh --no-pkce    # deliberately weak client, for the attack exercise
set -euo pipefail
cd "$(dirname "$0")/client"

export ISSUER="${ISSUER:-http://localhost:8081/realms/authlab}"
export REDIRECT_URI="${REDIRECT_URI:-http://localhost:9000/callback}"
export SCOPE="${SCOPE:-openid profile email roles}"
export PORT="${PORT:-9000}"

if [[ "${1:-}" == "--no-pkce" ]]; then
  export CLIENT_ID="demo-web-nopkce"
  export USE_PKCE="false"
  echo "!! running WITHOUT PKCE -- this configuration is vulnerable on purpose"
else
  export CLIENT_ID="${CLIENT_ID:-demo-web}"
  export USE_PKCE="true"
fi

exec go run .
