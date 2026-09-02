#!/usr/bin/env bash
# Runs the two OIDC relying parties on the host: app-a :9000, app-b :9001.
# Ctrl-C stops both. Start Keycloak first with `podman compose up -d`.
set -euo pipefail
cd "$(dirname "$0")"

export ISSUER="${ISSUER:-http://localhost:8081/realms/authlab}"

APP_NAME=app-a CLIENT_ID=app-a CLIENT_SECRET=app-a-secret \
  BASE_URL=http://localhost:9000 PORT=9000 go run ./cmd/rp &
PID_A=$!
APP_NAME=app-b CLIENT_ID=app-b CLIENT_SECRET=app-b-secret \
  BASE_URL=http://localhost:9001 PORT=9001 go run ./cmd/rp &
PID_B=$!

trap 'kill $PID_A $PID_B 2>/dev/null || true' INT TERM EXIT
echo "app-a -> http://localhost:9000   app-b -> http://localhost:9001"
wait
