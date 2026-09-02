#!/usr/bin/env bash
# SCIM: the offboarding half of enterprise identity. The IdP provisions a user,
# they get access, then the IdP deprovisions them (active=false) and access is
# cut on the very next request — without deleting the human.
# Requires: curl, jq. Service running.
set -euo pipefail
BASE="${BASE:-http://localhost:8080}"
ACME="aaaa1111-0000-0000-0000-000000000001"
TOKEN="scim-acme-secret-token"      # Acme's SCIM bearer token (seeded)
SCIM=(-H "Authorization: Bearer $TOKEN" -H "Content-Type: application/scim+json")
hr() { printf '\n\033[1;35m── %s\033[0m\n' "$*"; }

hr "IdP PROVISIONS frank via SCIM (POST /scim/v2/Users)"
FRANK=$(curl -sS "${SCIM[@]}" -X POST "$BASE/scim/v2/Users" \
        -d '{"schemas":["urn:ietf:params:scim:schemas:core:2.0:User"],"userName":"frank@acme.com","active":true}')
echo "$FRANK" | jq '{id,userName,active}'
FID=$(echo "$FRANK" | jq -r .id)

hr "frank can now act in Acme (SSO login succeeds -> membership active)"
curl -sS -X POST "$BASE/sso/callback" -d '{"email":"frank@acme.com"}' | jq .

hr "OFFBOARDING: IdP sends PATCH active=false (employee leaves the company)"
curl -sS "${SCIM[@]}" -X PATCH "$BASE/scim/v2/Users/$FID" \
  -d '{"schemas":["urn:ietf:params:scim:api:messages:2.0:PatchOp"],"Operations":[{"op":"replace","path":"active","value":false}]}' \
  | jq '{userName,active}'

hr "frank tries to use the app -> BLOCKED on the next request"
curl -sS -H "X-User: frank@acme.com" -H "X-Org: $ACME" "$BASE/projects" | jq .

hr "frank tries to SSO back in -> refused (SSO must not resurrect a revoked membership)"
curl -sS -X POST "$BASE/sso/callback" -d '{"email":"frank@acme.com"}' | jq .

hr "The point"
cat <<'EOF'
Without SCIM, disabling frank in the IdP does nothing to your app — his account
lingers after he leaves ("SSO works but offboarding doesn't"). SCIM's PATCH
active=false is the signal that cuts access centrally and immediately. Note the
human/user row still exists (he may belong to other orgs); only the Acme
MEMBERSHIP was deactivated.
EOF
