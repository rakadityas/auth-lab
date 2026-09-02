#!/usr/bin/env bash
# The other grants you will actually meet: Client Credentials, Device Code,
# Refresh, plus Introspection and Revocation.
set -euo pipefail

ISSUER="${ISSUER:-http://localhost:8081/realms/authlab}"
META=$(curl -fsS "$ISSUER/.well-known/openid-configuration")
TOKEN_EP=$(jq -r .token_endpoint <<<"$META")
DEVICE_EP=$(jq -r .device_authorization_endpoint <<<"$META")
INTROSPECT_EP=$(jq -r .introspection_endpoint <<<"$META")
REVOKE_EP=$(jq -r .revocation_endpoint <<<"$META")

hr() { printf '\n\033[1;36m── %s\033[0m\n' "$*"; }

hr "CLIENT CREDENTIALS — service to service, no user involved"
echo "The client authenticates AS ITSELF. There is no resource owner, so there is"
echo "no redirect, no consent, no refresh token, and no 'sub' belonging to a human."
CC=$(curl -fsS -X POST "$TOKEN_EP" \
  -d grant_type=client_credentials \
  -d client_id=svc-backend \
  -d client_secret=svc-backend-secret \
  -d scope=roles)
jq '{token_type, expires_in, scope, refresh_token: (.refresh_token // "none — correct, do not issue one here")}' <<<"$CC"
SVC=$(jq -r .access_token <<<"$CC")
echo
echo "Claims:"
cut -d. -f2 <<<"$SVC" | tr '_-' '/+' | python3 -c '
import sys,base64,json
s=sys.stdin.read().strip(); s+="="*(-len(s)%4)
c=json.loads(base64.b64decode(s))
print(json.dumps({k:c[k] for k in ("iss","aud","sub","azp","scope","typ","exp") if k in c},indent=2))'

hr "INTROSPECTION (RFC 7662) — how a resource server validates an OPAQUE token"
curl -fsS -X POST "$INTROSPECT_EP" \
  -d client_id=svc-backend -d client_secret=svc-backend-secret \
  -d "token=$SVC" | jq '{active, scope, client_id, exp, token_type}'
echo "Note 'active': that single boolean is what stateless JWT verification cannot"
echo "give you. It is a network call per request unless you cache it — and the"
echo "cache TTL is exactly your revocation delay. This trade-off is Module 3's ADR."

hr "REVOCATION (RFC 7009)"
curl -fsS -o /dev/null -w 'revoke status: %{http_code}\n' -X POST "$REVOKE_EP" \
  -d client_id=svc-backend -d client_secret=svc-backend-secret \
  -d "token=$SVC" -d token_type_hint=access_token
echo "Introspect again:"
curl -fsS -X POST "$INTROSPECT_EP" \
  -d client_id=svc-backend -d client_secret=svc-backend-secret \
  -d "token=$SVC" | jq '{active}'
echo "active:false now. But a resource server doing LOCAL JWT verification would"
echo "still accept this token until it expires. Revocation only works if someone asks."

hr "DEVICE AUTHORIZATION GRANT (RFC 8628) — TVs, CLIs, anything without a browser"
DEV=$(curl -fsS -X POST "$DEVICE_EP" -d client_id=device-cli -d scope=openid)
jq '{user_code, verification_uri, verification_uri_complete, expires_in, interval}' <<<"$DEV"
DEVICE_CODE=$(jq -r .device_code <<<"$DEV")
echo
echo "Open this in a browser and log in as alice / password123:"
jq -r '.verification_uri_complete // .verification_uri' <<<"$DEV"
echo
echo "Meanwhile the device polls. Watch it get authorization_pending until you approve:"
for i in $(seq 1 24); do
  R=$(curl -sS -X POST "$TOKEN_EP" \
    -d grant_type=urn:ietf:params:oauth:grant-type:device_code \
    -d client_id=device-cli -d "device_code=$DEVICE_CODE")
  ERR=$(jq -r '.error // empty' <<<"$R")
  if [[ -z "$ERR" ]]; then
    echo "approved — tokens issued:"
    jq '{token_type, expires_in, scope}' <<<"$R"
    break
  fi
  echo "  poll $i: $ERR"
  # slow_down means the AS wants a longer interval; a real client must obey it.
  sleep 5
done

hr "NOT DEMONSTRATED, ON PURPOSE"
echo "Implicit grant (response_type=token) and Resource Owner Password Credentials"
echo "(grant_type=password) are deprecated by RFC 9700. Implicit puts tokens in the"
echo "URL fragment where they leak through history and Referer; ROPC requires the"
echo "user to hand their password to the client, which destroys the reason OAuth"
echo "exists and cannot support MFA or federation. If you see either in a design"
echo "doc, that is your review comment."
