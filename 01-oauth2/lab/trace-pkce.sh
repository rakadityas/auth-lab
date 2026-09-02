#!/usr/bin/env bash
# Walk an Authorization Code + PKCE flow one HTTP request at a time, with curl.
#
# There is no library and no browser here. By the end you will have seen every
# parameter that matters and why. Requires: curl, jq, openssl, python3.
set -euo pipefail

ISSUER="${ISSUER:-http://localhost:8081/realms/authlab}"
CLIENT_ID="${CLIENT_ID:-demo-web}"
REDIRECT_URI="${REDIRECT_URI:-http://localhost:9000/callback}"
USER="${USER_NAME:-alice}"
PASS="${USER_PASS:-password123}"
JAR=$(mktemp)
trap 'rm -f "$JAR"' EXIT

hr() { printf '\n\033[1;36m── %s\033[0m\n' "$*"; }
b64url() { openssl base64 -A | tr '+/' '-_' | tr -d '='; }
urlenc() { python3 -c 'import sys,urllib.parse;print(urllib.parse.quote(sys.argv[1],safe=""))' "$1"; }

hr "STEP 0  Discovery — never hardcode endpoints (RFC 8414)"
META=$(curl -fsS "$ISSUER/.well-known/openid-configuration")
AUTH_EP=$(jq -r .authorization_endpoint <<<"$META")
TOKEN_EP=$(jq -r .token_endpoint <<<"$META")
USERINFO_EP=$(jq -r .userinfo_endpoint <<<"$META")
jq '{issuer, authorization_endpoint, token_endpoint, jwks_uri,
     grant_types_supported, code_challenge_methods_supported}' <<<"$META"

hr "STEP 1  Generate PKCE verifier and challenge (RFC 7636)"
# 43-128 chars of unreserved ASCII. 32 random bytes base64url-encoded = 43 chars.
VERIFIER=$(openssl rand 32 | b64url)
CHALLENGE=$(printf '%s' "$VERIFIER" | openssl dgst -binary -sha256 | b64url)
STATE=$(openssl rand 12 | b64url)
NONCE=$(openssl rand 12 | b64url)
echo "code_verifier  (SECRET, stays on the client): $VERIFIER"
echo "code_challenge (public, sent in step 2):      $CHALLENGE"
echo "state (CSRF for the redirect):                $STATE"
echo "nonce (replay protection, echoed in ID token):$NONCE"

hr "STEP 2  Authorization request — this is a BROWSER redirect, not an API call"
AUTH_URL="$AUTH_EP?response_type=code&client_id=$CLIENT_ID&redirect_uri=$(urlenc "$REDIRECT_URI")&scope=$(urlenc 'openid profile email roles')&state=$STATE&nonce=$NONCE&code_challenge=$CHALLENGE&code_challenge_method=S256"
echo "$AUTH_URL"
echo
echo "The user agent GETs that URL. The authorization server stores the challenge"
echo "against the pending authorization and shows a login page."

hr "STEP 3  User authenticates (normally by hand; scripted here)"
LOGIN_PAGE=$(curl -fsS -c "$JAR" "$AUTH_URL")
FORM_ACTION=$(python3 -c '
import sys,re,html
m=re.search(r"<form[^>]*action=\"([^\"]+)\"", sys.stdin.read())
print(html.unescape(m.group(1)) if m else "")' <<<"$LOGIN_PAGE")
if [[ -z "$FORM_ACTION" ]]; then echo "could not find the login form; is Keycloak up?"; exit 1; fi
echo "POSTing credentials to the AS login form (credentials go to the AS, never to the client — that is the whole point of OAuth)"

REDIRECT=$(curl -sS -b "$JAR" -c "$JAR" -o /dev/null -D - \
  --data-urlencode "username=$USER" --data-urlencode "password=$PASS" \
  "$FORM_ACTION" | grep -i '^location:' | tail -1 | tr -d '\r' | sed 's/^[Ll]ocation: //')

hr "STEP 4  Authorization response — the code comes back on the redirect URI"
echo "$REDIRECT"
CODE=$(sed -n 's/.*[?&]code=\([^&]*\).*/\1/p' <<<"$REDIRECT")
RET_STATE=$(sed -n 's/.*[?&]state=\([^&]*\).*/\1/p' <<<"$REDIRECT")
if [[ -z "$CODE" ]]; then echo "no code in redirect — check the credentials"; exit 1; fi
echo
echo "code:           ${CODE:0:24}…"
echo "returned state: $RET_STATE"
[[ "$RET_STATE" == "$STATE" ]] && echo "state MATCHES — safe to continue" || { echo "STATE MISMATCH — abort"; exit 1; }
echo
echo "Note: the code travelled through the browser (URL bar, history, Referer,"
echo "server logs, any malicious app registered for this URI scheme on mobile)."
echo "That exposure is exactly why the code alone must not be enough."

hr "STEP 5  Token request — the back channel, with the verifier"
echo "POST $TOKEN_EP"
echo "  grant_type=authorization_code"
echo "  code=${CODE:0:24}…"
echo "  redirect_uri=$REDIRECT_URI      (must match step 2 byte-for-byte)"
echo "  client_id=$CLIENT_ID"
echo "  code_verifier=$VERIFIER         (the AS hashes this and compares)"
TOKENS=$(curl -fsS -X POST "$TOKEN_EP" \
  -d grant_type=authorization_code \
  -d "code=$CODE" \
  --data-urlencode "redirect_uri=$REDIRECT_URI" \
  -d "client_id=$CLIENT_ID" \
  -d "code_verifier=$VERIFIER")
jq '{token_type, expires_in, refresh_expires_in, scope,
     access_token: (.access_token[:24] + "…"),
     id_token: (.id_token[:24] + "…"),
     refresh_token: (.refresh_token[:24] + "…")}' <<<"$TOKENS"

hr "STEP 6  Decode the access token (base64, NOT encrypted)"
ACCESS=$(jq -r .access_token <<<"$TOKENS")
cut -d. -f2 <<<"$ACCESS" | tr '_-' '/+' | python3 -c '
import sys,base64,json
s=sys.stdin.read().strip(); s+="="*(-len(s)%4)
print(json.dumps(json.loads(base64.b64decode(s)),indent=2))'

hr "STEP 7  Use the access token at the resource server"
curl -fsS "$USERINFO_EP" -H "Authorization: Bearer $ACCESS" | jq .

hr "STEP 8  Replay the code — single use is mandatory (RFC 9700)"
echo "Sending the SAME code a second time:"
curl -sS -X POST "$TOKEN_EP" \
  -d grant_type=authorization_code -d "code=$CODE" \
  --data-urlencode "redirect_uri=$REDIRECT_URI" \
  -d "client_id=$CLIENT_ID" -d "code_verifier=$VERIFIER" | jq .
echo "Rejected. A conforming AS also revokes any tokens already issued for a"
echo "replayed code, because replay means the code probably leaked."

hr "STEP 9  Now attack it: correct code, WRONG verifier"
echo "This is the stolen-code scenario PKCE exists to defeat."
BAD=$(openssl rand 32 | b64url)
curl -sS -X POST "$TOKEN_EP" \
  -d grant_type=authorization_code -d "code=$CODE" \
  --data-urlencode "redirect_uri=$REDIRECT_URI" \
  -d "client_id=$CLIENT_ID" -d "code_verifier=$BAD" | jq .

hr "Done. Re-read steps 1, 5 and 9 together — that is the entire idea of PKCE."
