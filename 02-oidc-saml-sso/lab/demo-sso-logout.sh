#!/usr/bin/env bash
# Headless proof of SSO + Back-Channel Logout across two RPs.
#
# The browser walkthrough in the README is the primary way to see this. This
# script reproduces it without a browser so you can watch the server logs.
# Start Keycloak (podman compose up -d) and both RPs (./run-apps.sh) first.
# Requires: curl, jq, python3.
set -euo pipefail
A=http://localhost:9000
B=http://localhost:9001
KC=http://localhost:8081
J=$(mktemp); trap 'rm -f "$J"' EXIT
hr(){ printf '\n\033[1;36m── %s\033[0m\n' "$*"; }

form_action(){ python3 -c 'import sys,re,html;m=re.search(r"<form[^>]*action=\"([^\"]+)\"",sys.stdin.read());print(html.unescape(m.group(1)) if m else "")'; }

hr "1. Log in to app-a (you supply the password once)"
PAGE=$(curl -fsS -L -c "$J" -b "$J" "$A/login")
ACTION=$(form_action <<<"$PAGE")
curl -sS -L -c "$J" -b "$J" -o /dev/null --data-urlencode username=alice --data-urlencode password=password123 "$ACTION"
curl -s -b "$J" "$A/" | grep -oiE 'Logged in as <b>[^<]+' | sed 's/<b>/app-a: /'

hr "2. Visit app-b — SSO completes with NO password prompt"
RESP=$(curl -sS -L -c "$J" -b "$J" "$B/login")
grep -qi 'password' <<<"$RESP" && echo "password prompt shown (SSO failed)" || echo "app-b: logged in via SSO, no password asked"
curl -s -b "$J" "$B/" | grep -oiE 'Logged in as <b>[^<]+' | sed 's/<b>/app-b: /'

hr "3. Single logout — trigger the IdP to end alice's session everywhere"
echo "Using Keycloak's admin API as the trigger (a real user clicking 'logout'"
echo "in the browser does the same thing via the end_session endpoint)."
TOK=$(curl -s -X POST "$KC/realms/master/protocol/openid-connect/token" \
  -d client_id=admin-cli -d username=admin -d password=admin -d grant_type=password | jq -r .access_token)
USERID=$(curl -s "$KC/admin/realms/authlab/users?username=alice" -H "Authorization: Bearer $TOK" | jq -r '.[0].id')
curl -s -o /dev/null -w "admin logout -> HTTP %{http_code}\n" -X POST \
  "$KC/admin/realms/authlab/users/$USERID/logout" -H "Authorization: Bearer $TOK"
sleep 2

hr "4. Both RPs received a signed Back-Channel Logout Token, server-to-server"
echo "app-a and app-b are now logged out even though your browser never touched them:"
curl -s -b "$J" "$A/" | grep -oiE 'Not logged in' | sed 's/^/app-a: /'
curl -s -b "$J" "$B/" | grep -oiE 'Not logged in' | sed 's/^/app-b: /'
echo
echo "Look at the app-a / app-b server logs for the 'BACK-CHANNEL LOGOUT received'"
echo "lines — that POST came from the IdP directly, no browser and no cookies."
