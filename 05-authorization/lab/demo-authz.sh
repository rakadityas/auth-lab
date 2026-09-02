#!/usr/bin/env bash
# Runs the SAME set of authorization questions against both engines and shows
# where they diverge. The seeded world:
#
#   documents:  README (in folder Engineering)   Board Secret (at root, alice owns)
#   users:      alice = global admin  + owner of Board Secret
#               bob   = global editor + editor of folder Engineering
#               carol = global viewer + direct viewer of README
#               dave  = member of group "staff"; staff can view README
#
# Requires: curl, jq. Service running. Flip MODEL in compose.yaml and
# `podman compose up -d --build app` to switch engines between runs.
set -euo pipefail
BASE="${BASE:-http://localhost:8080}"
README="aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"
SECRET="bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb"
hr() { printf '\n\033[1;35m── %s\033[0m\n' "$*"; }

# ask WHO ACTION DOC -> prints allow/deny with the HTTP status
ask() { # $1=email $2=METHOD $3=docid $4=label
  local code
  code=$(curl -s -o /dev/null -w '%{http_code}' -X "$2" -H "X-User: $1" "$BASE/documents/$3" \
         ${2:+ } $( [ "$2" = PUT ] && echo '-d {"title":"x"}' ))
  if [ "$code" = 200 ]; then printf '  \033[32mALLOW\033[0m  %s\n' "$4"
  else printf '  \033[31mDENY \033[0m  %s  (HTTP %s)\n' "$4" "$code"; fi
}

MODEL=$(curl -fsS "$BASE/explain/$README" -H "X-User: alice@corp.com" | jq -r .model)
hr "ENGINE IN USE: $MODEL"

hr "Can bob WRITE each document?"
ask bob@corp.com   PUT "$README" "bob -> write README   (bob edits folder Engineering)"
ask bob@corp.com   PUT "$SECRET" "bob -> write Board Secret"
echo "   RBAC: bob is a GLOBAL editor -> ALLOW on BOTH (even the secret he was never given)."
echo "   ReBAC: bob edits folder Engineering -> ALLOW on README (inherited), DENY on the secret."

hr "Can carol DELETE / WRITE / READ README?"
ask carol@corp.com DELETE "$README" "carol -> delete README"
ask carol@corp.com PUT    "$README" "carol -> write README"
ask carol@corp.com GET    "$README" "carol -> read README"

hr "Can dave READ README purely via group membership?"
ask dave@corp.com  GET "$README" "dave -> read README  (dave ∈ group staff ∈ viewers)"
echo "   RBAC: dave has NO role -> DENY. ReBAC: group userset -> ALLOW."

hr "Explain: why can/can't bob touch the Board Secret?"
curl -fsS "$BASE/explain/$SECRET" -H "X-User: bob@corp.com" | jq .
