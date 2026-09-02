#!/usr/bin/env bash
# Multi-tenancy: isolation, org-scoped roles, invitations, and SSO+JIT.
# Requires: curl, jq. Service running.
set -euo pipefail
BASE="${BASE:-http://localhost:8080}"
ACME="aaaa1111-0000-0000-0000-000000000001"
BETA="bbbb2222-0000-0000-0000-000000000002"
hr() { printf '\n\033[1;36m── %s\033[0m\n' "$*"; }
u() { curl -sS -H "X-User: $1" -H "X-Org: $2" "${@:3}"; }  # u <user> <org> [curl args]

hr "alice (admin of Acme) lists Acme projects — allowed"
u alice@acme.com "$ACME" "$BASE/projects" | jq .

hr "ISOLATION: alice points X-Org at BETA's id — turned away, sees nothing"
u alice@acme.com "$BETA" "$BASE/projects" | jq .
echo "   -> membership check fails before any Beta data is read. This is the tenant boundary."

hr "ORG-SCOPED ROLES: bob is only a MEMBER of Acme; inviting requires admin"
u bob@acme.com "$ACME" "$BASE/invitations" -X POST -d '{"email":"dave@acme.com"}' | jq .
echo "   -> same user, but no admin role in THIS org -> denied. Roles are per-tenant."

hr "alice (admin) invites dave; dave accepts and joins Acme"
TOK=$(u alice@acme.com "$ACME" "$BASE/invitations" -X POST -d '{"email":"dave@acme.com","role":"member"}' | jq -r .accept_token)
curl -sS -X POST "$BASE/invitations/accept" -d "{\"token\":\"$TOK\"}" | jq .

hr "HOME-REALM DISCOVERY: where does erin@acme.com log in?"
curl -sS "$BASE/sso/discover?email=erin@acme.com" | jq .
echo "   -> domain acme.com maps to Acme's SSO. A gmail.com address would fall back to password."

hr "JIT PROVISIONING: erin logs in via Acme SSO for the first time"
curl -sS -X POST "$BASE/sso/callback" -d '{"email":"erin@acme.com"}' | jq .
echo "   -> no invite needed: SSO + JIT created her Acme membership on the spot."

hr "Acme members now:"
u alice@acme.com "$ACME" "$BASE/members" | jq -c '.[]'
