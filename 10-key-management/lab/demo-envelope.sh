#!/usr/bin/env bash
# Envelope encryption: encrypt PII with a per-record DEK wrapped by the KEK, then
# ROTATE the KEK by re-wrapping the tiny DEK — never re-encrypting the data.
# Requires: curl, jq. Service running.
set -euo pipefail
BASE="${BASE:-http://localhost:8080}"
hr() { printf '\n\033[1;35m── %s\033[0m\n' "$*"; }

hr "1. Encrypt a piece of PII (a national ID number)"
REC=$(curl -sS -X POST "$BASE/pii/encrypt" -d '{"plaintext":"NID-123-45-6789"}')
echo "$REC" | jq .
echo "   -> stored form: {kek_version, wrapped_dek, ciphertext}. No plaintext, no bare DEK."

hr "2. Decrypt it back"
curl -sS -X POST "$BASE/pii/decrypt" -d "$REC" | jq .

hr "3. Current KEK versions"
curl -sS "$BASE/kek" | jq .

hr "4. ROTATE the master key (KEK). Existing records are untouched for now."
curl -sS -X POST "$BASE/kek/rotate" | jq .
curl -sS "$BASE/kek" | jq .

hr "5. The old record STILL decrypts (its KEK version is retained)"
curl -sS -X POST "$BASE/pii/decrypt" -d "$REC" | jq .

hr "6. REWRAP to the new KEK — note the ciphertext is byte-identical"
OLD_CT=$(echo "$REC" | jq -r .ciphertext)
REC2=$(curl -sS -X POST "$BASE/pii/rewrap" -d "$REC")
echo "$REC2" | jq '{from_kek, to_kek, note}'
NEW_CT=$(echo "$REC2" | jq -r .record.ciphertext)
if [ "$OLD_CT" = "$NEW_CT" ]; then
  echo "   ✅ ciphertext unchanged across KEK rotation — only the wrapped DEK moved."
else
  echo "   ✗ ciphertext changed (unexpected)"
fi

hr "7. Still decrypts after rewrap, now under the new KEK"
curl -sS -X POST "$BASE/pii/decrypt" -d "$(echo "$REC2" | jq .record)" | jq .

hr "The point"
cat <<'EOF'
Rotating the master key over terabytes of encrypted PII does NOT mean decrypting
and re-encrypting terabytes. Each record's data stays put; you only re-wrap its
small per-record DEK under the new KEK. That's why envelope encryption is how
this is done at scale — and why the KEK can live in a KMS/HSM the app never reads.
EOF
