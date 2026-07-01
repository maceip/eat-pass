#!/usr/bin/env bash
# Demonstrates: no attestation → no email. SMTP credentials are irrelevant on the client.
set -euo pipefail

GATE="${1:-${TOOL_GATE_URL:-https://attest.secure.build:8787}}"
TO="${2:-ryan@example.com}"
SUBJECT="${3:-demo}"
BODY="${4:-This should not send without a PrivateToken.}"

CURL_OPTS=(-sS --connect-timeout 15 --max-time 30)
if [[ "$GATE" == https://* ]]; then
  CURL_OPTS+=(-k)  # attested-TLS uses self-signed leaf on uqaz1
fi

quote() { python3 -c "import urllib.parse,sys; print(urllib.parse.quote(sys.argv[1]))" "$1"; }
URL="${GATE%/}/v1/tools/email.send"
TMP="$(mktemp)"
trap 'rm -f "$TMP"' EXIT

echo "POST $URL"
echo "(no Authorization header — simulates agent outside sandbox / without mint)"
echo

set +e
HTTP=$(curl "${CURL_OPTS[@]}" -o "$TMP" -w "%{http_code}" \
  -X POST "$URL" \
  -H "Content-Type: application/json" \
  -d '{"to":"'"$TO"'","subject":"'"$SUBJECT"'","body":"'"$BODY"'"}')
CURL_RC=$?
set -e

if [[ "$CURL_RC" -ne 0 ]]; then
  echo "curl failed (exit $CURL_RC) — is tool-gate running at $GATE ?" >&2
  echo "  local: ../../cvm-agent/deploy/run-tool-gate-stack.sh" >&2
  exit 2
fi

echo "HTTP $HTTP"
head -c 800 "$TMP"; echo
echo

if [[ "$HTTP" == "401" ]]; then
  echo "PASS: tool-gate rejected unauthenticated send (expected)."
  exit 0
fi

echo "FAIL: expected 401 without attested token (got $HTTP)" >&2
exit 1
