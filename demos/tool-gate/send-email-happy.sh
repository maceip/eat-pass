#!/usr/bin/env bash
# Happy path: attested mint inside uqaz1 CVM → tool-gate → mail (dry-run or SMTP).
set -euo pipefail

HOST="${DEPLOY_HOST:-azureuser@attest.secure.build}"
KT="${KT_LOG_PUB:-4162653d424e4ef0545a11e1ccd7cf1feda2572c5d9557675ad270103fa363f2}"
SUBJECT="${1:-eat-pass demo $(date -u +%Y%m%dT%H%M%SZ)}"

echo "=== attested send-email happy path on $HOST ==="

ssh -o BatchMode=yes "$HOST" bash -s <<REMOTE
set -euo pipefail
export PATH="\$HOME/.cargo/bin:\$PATH"
UQ="\$HOME/unified-quote/target/release/uq"
CVM="\$HOME/cvm-agent-src/target/release/cvm"
test -x "\$UQ" && test -x "\$CVM"

"\$CVM" tool send-email \\
  --to ryan \\
  --subject "$SUBJECT" \\
  --body "Happy path: CVM attested mint → tool-gate → gated mailbox." \\
  --kt-log-pub "$KT" \\
  --gate https://127.0.0.1:8787 \\
  --issuer http://127.0.0.1:8088 \\
  --attester http://127.0.0.1:8087 \\
  --uq-collect "sudo \$UQ azure collect" \\
  --insecure-tls
REMOTE

echo "=== happy path OK ==="
