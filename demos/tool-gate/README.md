# Attested tool gate — email without credentials on the agent

**What PAT can't show:** an agent running **outside** the attested CVM cannot send
mail as Ryan — it has **no SMTP password**. Only a hardware-attested mint +
one-time PoMFRIT token unlocks `POST /v1/tools/email.send` on the tool-gate host.

## Architecture

| Component | Repo | Role |
|-----------|------|------|
| `cvm` agent | cvm-agent | Runs inside Azure CVM; mints token bound to email intent |
| `eat-pass attester` | eat-pass | **Azure gate** — verifies SNP measurement + binding |
| `eat-pass issuer` | eat-pass | PoMFRIT blind-sign after FAEST authorization |
| `tool-gate` | cvm-agent | Holds `TOOL_GATE_SMTP_*`; sends mail after token spend |

Ryan's mailbox password lives in `tool-gate.env` on the gate host only.
The agent never sees it.

## Quick fail demo (no token)

With the stack running locally or on `uqaz1`:

| [`show-no-proof.sh`](./show-no-proof.sh) | Agent without token → 401 | No |
| [`send-email-happy.sh`](./send-email-happy.sh) | Full mint + send on `uqaz1` (SSH) | Yes (Azure CVM) |

```bash
./show-no-proof.sh https://attest.secure.build:8787
./send-email-happy.sh   # SSH to uqaz1; uses TOOL_GATE_DRY_RUN if set on gate
```

Expected: `401` + `WWW-Authenticate` challenge — proof required.

## Full stack (operator)

```bash
# on gate host (secrets stay here)
cp ../../cvm-agent/deploy/tool-gate.env.example tool-gate.env
# set EATPASS_* seeds, KT_LOG_PUB, TOOL_GATE_SMTP_*, TOOL_GATE_CONTACT_RYAN
../../cvm-agent/deploy/run-tool-gate-stack.sh
```

## Happy path (inside attested CVM)

```bash
cvm tool send-email --to ryan --subject "From the CVM" --body "Attested send." \
  --kt-log-pub "$KT_LOG_PUB" \
  --gate http://127.0.0.1:8787 \
  --issuer http://127.0.0.1:8088 \
  --attester http://127.0.0.1:8087
```

Use `TOOL_GATE_DRY_RUN=1` in env to log the send without delivering mail.

## Production on uqaz1

```bash
../../cvm-agent/deploy/install-uqaz1.sh
```

Tool-gate listens on `:8787` (TLS). Attested-TLS evidence at `:8443`.
