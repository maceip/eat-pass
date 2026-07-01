# eat-pass demos

Runnable demos that **require hardware remote attestation** — not something
Google PAT or Apple ARC can replicate.

Each demo states what platform tokens **cannot** show.

| Demo | What PAT can't do | Needs TEE? |
|------|-------------------|------------|
| [laptop-jury](./laptop-jury/) | Third-party verify to AMD/Intel root on a laptop | No (verifier only) |
| [fail-closed](./fail-closed/) | Wrong build / wrong binding rejected at policy | No (`policy simulate`) |
| [tool-gate](./tool-gate/) | Agent without attested build can't send mail; SMTP secrets never on agent | Yes (mint in CVM) |
| [offline-protocol](../cli/tests/e2e.rs) | *(protocol only — not an RA demo)* | No (`dev-sim`) |

**Platform surfaces:** [`docs/platform-surface.md`](../docs/platform-surface.md) — policy is the operator interface; `--gate` picks evidence wire format per platform.

**Live infrastructure**

- Attestation nodes: [unified-quote live dashboard](https://maceip.github.io/unified-quote/live.html)
- Azure attested-TLS: `https://attest.secure.build:8443/`
- Tool-gate stack on `uqaz1`: `cvm-agent/deploy/install-uqaz1.sh`

**Stack map (gates, not “gauges”)**

```
Agent (cvm in Azure CVM)
  → uq azure collect          # evidence collector
  → eat-pass attester (azure gate)   # FAEST authorization
  → eat-pass issuer           # PoMFRIT blind mint
  → tool-gate                 # privileged tool RP (email.send)
       ↑ SMTP password lives here only — never on the agent
```

## Run all tests (laptop)

```bash
./demos/test-all.sh
./scripts/verify-before-push.sh          # demos only
./scripts/verify-before-push.sh --full   # + cargo test --workspace in Docker (macOS/ARM)
```

macOS/ARM cannot build PoMFRIT natively; use `scripts/test-workspace-linux-docker.sh` (same as CI Linux job).

