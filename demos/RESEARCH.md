# Demo research — remote attestation as the centerpiece

**Goal:** demos that are **interesting, useful, and impossible on Google PAT / Apple
ARC** — because the security story is **hardware remote attestation → policy →
anonymous spend**, not “logged-in human / device reputation.”

**Non-goal:** CAPTCHA replacement, “am I a bot,” or account-gated PAT flows.

---

## Why remote attestation must be the core

PAT/ARC answer: *“this client is probably fine with the platform.”*

eat-pass answers: *“this **exact build** ran in **this class of hardware** and
committed to **this mint** — now here is an **unlinkable** spend token.”*

That second sentence **requires** remote attestation to be good — not decorative:

| Property | Without strong RA | With eat-pass + unified-quote |
|----------|-------------------|-------------------------------|
| Build-level allowlist | Account / heuristics | `value_x` / `measurement` in policy |
| Per-mint binding | N/A or server session | `binding` in quote (`eat_nonce`, vTPM `qualifyingData`) |
| Third-party verify | Trust CDN issuer | Anyone runs `uq verify` → AMD/Intel root |
| Anonymous action | PAT unlinkability only | RA gate **then** PoMFRIT blind mint |
| Cross-cloud | Vendor silo | Same gate; different evidence collectors |

**Demo rule:** if the audience can’t **see attestation fail or pass on hardware
roots**, it’s not our demo — it’s a Privacy Pass tutorial.

---

## What is already strong in this stack (proven, not slideware)

From [`unified-quote/v2/STAGES.md`](../../unified-quote/v2/STAGES.md) and
[`unified-quote/README.md`](../../unified-quote/README.md):

1. **Live AMD SNP verify to Milan ARK** — captured quote + `uq verify`; live
   attested-TLS endpoint (`https://3.138.156.141/`).
2. **Two-layer identity (LATTE)** — platform measurement (firmware/TEE) +
   application `value_x` (what you put in eat-pass policy).
3. **SNP ↔ NitroTPM link on AWS** — kernel PCRs bound into `REPORT_DATA`; closes
   “firmware-only measurement” gap.
4. **Remote verify from a laptop** — no TEE on verifier machine:
   `uq verify --remote https://<host>` / `uq check https://…`.
5. **eat-pass coupling** — attester only signs FAEST authorization when
   `eat_nonce == binding_of(blinded)` **and** vendor quote verifies
   ([`gate/src/lib.rs`](../gate/src/lib.rs)).

**Azure CVM:** tested but not fully verified on raw SNP path yet — use AWS SNP
for the **hero** remote-attestation demo; Azure as stretch.

---

## The killer demo narrative (one story, all platforms)

### Act 1 — Remote attestation (the part PAT can’t do)

**Scene:** Operator laptop + CVM agent.

1. Show policy allowlist: `measurement = <launch digest>` (or `value_x`).
2. Agent inside CVM runs collect → **hardware quote** with `binding` inside
   `report_data` / vTPM `qualifyingData`.
3. **Laptop** runs `uq verify` on the bundle → **AMD/Intel root PASS** (audience
   sees chain, not your slide).
4. Attester returns **EAR-shaped appraisal** (pass + checks) — explicit policy,
   not Google PMB.

**PAT can’t do this:** no vendor quote, no build digest in operator policy, no
third-party verify to silicon root.

### Act 2 — Coupled mint (the part “attestation-only” stacks skip)

1. Same agent calls `begin(1)` → `binding`.
2. Collect evidence **for that binding** (not a stale quote).
3. `/authorize` → FAEST ok → `/sign` → PoMFRIT token.

**Fail demos (must show one):**

- Replay quote with **new** binding → attester **reject**.
- Wrong build / wrong measurement → **reject at attestation** (visible).
- Skip attestation, call issuer → **reject** (no FAEST auth).

### Act 3 — Unlinkable spend (the part attestation-only APIs skip)

1. Origin accepts `Authorization: PrivateToken …` with **only issuer pubkey**.
2. Run **two** agents (same policy class) — origin can’t tell same instance vs
   different; issuer can’t link mint → redeem (blind RSA/PoMFRIT).
3. Replay same token → redeemer **409**.

**PAT overlap:** unlinkable token only. **Missing:** hardware build gate + coupled
binding + open attester policy.

---

## Platform matrix — what to demo where

| Platform | SDK surface | RA evidence | Demo “wow” | Honest limit |
|----------|-------------|-------------|------------|--------------|
| **Linux CVM** | `EatPassLinuxTeeClient` | SNP/TDX/Nitro EAT | **Hero demo** — laptop verifies AMD root while CVM mints | Needs real CVM |
| **Linux agent** | `EatPassLinuxWorkloadClient` | Host TPM + build digest | Same **gate shape**, weaker root (TPM not silicon CVM) | Not confidential VM |
| **Windows** | C# / TPM | TPM2 quote | Enterprise agent path | Same as workload |
| **macOS / iOS** | Swift App Attest | Apple App Attest | Same mint protocol, **your** policy not Apple good-standing | Device, not cloud CVM |
| **Android** | Kotlin Key Attest | KeyMint chain | `app_id_hash` allowlist, binding in challenge | Not cloud RA |

**Research conclusion:** lead with **Linux CVM + live `uq verify`**. Other
platforms prove **same eat-pass contract**, not the same **silicon remote
attestation** story.

---

## Demo ideas ranked (useful × only-us × RA strength)

### Tier S — ship these first

1. **“Laptop jury”**  
   CVM mints; projector laptop runs `uq verify` + `eat-pass verify-azure-tls`.
   Audience trusts AMD, not you.

2. **“Wrong binary dies at the gate”**  
   Policy allows digest A; run agent B → attester appraisal **fail** before
   any token. Contrast: PAT would still issue “human” tokens.

3. **“Binding or bust”**  
   Collect quote for binding₁; attempt mint with binding₂ → reject. Shows
   coupled mint (Hanff CCS 2025), not reusable attestation.

4. **“Two ghosts, one policy”**  
   Two CVMs mint; both call protected API; operator logs show two appraisals,
   origin logs show two unlinked spends.

### Tier A — strong follow-ups

5. **“Attested tool gate”** — mock LLM tool `POST /tools/run` only with token;
   only CVM with approved agent binary passes RA + mint.

6. **“Policy diff live”** — `eat-pass policy diff` tighten allowlist; second
   agent fails immediately (explicit revoke, not PMB coloring).

7. **“KT pin”** — client refuses issuer after log head change (transparency, not
   platform PAT).

### Tier B — supporting (same protocol, weaker RA story)

8. Android/iOS — App Attest + coupled mint (mobile gate).  
9. Linux TPM — agent on k8s without CVM (workload surface).  

Label these: **“same gate, different evidence collector”** — not silicon CVM RA.

---

## What not to demo (weak or misleading)

- Generic “mint a token” without verify step on hardware roots.
- PAT comparison on **speed** or **UX** — you lose.
- Azure raw SNP as hero until MAA/vTOM path is verified.
- PoMFRIT math as the demo centerpiece — cite the paper, demo **RA + policy +
  unlinkable spend**.

---

## Minimal live stack (for Tier S demos)

```bash
# terminal A — services (Linux x86_64)
eat-pass attester --gate azure --policy policy/examples/uqaz1-example.json
eat-pass issuer --attester-pub <faest-vk-hex>
eat-pass redeem --listen :8100
eat-pass origin --issuer http://127.0.0.1:8088 --redeemer http://127.0.0.1:8100 \
  --kt-log-pub <hex>

# terminal B — inside CVM
eat-pass token --kt-log-pub <hex> \
  --uq-collect "uq azure collect" \
  --present http://127.0.0.1:8099/resource

# terminal C — laptop (no TEE)
uq verify /path/to/bundle.json
# or remote attested TLS:
uq check https://3.138.156.141/
```

Python SDK equivalent: `EatPassLinuxTeeClient` + policy-matching `collect_cmd`.

Local dev without hardware: `cargo test --features dev-sim` proves protocol
only — **do not** market as RA demo.

---

## References (demo script citations)

| Idea | Cite / artifact |
|------|-----------------|
| Coupled binding | Hanff et al. CCS 2025 |
| EAT → appraisal | RFC 9711 + RATS EAR draft |
| Two-layer measurement | LATTE (EuroS&P 2025) |
| TEE-as-witness build | Attestable Containers (CCS 2025) |
| PoMFRIT spend | Baum et al. ePrint 2026/109 |
| vs Google PMB | [`docs/competitive.md`](../docs/competitive.md) |
| Live SNP verify | `unified-quote` README, `deploy/live-snp/` |

---

## Next step (implementation)

Add `demos/` runnable packages:

- `demos/cvm-laptop-jury/` — scripts + README for Tier S #1–#3  
- `demos/tool-gate/` — tiny origin + “wrong binary” fixture  
- `demos/mobile-coupled/` — pointer to Android demo app (same narrative, Tier B)

Each demo README must state: **what PAT cannot show** in one sentence.
