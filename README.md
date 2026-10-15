# kavach-bot

Kavach P0: the **"Bhej ke check karo"** WhatsApp bot. Forward a suspicious message or link
and get **one** reply with a verdict and plain-language reasons, in Hindi, Hinglish or English.

Design source: *Kavach TDS v0.3*, chapters 8 (bot pipeline), 9 (reputation), 11–12 (stack).

## How it works (M1–M4)

```
Meta Cloud API → /webhook (signature check, ack fast)
  → orchestrator: dedupe by message id → rate limit → language command → reply cache
  → Redis Stream → worker: text intents + URL checks (allowlist, OpenPhish, own reputation DB,
    lexical, look-alike, URL features) → deep checks for unresolved links (sandbox unshorten +
    page visit, RDAP domain age, Web Risk) → deterministic verdict → ONE WhatsApp reply
    (an image with caption when there's a screenshot of a fake page)
  Photos (M3): download → OCR (Tesseract, Hindi + English) + QR decode → same pipeline
    (UPI QR + "scan to receive money" = scam); the photo lives in memory only
  APK files (M4): file-hash reputation → sandbox reads the manifest + signer with Androguard
    (never installed or run; zip-bomb checks; resource-limited child process) → permission /
    impersonation rules (SMS/OTP reading, accessibility, overlays, device admin…) → verdict;
    any app shared on WhatsApp is at least ⚠️
  → Postgres: hashes, verdicts and reason codes only (no message text, wa_id stored as HMAC)
```

| Verdict | When |
|---|---|
| 🚨 SCAM | decisive list hit (OpenPhish / own DB), or score ≥ 7 |
| ⚠️ SUSPICIOUS | score 3–7 |
| ✅ LOOKS SAFE | every link is an official domain and the text is clean |
| ℹ️ NO RISK FOUND | nothing known-bad (never "guaranteed safe") |

## Sandbox (M2)

Only the `sandbox` container ever opens user links. It runs on its own Docker network (internet only: Postgres, Redis and the API don't resolve from it), as a non-root user, with a read-only filesystem, no Linux capabilities and capped CPU and memory. Every URL and redirect hop must resolve only to public addresses (`src/kavach/sandbox/netguard.py`).

## Dependencies and supply chain

- **Exact pins** in `pyproject.toml` (direct dependencies only), each at least **14 days old** when chosen,
  because brand-new releases are where hijacked or broken versions show up.
- **Hash-locked trees** in `requirements/`: `runtime.txt` (api/worker), `sandbox.txt` (adds Androguard +
  Playwright), `dev.txt` (adds test tools). Every package, sub-dependencies included, is pinned by SHA-256,
  and the whole tree respects the same 14-day cutoff (`uv pip compile --exclude-newer`).
- **Builds install only from the locks**, with `pip install --require-hashes --no-deps`. A changed or tampered
  file fails the build.
- **Docker images are pinned by tag + digest**, so a re-pointed tag can't change what we run.
- **Vulnerability scan:** `make audit` (pip-audit against the OSV / PyPI advisory databases).

To add or upgrade a library: edit `pyproject.toml` (choose a release ≥ 14 days old), bump `LOCK_CUTOFF` in the
`Makefile` if needed, then run `make lock audit test` and rebuild.

## Run locally

Prerequisites: Docker Desktop and Python 3.12+.

```bash
make setup                       # venv + dev tools
cp .env.example .env             # fill in; see "Keys" below
make test lint                   # unit tests + ruff + mypy (no Docker needed)
make up                          # postgres, redis, migrations, api, worker
```

### Offline eval (no Docker, no internet)

```bash
make eval                                             # eval/messages.csv → console + HTML report
.venv/bin/python -m kavach.tools.evaluate --text "OTP batao jaldi"
```

### Image eval (real OCR, needs `make up`)

`make image-eval` sends every labelled image in `tests/fixtures/images/` (`scam_*`, `safe_*`,
`blank_*`) through the running bot and checks the verdict in the reply the user would actually
get. Drop your own screenshots in with the same naming. To regenerate the built-in fixtures:
`.venv/bin/python scripts/make_image_fixtures.py`.

### APK eval (needs `make up`)

`make apk-eval` generates harmless, code-free test APKs locally (`tests/apkgen.py`: a manifest
plus a throwaway signature, nothing executable, nothing downloaded) and sends them through the
running bot. Generated APKs are gitignored.

### Playground (chat in the browser)

`make up && make playground` opens a WhatsApp-style chat at `http://localhost:8000/playground`,
with a panel showing the score and reasons. Attach photos or `.apk` files with 📎, paste photos (⌘V), or drag them in.
It's only available when `WHATSAPP_DRY_RUN=true`.

### Try it without WhatsApp (dry run)

Set `WHATSAPP_DRY_RUN=true` and any `META_APP_SECRET` / `USER_HASH_KEY` in `.env`, then:

```bash
make up && make replay                              # built-in samples
.venv/bin/python -m kavach.tools.replay "OTP batao jaldi, account band ho jayega"
```

### Connect real WhatsApp

1. In `.env`, set `WHATSAPP_DRY_RUN=false` and fill in the Meta values.
2. Start a public URL: `make quicktunnel` (random URL) or `make tunnel` (named, stable).
3. Meta dashboard → WhatsApp → Configuration → Webhook:
   - **Callback URL**: `https://<tunnel-host>/webhook`
   - **Verify token**: your `WHATSAPP_VERIFY_TOKEN`
   - Subscribe to the **messages** field.
4. From your phone (added as a test recipient), message the test number.

## Keys (all in `.env`, never committed)

| Key | Where from |
|---|---|
| `WHATSAPP_ACCESS_TOKEN`, `WHATSAPP_PHONE_NUMBER_ID`, `WHATSAPP_WABA_ID` | Meta App → WhatsApp → API Setup |
| `META_APP_SECRET` | Meta App → App settings → Basic |
| `WHATSAPP_VERIFY_TOKEN` | any random string you choose |
| `USER_HASH_KEY` | `python3 -c "import secrets;print(secrets.token_hex(32))"` |
| `CLOUDFLARE_TUNNEL_TOKEN` | optional, Cloudflare Zero Trust → Tunnels |
| `WEBRISK_API_KEY` | optional, Google Cloud → Web Risk API (100k lookups/month free) |

## Tests

```bash
make test                        # unit + golden scam/benign corpus (prints precision/recall)
.venv/bin/pytest -m integration  # store tests against the compose Postgres
```

## Milestones

- [x] **M1**: webhook, queue, text intents, URL lists, templates, reputation DB v0
- [x] **M2**: isolated Playwright sandbox, unshortening (SSRF-guarded), domain age (RDAP), look-alikes, URL features, screenshot evidence, optional Web Risk
- [x] **M3**: photos: OCR (Tesseract hin+eng), UPI QR decoding, "scan to receive money" and excess-payment scams, reply cache versioned by rules fingerprint
- [x] **M4**: APK files: static analysis in the sandbox (Androguard), banking-trojan / fake-bank / wedding-card patterns, file-hash reputation
- [ ] **M5**: Ollama explanations, n-gram classifier, labelling UI, k-anon lookup API
