# kavach-bot

Kavach P0: the **"Bhej ke check karo"** WhatsApp bot. Forward a suspicious message or link
and get **one** reply with a verdict and plain-language reasons, in Hindi, Hinglish or English.

Design source: *Kavach TDS v0.3*, chapters 8 (bot pipeline), 9 (reputation), 11–12 (stack).

## How it works (M1)

```
Meta Cloud API → /webhook (signature check, ack fast)
  → orchestrator: dedupe by message id → rate limit → language command → reply cache
  → Redis Stream → worker: text intents + URL checks (allowlist, OpenPhish, own reputation DB,
    lexical) → deterministic verdict → template explanation → ONE WhatsApp reply
  → Postgres: hashes, verdicts and reason codes only (no message text, wa_id stored as HMAC)
```

| Verdict | When |
|---|---|
| 🚨 SCAM | decisive list hit (OpenPhish / own DB), or score ≥ 7 |
| ⚠️ SUSPICIOUS | score 3–7 |
| ✅ LOOKS SAFE | every link is an official domain and the text is clean |
| ℹ️ NO RISK FOUND | nothing known-bad (never "guaranteed safe") |

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

### Playground (chat in the browser)

`make up && make playground` opens a WhatsApp-style chat at `http://localhost:8000/playground`,
with a panel showing the score and reasons. It's only available when `WHATSAPP_DRY_RUN=true`.

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

## Tests

```bash
make test                        # unit + golden scam/benign corpus (prints precision/recall)
.venv/bin/pytest -m integration  # store tests against the compose Postgres
```

## Milestones

- [x] **M1**: webhook, queue, text intents, URL lists, templates, reputation DB v0
- [ ] **M2**: unshortening, domain age (RDAP), lexical model, Playwright sandbox, Web Risk
- [ ] **M3**: image OCR (Tesseract hin+eng)
- [ ] **M4**: APK analysis (Androguard)
- [ ] **M5**: Ollama explanations, n-gram classifier, labelling UI, k-anon lookup API
