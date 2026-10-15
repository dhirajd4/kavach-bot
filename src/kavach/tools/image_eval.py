"""Media eval: send labelled images and APK files through the RUNNING bot (real OCR, QR
decoding and sandboxed APK parsing in Docker) via the playground endpoint, and check the
verdict in the reply the user would actually get.

File names carry the label: scam_* (must be flagged), safe_* (must not be flagged),
warn_* (must be ⚠️ suspicious, e.g. any harmless APK), blank_* (must say "nothing readable").

    make up && make image-eval && make apk-eval
    .venv/bin/python -m kavach.tools.image_eval path/to/folder
"""

import argparse
import base64
import sys
import time
import uuid
from pathlib import Path

import httpx

FLAGGED = {"scam", "suspicious"}
# The verdict the USER sees, read from the reply headline (catches stale cached replies).
HEADLINES = (("🚨", "scam"), ("⚠️", "suspicious"), ("✅", "looks_safe"), ("ℹ️", "no_risk_found"))


def reply_verdict(reply: str) -> str:
    body = reply.split("━━━━━━━━━━")[-1]
    return next((v for icon, v in HEADLINES if icon in body), "nothing_to_check")


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("folder", nargs="?", default="tests/fixtures/images")
    ap.add_argument("--url", default="http://localhost:8000")
    ap.add_argument("--show-replies", action="store_true")
    args = ap.parse_args()

    files = sorted(
        p
        for p in Path(args.folder).iterdir()
        if p.suffix.lower() in {".png", ".jpg", ".jpeg", ".webp", ".apk"}
    )
    if not files:
        sys.exit(f"no images or APKs in {args.folder}")
    ok = 0
    print(f"{'':2} {'file':34} {'verdict':14} {'score':>5} {'ms':>6}  ocr  qr  reasons")
    print("-" * 110)
    with httpx.Client(base_url=args.url, timeout=60) as http:
        for path in files:
            sender = "9177" + str(uuid.uuid4().int)[:8]  # fresh user: no cache, no rate limit
            started = time.monotonic()
            payload = base64.b64encode(path.read_bytes()).decode()
            if path.suffix.lower() == ".apk":
                body = {"sender": sender, "file_b64": payload, "filename": path.name}
            else:
                body = {"sender": sender, "image_b64": payload}
            resp = http.post("/dev/simulate", json=body)
            if resp.status_code == 404:
                sys.exit("playground disabled: set WHATSAPP_DRY_RUN=true and `make up`")
            resp.raise_for_status()
            data = resp.json()
            d = data["debug"]
            verdict = d["verdict"]
            label = path.stem.split("_", 1)[0]
            seen = reply_verdict(data["reply"] or "")
            mismatch = seen != verdict
            correct = not mismatch and (
                (label == "scam" and verdict in FLAGGED)
                or (label == "safe" and verdict not in FLAGGED)
                or (label == "warn" and verdict == "suspicious")
                or (label == "blank" and not (d.get("image") or {}).get("readable", True))
                or label not in {"scam", "safe", "warn", "blank"}
            )
            ok += correct
            img = d.get("image") or {}
            print(
                f"{'✓' if correct else '✗':2} {path.name[:34]:34} {verdict:14} {d['score']:5.1f} "
                f"{int((time.monotonic() - started) * 1000):6}  {img.get('ocr_chars', 0):>3}"
                f"  {img.get('qr_count', 0):>2}  {', '.join(d['all_codes'])[:60]}"
            )
            if mismatch:
                print(f"     ✗ the user's reply says {seen!r} but the rules say {verdict!r}")
            if args.show_replies:
                print("     " + (data["reply"] or "").replace("\n", "\n     ") + "\n")
    print("-" * 110)
    print(f"{ok}/{len(files)} correct")
    sys.exit(0 if ok == len(files) else 1)


if __name__ == "__main__":
    main()
