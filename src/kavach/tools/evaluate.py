"""Offline evaluation: run a labelled CSV through the real detection pipeline.

No Docker, no Meta and no internet needed: an in-memory Redis and store stand in. Add
--openphish to pull the live phishing feed first (needs internet).

    python -m kavach.tools.evaluate                       # eval/messages.csv
    python -m kavach.tools.evaluate my.csv --html report.html --lang en
    python -m kavach.tools.evaluate --text "OTP batao jaldi"   # one-off check

CSV columns: expected (scam|safe), scenario, text
"""

import argparse
import asyncio
import csv
import html
import sys
from dataclasses import dataclass
from pathlib import Path

import fakeredis
import httpx

from kavach.intel import openphish
from kavach.pipeline import analyse_text
from kavach.reputation.memory import MemoryStore
from kavach.verdict.composer import explain, render
from kavach.verdict.rules import Decision, Verdict

FLAGGED = {Verdict.SCAM, Verdict.SUSPICIOUS}
ICON = {
    Verdict.SCAM: "🚨",
    Verdict.SUSPICIOUS: "⚠️",
    Verdict.LOOKS_SAFE: "✅",
    Verdict.NO_RISK_FOUND: "ℹ️",
    Verdict.NOTHING_TO_CHECK: "💬",
}


@dataclass
class Row:
    expected: str
    scenario: str
    text: str
    decision: Decision
    reply: str

    @property
    def flagged(self) -> bool:
        return self.decision.verdict in FLAGGED

    @property
    def correct(self) -> bool:
        return self.flagged == (self.expected == "scam")


async def run(rows_in: list[dict[str, str]], lang: str, use_openphish: bool) -> list[Row]:
    redis = fakeredis.FakeAsyncRedis()
    store = MemoryStore()
    if use_openphish:
        async with httpx.AsyncClient(timeout=15) as http:
            n = await openphish.sync(redis, http, "https://openphish.com/feed.txt")
            print(f"OpenPhish feed loaded: {n} URLs\n")
    out: list[Row] = []
    for r in rows_in:
        result = await analyse_text(r["text"], redis, store)
        exp = await explain(result.decision, lang, None)
        reply = render(result.decision, exp, lang, first_time=False)
        out.append(
            Row(
                r.get("expected", "?").strip().lower(),
                r.get("scenario", ""),
                r["text"],
                result.decision,
                reply,
            )
        )
    await redis.aclose()
    return out


def metrics(rows: list[Row]) -> dict[str, float]:
    labelled = [r for r in rows if r.expected in {"scam", "safe"}]
    tp = sum(r.flagged and r.expected == "scam" for r in labelled)
    fp = sum(r.flagged and r.expected == "safe" for r in labelled)
    fn = sum(not r.flagged and r.expected == "scam" for r in labelled)
    tn = sum(not r.flagged and r.expected == "safe" for r in labelled)
    scam_level = sum(r.decision.verdict is Verdict.SCAM and r.expected == "scam" for r in labelled)
    return {
        "total": len(labelled),
        "tp": tp,
        "fp": fp,
        "fn": fn,
        "tn": tn,
        "precision": tp / (tp + fp) if tp + fp else 1.0,
        "recall": tp / (tp + fn) if tp + fn else 1.0,
        "accuracy": (tp + tn) / len(labelled) if labelled else 0.0,
        "scam_level_recall": scam_level / (tp + fn) if tp + fn else 1.0,
    }


def print_console(rows: list[Row], m: dict[str, float]) -> None:
    print(f"{'':2} {'expect':6} {'verdict':14} {'score':>5}  {'scenario':14} text / reasons")
    print("-" * 110)
    for r in rows:
        mark = "✓" if r.correct else "✗"
        d = r.decision
        print(
            f"{mark:2} {r.expected:6} {ICON[d.verdict]} {d.verdict.value:12} {d.score:5.1f}  "
            f"{r.scenario[:14]:14} {r.text[:60]}"
        )
        if d.reason_codes:
            print(f"{'':45}↳ {', '.join(d.reason_codes)}")
    print("-" * 110)
    if m["total"]:
        print(
            f"messages={m['total']:.0f}  caught={m['tp']:.0f}/{m['tp'] + m['fn']:.0f} scams  "
            f"false_alarms={m['fp']:.0f}/{m['fp'] + m['tn']:.0f} safe"
        )
        print(
            f"precision={m['precision']:.2f}  recall={m['recall']:.2f}  "
            f"accuracy={m['accuracy']:.2f}  scam-level recall={m['scam_level_recall']:.2f}"
        )
    misses = [r for r in rows if r.expected in {"scam", "safe"} and not r.correct]
    if misses:
        print("\nMISTAKES:")
        for r in misses:
            print(f"  [{r.expected} → {r.decision.verdict.value}] {r.text}")


def write_html(rows: list[Row], m: dict[str, float], path: Path) -> None:
    def esc(s: str) -> str:
        return html.escape(s).replace("\n", "<br>")

    trs = "\n".join(
        f"<tr class='{'ok' if r.correct else 'bad'}'><td>{'✓' if r.correct else '✗'}</td>"
        f"<td>{esc(r.expected)}</td><td>{ICON[r.decision.verdict]} {r.decision.verdict.value}"
        f"</td><td>{r.decision.score:.1f}</td><td>{esc(r.scenario)}</td><td>{esc(r.text)}"
        f"<div class='codes'>{esc(', '.join(r.decision.reason_codes))}</div></td>"
        f"<td><div class='bubble'>{esc(r.reply)}</div></td></tr>"
        for r in rows
    )
    path.write_text(
        f"""<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><title>Kavach Eval Report</title>
<style>
:root{{--bg:#f6f7f9;--card:#fff;--ink:#1d2329;--muted:#5d6b78;--ok:#e7f6ec;--bad:#fde8e8;
--line:#dfe3e8;--bubble:#dcf8c6}}
@media (prefers-color-scheme:dark){{:root{{--bg:#111418;--card:#1a1f25;--ink:#e6e9ec;
--muted:#9aa6b2;--ok:#16301f;--bad:#3a1a1a;--line:#2b323a;--bubble:#1f3a2a}}}}
body{{margin:0;font:14px/1.45 system-ui,sans-serif;background:var(--bg);color:var(--ink)}}
main{{max-width:1200px;margin:auto;padding:24px 16px}}
.kpis{{display:flex;gap:12px;flex-wrap:wrap;margin:16px 0}}
.kpi{{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:12px 16px}}
.kpi b{{display:block;font-size:22px}} .kpi span{{color:var(--muted);font-size:12px}}
.wrap{{overflow-x:auto}} table{{border-collapse:collapse;width:100%;background:var(--card)}}
td,th{{border-bottom:1px solid var(--line);padding:8px;vertical-align:top;text-align:left}}
tr.ok td:first-child{{background:var(--ok)}} tr.bad td{{background:var(--bad)}}
.codes{{color:var(--muted);font-size:12px;margin-top:4px}}
.bubble{{background:var(--bubble);border-radius:8px;padding:8px;font-size:12.5px;min-width:260px}}
</style></head><body><main><h1>Kavach bot · offline eval</h1>
<div class="kpis">
<div class="kpi"><b>{m["tp"]:.0f}/{m["tp"] + m["fn"]:.0f}</b><span>scams caught</span></div>
<div class="kpi"><b>{m["fp"]:.0f}/{m["fp"] + m["tn"]:.0f}</b><span>false alarms</span></div>
<div class="kpi"><b>{m["precision"]:.2f}</b><span>precision</span></div>
<div class="kpi"><b>{m["recall"]:.2f}</b><span>recall</span></div>
<div class="kpi"><b>{m["scam_level_recall"]:.2f}</b><span>recall at 🚨 SCAM level</span></div>
</div><div class="wrap"><table><tr><th></th><th>expected</th><th>verdict</th><th>score</th>
<th>scenario</th><th>message · reason codes</th><th>bot reply</th></tr>
{trs}</table></div></main></body></html>""",
        encoding="utf-8",
    )


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawTextHelpFormatter)
    ap.add_argument("csv", nargs="?", default="eval/messages.csv")
    ap.add_argument("--text", action="append", help="check ad-hoc text (repeatable)")
    ap.add_argument("--lang", default="hinglish", choices=["hi", "hinglish", "en"])
    ap.add_argument("--html", help="also write an HTML report here")
    ap.add_argument("--openphish", action="store_true", help="load live OpenPhish feed first")
    ap.add_argument("--show-replies", action="store_true", help="print the full bot reply")
    args = ap.parse_args()

    if args.text:
        rows_in = [{"expected": "?", "scenario": "adhoc", "text": t} for t in args.text]
    else:
        with open(args.csv, newline="", encoding="utf-8") as f:
            rows_in = list(csv.DictReader(f))
    rows = asyncio.run(run(rows_in, args.lang, args.openphish))
    m = metrics(rows)
    print_console(rows, m)
    if args.show_replies or args.text:
        for r in rows:
            print("\n" + "=" * 60 + f"\n{r.text}\n" + "-" * 60 + f"\n{r.reply}")
    if args.html:
        write_html(rows, m, Path(args.html))
        print(f"\nHTML report: {Path(args.html).resolve()}")
    if m["total"] and m["fn"] + m["fp"]:
        sys.exit(1)  # non-zero so CI can gate on it


if __name__ == "__main__":
    main()
