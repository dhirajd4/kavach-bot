"""Sandbox service: the ONLY place that touches user-supplied URLs.

Runs in its own container on an isolated Docker network (internet only: no Postgres, Redis or
API reachable), as a non-root user. It reports *facts* about a page; the worker decides.

    POST /expand {"url": ...}  → redirect chain (HTTP only, no JS, no body download)
    POST /visit  {"url": ...}  → headless Chromium visit: final URL, title, text, form fields,
                                  APK download attempt, JPEG screenshot (base64)

    uvicorn kavach.sandbox.service:app --host 0.0.0.0 --port 8100
"""

import asyncio
import base64
import logging
import re
import time
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from typing import Any

import httpx
from fastapi import FastAPI, HTTPException, Request
from playwright.async_api import Browser, Route, async_playwright
from pydantic import BaseModel, Field

from kavach.apk.extract import run_isolated
from kavach.logs import setup_logging
from kavach.sandbox.expand import UA, expand
from kavach.sandbox.netguard import BlockedURL, check_url

log = logging.getLogger(__name__)

NAV_TIMEOUT_MS = 9_000
SETTLE_MS = 1_500
MAX_CONCURRENT_PAGES = 3
BLOCKED_RESOURCE_TYPES = frozenset({"media", "font", "websocket", "eventsource", "manifest"})

PAGE_FACTS_JS = """
() => {
  const txt = (e) => (e || '').toString().toLowerCase().slice(0, 80);
  const inputs = [...document.querySelectorAll('input, select, textarea')].slice(0, 60)
    .filter((e) => e.type !== 'hidden')
    .map((e) => ({
      type: txt(e.type), name: txt(e.name), id: txt(e.id), placeholder: txt(e.placeholder),
      autocomplete: txt(e.autocomplete),
      label: txt(e.labels && e.labels[0] ? e.labels[0].innerText : e.getAttribute('aria-label')),
    }));
  const forms = [...document.forms].slice(0, 10).map((f) => f.action || '');
  const body = document.body ? document.body.innerText : '';
  return { title: (document.title || '').slice(0, 200), text: body.slice(0, 3000), inputs, forms };
}
"""


class UrlIn(BaseModel):
    url: str = Field(min_length=4, max_length=4000)


state: dict[str, Any] = {}


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    setup_logging()
    pw = await async_playwright().start()
    # Playwright passes --no-sandbox to Chromium inside containers; the container itself
    # (own network, non-root, no secrets, tmpfs) is the isolation boundary.
    browser = await pw.chromium.launch(args=["--disable-dev-shm-usage"])
    state.update(
        pw=pw,
        browser=browser,
        http=httpx.AsyncClient(timeout=5, verify=True),
        sem=asyncio.Semaphore(MAX_CONCURRENT_PAGES),
    )
    yield
    await state["http"].aclose()
    await browser.close()
    await pw.stop()


app = FastAPI(title="Kavach sandbox", lifespan=lifespan, docs_url=None, redoc_url=None)


@app.get("/healthz")
async def healthz() -> dict[str, str]:
    return {"status": "ok"}


@app.post("/expand")
async def expand_url(body: UrlIn) -> dict[str, Any]:
    r = await expand(body.url, state["http"])
    return {
        "chain": r.chain,
        "final_url": r.final_url,
        "status": r.status,
        "apk_download": r.apk_download,
        "error": r.error,
    }


MAX_APK_BYTES = 60 * 1024 * 1024


@app.post("/apk")
async def inspect_apk(request: Request) -> dict[str, Any]:
    """Static facts about an APK (raw bytes in the body). Never installed or executed."""
    data = await request.body()
    if not data or len(data) > MAX_APK_BYTES:
        raise HTTPException(status_code=413)
    facts = await run_isolated(data)
    log.info("apk inspected", extra={"size": len(data), "error": facts.get("error", "")})
    return facts


@app.post("/visit")
async def visit(body: UrlIn) -> dict[str, Any]:
    async with state["sem"]:
        return await _visit(state["browser"], body.url)


async def _visit(browser: Browser, url: str) -> dict[str, Any]:
    started = time.monotonic()
    out: dict[str, Any] = {
        "final_url": url,
        "title": "",
        "text": "",
        "inputs": [],
        "forms": [],
        "apk_download": False,
        "screenshot_b64": "",
        "error": "",
        "ms": 0,
    }
    try:
        await check_url(url)
    except BlockedURL as exc:
        out["error"] = f"blocked: {exc}"
        return out

    context = await browser.new_context(
        user_agent=UA,
        viewport={"width": 412, "height": 860},
        device_scale_factor=1,
        is_mobile=True,
        has_touch=True,
        locale="en-IN",
        accept_downloads=False,
        java_script_enabled=True,
        service_workers="block",
    )
    checked: dict[str, bool] = {}

    async def guard(route: Route) -> None:
        req = route.request
        if req.resource_type in BLOCKED_RESOURCE_TYPES:
            await route.abort()
            return
        host_key = req.url.split("/", 3)[2] if "://" in req.url else req.url
        if host_key not in checked:
            try:
                await check_url(req.url)
                checked[host_key] = True
            except BlockedURL:
                checked[host_key] = False
        if checked[host_key]:
            await route.continue_()
        else:
            await route.abort("blockedbyclient")

    await context.route("**/*", guard)
    page = await context.new_page()

    def on_response(resp: Any) -> None:
        ctype = (resp.headers.get("content-type") or "").lower()
        disp = (resp.headers.get("content-disposition") or "").lower()
        if "android.package-archive" in ctype or ".apk" in disp:
            out["apk_download"] = True

    page.on("response", on_response)
    page.on("download", lambda _d: out.__setitem__("apk_download", True))
    try:
        await page.goto(url, wait_until="domcontentloaded", timeout=NAV_TIMEOUT_MS)
        await page.wait_for_timeout(SETTLE_MS)  # let JS redirects / login forms render
        out["final_url"] = page.url
        out.update(await page.evaluate(PAGE_FACTS_JS))
        shot = await page.screenshot(type="jpeg", quality=60, full_page=False)
        out["screenshot_b64"] = base64.b64encode(shot).decode()
    except Exception as exc:  # noqa: BLE001 - report, never crash the service
        net = re.search(r"net::(ERR_[A-Z_]+)", str(exc))
        out["error"] = f"visit: {net.group(1) if net else type(exc).__name__}"
        if "Download is starting" in str(exc):
            out["apk_download"] = True
    finally:
        await context.close()
        out["ms"] = int((time.monotonic() - started) * 1000)
    log.info("visit done", extra={"ms": out["ms"], "error": out["error"]})
    return out
