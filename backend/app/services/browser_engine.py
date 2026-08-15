"""Playwright browser engine — renders pages with full JS execution and captures evidence."""

from __future__ import annotations

import asyncio
import base64
import logging
import time
from urllib.parse import urlsplit

from app.schemas.active_recon import (
    BrowserCapture,
    ConsoleEntry,
    NetworkEntry,
    StorageEntry,
)

logger = logging.getLogger(__name__)

_PLAYWRIGHT_AVAILABLE = False
try:
    from playwright.async_api import async_playwright, Browser, BrowserContext, Page  # type: ignore[import-untyped]
    _PLAYWRIGHT_AVAILABLE = True
except ImportError:
    pass


def is_available() -> bool:
    return _PLAYWRIGHT_AVAILABLE


async def render_page(
    url: str,
    *,
    headers: dict[str, str] | None = None,
    cookies: dict[str, str] | None = None,
    timeout_ms: int = 15_000,
    allowed_origin: str | None = None,
) -> BrowserCapture:
    """Launch an isolated Chromium context, navigate to *url*, and capture everything.

    Captures: console output, network requests, cookies, localStorage,
    sessionStorage, a DOM snapshot, and a screenshot.
    """
    if not _PLAYWRIGHT_AVAILABLE:
        return BrowserCapture(
            url=url, final_url=url,
            errors=["Playwright is not installed. Run: pip install playwright && playwright install chromium"],
        )

    parts = urlsplit(url)
    origin = f"{parts.scheme}://{parts.netloc}"
    if allowed_origin is None:
        allowed_origin = origin

    console_log: list[ConsoleEntry] = []
    network_log: list[NetworkEntry] = []
    errors: list[str] = []

    started = time.monotonic()

    try:
        async with async_playwright() as pw:
            browser: Browser = await pw.chromium.launch(
                headless=True,
                args=["--no-sandbox", "--disable-gpu", "--disable-dev-shm-usage"],
            )
            context: BrowserContext = await browser.new_context(
                ignore_https_errors=True,
                user_agent="CTFKit-Browser/0.1",
                extra_http_headers=headers or {},
                viewport={"width": 1280, "height": 800},
            )

            # Set cookies if provided
            if cookies:
                cookie_list = []
                for name, value in cookies.items():
                    cookie_list.append({
                        "name": name,
                        "value": value,
                        "domain": parts.hostname or "localhost",
                        "path": "/",
                    })
                await context.add_cookies(cookie_list)

            page: Page = await context.new_page()

            # Console listener
            def on_console(msg: object) -> None:
                try:
                    console_log.append(ConsoleEntry(
                        level=getattr(msg, "type", "log"),
                        text=str(getattr(msg, "text", str(msg)))[:4_000],
                    ))
                except Exception:
                    pass

            page.on("console", on_console)

            # Network listener
            request_times: dict[str, float] = {}

            def on_request(req: object) -> None:
                try:
                    req_url = str(getattr(req, "url", ""))
                    request_times[req_url] = time.monotonic()
                except Exception:
                    pass

            def on_response(resp: object) -> None:
                try:
                    resp_url = str(getattr(resp, "url", ""))
                    req_start = request_times.pop(resp_url, started)
                    elapsed = max(0, round((time.monotonic() - req_start) * 1_000))
                    network_log.append(NetworkEntry(
                        method=str(getattr(getattr(resp, "request", None), "method", "GET")),
                        url=resp_url[:2_000],
                        status_code=getattr(resp, "status", None),
                        content_type=None,
                        elapsed_ms=elapsed,
                    ))
                except Exception:
                    pass

            page.on("request", on_request)
            page.on("response", on_response)

            # Page error listener
            def on_page_error(error: object) -> None:
                errors.append(f"Page error: {str(error)[:500]}")

            page.on("pageerror", on_page_error)

            # Navigate
            try:
                await page.goto(url, wait_until="networkidle", timeout=timeout_ms)
            except Exception as exc:
                try:
                    await page.goto(url, wait_until="domcontentloaded", timeout=timeout_ms)
                except Exception:
                    errors.append(f"Navigation failed: {type(exc).__name__}: {str(exc)[:300]}")

            # Wait a bit for any deferred JS
            await asyncio.sleep(0.5)

            # Get final URL and title
            final_url = page.url
            title = await page.title()

            # DOM snapshot
            try:
                dom_snapshot = await page.content()
                if len(dom_snapshot) > 512_000:
                    dom_snapshot = dom_snapshot[:512_000]
            except Exception:
                dom_snapshot = None

            # Screenshot
            screenshot_b64: str | None = None
            try:
                screenshot_bytes = await page.screenshot(full_page=False, type="png")
                screenshot_b64 = base64.b64encode(screenshot_bytes).decode("ascii")
            except Exception:
                pass

            # Cookies from browser
            storage: list[StorageEntry] = []
            try:
                browser_cookies = await context.cookies()
                for cookie in browser_cookies:
                    storage.append(StorageEntry(
                        storage_type="cookie",
                        key=cookie.get("name", ""),
                        value=cookie.get("value", ""),
                    ))
            except Exception:
                pass

            # localStorage
            try:
                local_storage = await page.evaluate("""() => {
                    const items = {};
                    for (let i = 0; i < localStorage.length; i++) {
                        const key = localStorage.key(i);
                        if (key) items[key] = localStorage.getItem(key) || '';
                    }
                    return items;
                }""")
                for key, value in (local_storage or {}).items():
                    storage.append(StorageEntry(
                        storage_type="localStorage",
                        key=str(key)[:500],
                        value=str(value)[:2_000],
                    ))
            except Exception:
                pass

            # sessionStorage
            try:
                session_storage = await page.evaluate("""() => {
                    const items = {};
                    for (let i = 0; i < sessionStorage.length; i++) {
                        const key = sessionStorage.key(i);
                        if (key) items[key] = sessionStorage.getItem(key) || '';
                    }
                    return items;
                }""")
                for key, value in (session_storage or {}).items():
                    storage.append(StorageEntry(
                        storage_type="sessionStorage",
                        key=str(key)[:500],
                        value=str(value)[:2_000],
                    ))
            except Exception:
                pass

            elapsed = max(0, round((time.monotonic() - started) * 1_000))

            await context.close()
            await browser.close()

            return BrowserCapture(
                url=url,
                final_url=final_url,
                title=title,
                dom_snapshot=dom_snapshot,
                console_log=console_log[:500],
                network_log=network_log[:500],
                storage=storage[:200],
                screenshot_base64=screenshot_b64,
                errors=errors,
                elapsed_ms=elapsed,
            )

    except Exception as exc:
        elapsed = max(0, round((time.monotonic() - started) * 1_000))
        logger.exception("Browser engine error")
        return BrowserCapture(
            url=url, final_url=url,
            errors=[f"Browser engine failed: {type(exc).__name__}: {str(exc)[:300]}"],
            elapsed_ms=elapsed,
        )


async def render_page_with_script(
    url: str,
    inject_script: str,
    *,
    headers: dict[str, str] | None = None,
    cookies: dict[str, str] | None = None,
    timeout_ms: int = 15_000,
) -> tuple[BrowserCapture, list[str]]:
    """Render a page with an injected monitoring script and return captured sink hits.

    The injected script should push findings to window.__CTFKIT_SINKS__.
    Returns a tuple of (BrowserCapture, list of sink hits).
    """
    if not _PLAYWRIGHT_AVAILABLE:
        return BrowserCapture(
            url=url, final_url=url,
            errors=["Playwright is not installed."],
        ), []

    parts = urlsplit(url)
    console_log: list[ConsoleEntry] = []
    network_log: list[NetworkEntry] = []
    errors: list[str] = []
    sink_hits: list[str] = []

    started = time.monotonic()

    try:
        async with async_playwright() as pw:
            browser = await pw.chromium.launch(
                headless=True,
                args=["--no-sandbox", "--disable-gpu", "--disable-dev-shm-usage"],
            )
            context = await browser.new_context(
                ignore_https_errors=True,
                user_agent="CTFKit-XSS-Scanner/0.1",
                extra_http_headers=headers or {},
            )

            if cookies:
                cookie_list = []
                for name, value in cookies.items():
                    cookie_list.append({
                        "name": name,
                        "value": value,
                        "domain": parts.hostname or "localhost",
                        "path": "/",
                    })
                await context.add_cookies(cookie_list)

            # Inject the monitoring script before page loads
            await context.add_init_script(f"""
                window.__CTFKIT_SINKS__ = [];
                {inject_script}
            """)

            page = await context.new_page()

            def on_console(msg: object) -> None:
                try:
                    console_log.append(ConsoleEntry(
                        level=getattr(msg, "type", "log"),
                        text=str(getattr(msg, "text", str(msg)))[:4_000],
                    ))
                except Exception:
                    pass

            page.on("console", on_console)

            try:
                await page.goto(url, wait_until="networkidle", timeout=timeout_ms)
            except Exception:
                try:
                    await page.goto(url, wait_until="domcontentloaded", timeout=timeout_ms)
                except Exception as exc:
                    errors.append(f"Navigation failed: {type(exc).__name__}")

            await asyncio.sleep(0.8)

            # Collect sink hits
            try:
                hits = await page.evaluate("() => window.__CTFKIT_SINKS__ || []")
                if isinstance(hits, list):
                    sink_hits = [str(h)[:2_000] for h in hits[:100]]
            except Exception:
                pass

            final_url = page.url
            title = await page.title()

            try:
                dom = await page.content()
                if len(dom) > 512_000:
                    dom = dom[:512_000]
            except Exception:
                dom = None

            elapsed = max(0, round((time.monotonic() - started) * 1_000))
            await context.close()
            await browser.close()

            capture = BrowserCapture(
                url=url, final_url=final_url, title=title,
                dom_snapshot=dom,
                console_log=console_log[:200],
                network_log=network_log[:200],
                errors=errors,
                elapsed_ms=elapsed,
            )
            return capture, sink_hits

    except Exception as exc:
        elapsed = max(0, round((time.monotonic() - started) * 1_000))
        return BrowserCapture(
            url=url, final_url=url,
            errors=[f"Browser engine failed: {type(exc).__name__}"],
            elapsed_ms=elapsed,
        ), []
