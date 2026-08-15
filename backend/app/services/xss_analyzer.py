"""XSS analyzer — detects reflected and DOM-based XSS using canary markers."""

from __future__ import annotations

import html
import logging
import re
import time
from urllib.parse import parse_qsl, urlencode, urljoin, urlsplit, urlunsplit
from uuid import uuid4

import httpx

from app.schemas.active_recon import XssFinding, XssScanResult
from app.services import browser_engine

logger = logging.getLogger(__name__)

# Canary prefix to avoid collisions with page content
_CANARY_PREFIX = "CTFKIT"

# DOM sink monitoring script injected into the browser context
_DOM_SINK_MONITOR = r"""
(function() {
    const CANARY_RE = /CTFKIT_[a-f0-9]{8}/gi;

    // Monitor innerHTML setter
    const origInnerHTML = Object.getOwnPropertyDescriptor(Element.prototype, 'innerHTML');
    if (origInnerHTML && origInnerHTML.set) {
        Object.defineProperty(Element.prototype, 'innerHTML', {
            set: function(val) {
                const str = String(val);
                const matches = str.match(CANARY_RE);
                if (matches) {
                    matches.forEach(m => {
                        window.__CTFKIT_SINKS__.push('innerHTML:' + m + ':' + str.substring(0, 200));
                    });
                }
                return origInnerHTML.set.call(this, val);
            },
            get: origInnerHTML.get,
            configurable: true,
        });
    }

    // Monitor document.write
    const origWrite = document.write;
    document.write = function(content) {
        const str = String(content);
        const matches = str.match(CANARY_RE);
        if (matches) {
            matches.forEach(m => {
                window.__CTFKIT_SINKS__.push('document.write:' + m + ':' + str.substring(0, 200));
            });
        }
        return origWrite.apply(this, arguments);
    };

    // Monitor eval
    const origEval = window.eval;
    window.eval = function(code) {
        const str = String(code);
        const matches = str.match(CANARY_RE);
        if (matches) {
            matches.forEach(m => {
                window.__CTFKIT_SINKS__.push('eval:' + m + ':' + str.substring(0, 200));
            });
        }
        return origEval.apply(this, arguments);
    };

    // Monitor setTimeout / setInterval with string args
    const origSetTimeout = window.setTimeout;
    window.setTimeout = function(fn, delay) {
        if (typeof fn === 'string') {
            const matches = fn.match(CANARY_RE);
            if (matches) {
                matches.forEach(m => {
                    window.__CTFKIT_SINKS__.push('setTimeout:' + m + ':' + fn.substring(0, 200));
                });
            }
        }
        return origSetTimeout.apply(this, arguments);
    };

    const origSetInterval = window.setInterval;
    window.setInterval = function(fn, delay) {
        if (typeof fn === 'string') {
            const matches = fn.match(CANARY_RE);
            if (matches) {
                matches.forEach(m => {
                    window.__CTFKIT_SINKS__.push('setInterval:' + m + ':' + fn.substring(0, 200));
                });
            }
        }
        return origSetInterval.apply(this, arguments);
    };

    // Monitor location assignments
    const origAssign = Location.prototype.assign;
    if (origAssign) {
        Location.prototype.assign = function(url) {
            const str = String(url);
            const matches = str.match(CANARY_RE);
            if (matches) {
                matches.forEach(m => {
                    window.__CTFKIT_SINKS__.push('location.assign:' + m + ':' + str.substring(0, 200));
                });
            }
            return origAssign.apply(this, arguments);
        };
    }
})();
"""


def _generate_canary() -> str:
    """Generate a unique canary string like CTFKIT_a1b2c3d4."""
    return f"{_CANARY_PREFIX}_{uuid4().hex[:8]}"


def _determine_context(body: str, canary: str) -> str | None:
    """Determine in what HTML context the canary appears."""
    idx = body.find(canary)
    if idx < 0:
        return None

    # Look at surrounding content to determine context
    before = body[max(0, idx - 200):idx].lower()
    after = body[idx:idx + len(canary) + 200].lower()

    # Inside a <script> tag?
    last_script_open = before.rfind("<script")
    last_script_close = before.rfind("</script")
    if last_script_open > last_script_close:
        return "script"

    # Inside an HTML comment?
    last_comment_open = before.rfind("<!--")
    last_comment_close = before.rfind("-->")
    if last_comment_open > last_comment_close:
        return "comment"

    # Inside an HTML attribute?
    # Look for patterns like: attr="...CANARY..." or attr='...CANARY...'
    for quote in ('"', "'"):
        last_eq_quote = before.rfind(f"={quote}")
        if last_eq_quote >= 0:
            # Check there's no closing quote between the opening and the canary
            between = before[last_eq_quote + 2:]
            if quote not in between:
                return "html_attr"

    # Inside a URL context (href, src, action)?
    url_attrs = ("href=", "src=", "action=", "data=", "formaction=")
    for attr in url_attrs:
        if attr in before[-80:]:
            return "url"

    return "html_body"


def _build_suggestion(context: str | None) -> str:
    """Return a suggested payload type based on injection context."""
    suggestions = {
        "html_body": "Try: <img src=x onerror=alert(1)> or <script>alert(1)</script>",
        "html_attr": "Try: \" onmouseover=alert(1) \" or ' onfocus=alert(1) autofocus '",
        "script": "Try: ';alert(1);// or \";alert(1);//",
        "comment": "Try: --><script>alert(1)</script><!--",
        "url": "Try: javascript:alert(1) or data:text/html,<script>alert(1)</script>",
        "dom_sink": "The canary reached a dangerous DOM sink — likely DOM XSS.",
    }
    return suggestions.get(context or "", "Injection context could not be determined.")


async def scan_reflected_xss(
    url: str,
    parameters: list[str],
    *,
    headers: dict[str, str] | None = None,
    cookies: dict[str, str] | None = None,
    timeout_ms: int = 8_000,
) -> list[XssFinding]:
    """Test each parameter for reflected XSS by injecting canary strings via httpx."""
    findings: list[XssFinding] = []
    per_timeout = timeout_ms / 1_000

    parts = urlsplit(url)
    existing_params = dict(parse_qsl(parts.query, keep_blank_values=True))

    req_headers = {"User-Agent": "CTFKit-XSS/0.1", "Accept": "*/*"}
    if headers:
        req_headers.update(headers)
    if cookies:
        req_headers["Cookie"] = "; ".join(f"{k}={v}" for k, v in cookies.items())

    async with httpx.AsyncClient(
        timeout=httpx.Timeout(per_timeout),
        follow_redirects=True,
        trust_env=False,
        limits=httpx.Limits(max_connections=5, max_keepalive_connections=2),
    ) as client:
        for param in parameters[:50]:  # Cap at 50 parameters
            canary = _generate_canary()

            # Inject canary into the parameter
            test_params = dict(existing_params)
            test_params[param] = canary
            test_query = urlencode(test_params)
            test_url = urlunsplit((parts.scheme, parts.netloc, parts.path, test_query, ""))

            try:
                response = await client.get(test_url, headers=req_headers)
                body = response.text[:512_000]

                # Check if canary is reflected
                if canary in body:
                    context = _determine_context(body, canary)

                    # Check if it's reflected unescaped (potential XSS)
                    escaped_canary = html.escape(canary)
                    is_unescaped = canary in body and escaped_canary != canary

                    # Determine severity
                    if context in ("script", "html_attr", "url"):
                        severity = "high"
                    elif context == "html_body":
                        severity = "medium"
                    else:
                        severity = "low"

                    # Get evidence snippet
                    idx = body.find(canary)
                    evidence_start = max(0, idx - 50)
                    evidence_end = min(len(body), idx + len(canary) + 50)
                    evidence = body[evidence_start:evidence_end]

                    findings.append(XssFinding(
                        finding_type="reflected",
                        severity=severity,
                        parameter=param,
                        url=test_url,
                        canary=canary,
                        injection_context=context,
                        evidence=evidence[:500],
                        suggestion=_build_suggestion(context),
                    ))

            except (httpx.HTTPError, Exception) as exc:
                logger.debug("XSS test failed for param %s: %s", param, exc)
                continue

    return findings


async def scan_dom_xss(
    url: str,
    parameters: list[str],
    *,
    headers: dict[str, str] | None = None,
    cookies: dict[str, str] | None = None,
    browser_timeout_ms: int = 15_000,
) -> list[XssFinding]:
    """Test each parameter for DOM-based XSS using a browser with sink monitoring."""
    if not browser_engine.is_available():
        return []

    findings: list[XssFinding] = []
    parts = urlsplit(url)
    existing_params = dict(parse_qsl(parts.query, keep_blank_values=True))

    for param in parameters[:20]:  # Cap at 20 for browser-based tests
        canary = _generate_canary()

        # Test via query parameter
        test_params = dict(existing_params)
        test_params[param] = canary
        test_query = urlencode(test_params)
        test_url = urlunsplit((parts.scheme, parts.netloc, parts.path, test_query, ""))

        capture, sink_hits = await browser_engine.render_page_with_script(
            test_url,
            _DOM_SINK_MONITOR,
            headers=headers,
            cookies=cookies,
            timeout_ms=browser_timeout_ms,
        )

        # Check sink hits for our canary
        for hit in sink_hits:
            parts_hit = hit.split(":", 2)
            if len(parts_hit) >= 2 and canary in hit:
                sink_name = parts_hit[0]
                evidence = parts_hit[2] if len(parts_hit) > 2 else ""

                findings.append(XssFinding(
                    finding_type="dom",
                    severity="high",
                    parameter=param,
                    url=test_url,
                    canary=canary,
                    injection_context="dom_sink",
                    dom_sink=sink_name,
                    evidence=evidence[:500],
                    suggestion=_build_suggestion("dom_sink"),
                ))

        # Also check the rendered DOM for the canary
        if capture.dom_snapshot and canary in capture.dom_snapshot:
            context = _determine_context(capture.dom_snapshot, canary)
            # Only add if we didn't already find it in sinks
            if not any(f.parameter == param and f.finding_type == "dom" for f in findings):
                findings.append(XssFinding(
                    finding_type="dom",
                    severity="medium" if context == "html_body" else "high",
                    parameter=param,
                    url=test_url,
                    canary=canary,
                    injection_context=context,
                    evidence=f"Canary found in rendered DOM in {context} context",
                    suggestion=_build_suggestion(context),
                ))

        # Test via URL fragment (hash)
        fragment_url = f"{url}#{canary}"
        capture_frag, sink_hits_frag = await browser_engine.render_page_with_script(
            fragment_url,
            _DOM_SINK_MONITOR,
            headers=headers,
            cookies=cookies,
            timeout_ms=browser_timeout_ms,
        )

        for hit in sink_hits_frag:
            if canary in hit:
                parts_hit = hit.split(":", 2)
                sink_name = parts_hit[0] if parts_hit else "unknown"
                evidence = parts_hit[2] if len(parts_hit) > 2 else ""

                findings.append(XssFinding(
                    finding_type="dom",
                    severity="high",
                    parameter=f"URL fragment (#{param})",
                    url=fragment_url,
                    canary=canary,
                    injection_context="dom_sink",
                    dom_sink=sink_name,
                    evidence=evidence[:500],
                    suggestion="DOM XSS via URL hash — the fragment is processed by client-side JavaScript.",
                ))
                break  # One finding per fragment test is enough

    return findings


async def run_xss_scan(
    url: str,
    parameters: list[str],
    *,
    headers: dict[str, str] | None = None,
    cookies: dict[str, str] | None = None,
    timeout_ms: int = 8_000,
    browser_timeout_ms: int = 15_000,
    enable_dom: bool = True,
) -> XssScanResult:
    """Run both reflected and DOM-based XSS scanning."""
    started = time.monotonic()

    reflected = await scan_reflected_xss(
        url, parameters,
        headers=headers, cookies=cookies, timeout_ms=timeout_ms,
    )

    dom_findings: list[XssFinding] = []
    if enable_dom and browser_engine.is_available():
        dom_findings = await scan_dom_xss(
            url, parameters,
            headers=headers, cookies=cookies,
            browser_timeout_ms=browser_timeout_ms,
        )

    all_findings = reflected + dom_findings

    elapsed = max(0, round((time.monotonic() - started) * 1_000))

    return XssScanResult(
        findings=all_findings,
        parameters_tested=len(parameters),
        total_reflected=sum(1 for f in all_findings if f.finding_type == "reflected"),
        total_dom=sum(1 for f in all_findings if f.finding_type == "dom"),
        elapsed_ms=elapsed,
    )
