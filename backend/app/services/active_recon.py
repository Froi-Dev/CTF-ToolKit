"""Active recon service — orchestrates crawling, dir busting, param fuzzing, browser, XSS, and flag detection."""

from __future__ import annotations

import asyncio
import ipaddress
import logging
import re
import socket
import time
from collections import deque
from datetime import datetime, timezone
from difflib import SequenceMatcher
from html.parser import HTMLParser
from urllib.parse import parse_qsl, urlencode, urljoin, urlsplit, urlunsplit
from uuid import uuid4

import httpx
from anyio import to_thread

from app.core.errors import UnsafeWebTargetError, WebRequestError
from app.schemas.active_recon import (
    ActiveReconResponse,
    BrowserCapture,
    CrawledForm,
    CrawledPage,
    CrawlResult,
    DirBustEntry,
    DirBustResult,
    FlagResult,
    FormInput,
    ParamFuzzEntry,
    ParamFuzzResult,
    ScanProgress,
    XssScanResult,
)
from app.services import browser_engine
from app.services.flag_detector import FlagDetector, _TextSource
from app.services.xss_analyzer import run_xss_scan

logger = logging.getLogger(__name__)

MAX_RESPONSE_BYTES = 512 * 1024
_BLOCKED_METADATA = {ipaddress.ip_address("169.254.169.254"), ipaddress.ip_address("100.100.100.200")}

# Built-in wordlists
_WORDLIST_SMALL = [
    "admin", "login", "dashboard", "api", "config", "backup", "test",
    "wp-admin", "wp-login.php", "robots.txt", "sitemap.xml", ".env",
    ".git", ".git/config", ".git/HEAD", ".htaccess", ".htpasswd",
    "server-status", "server-info", "phpinfo.php", "info.php",
    "flag", "flag.txt", "secret", "secret.txt", "debug", "console",
    "shell", "upload", "uploads", "files", "images", "static",
    "css", "js", "assets", "media", "tmp", "temp", "logs", "log",
    "database", "db", "sql", "dump", "data", "user", "users",
    "password", "passwd", "credentials", "auth", "token", "session",
    "private", "internal", "hidden", "dev", "development", "staging",
    "production", "beta", "alpha", "old", "new", "v1", "v2", "api/v1",
    "api/v2", "graphql", "swagger", "docs", "documentation",
    "readme", "README.md", "LICENSE", "CHANGELOG", "TODO",
    "wp-content", "wp-includes", "wp-config.php", "xmlrpc.php",
    "administrator", "panel", "cpanel", "phpmyadmin", "adminer",
    "manage", "manager", "portal", "gateway", "proxy", "cgi-bin",
    "bin", "include", "includes", "lib", "vendor", "node_modules",
    "package.json", "composer.json", "Gemfile", "requirements.txt",
    ".svn", ".svn/entries", ".DS_Store", "Thumbs.db", "web.config",
    "crossdomain.xml", "clientaccesspolicy.xml", ".well-known",
    "security.txt", ".well-known/security.txt", "humans.txt",
    "status", "health", "healthcheck", "ping", "version",
    "register", "signup", "sign-up", "forgot", "reset", "verify",
    "confirm", "profile", "account", "settings", "preferences",
    "search", "filter", "export", "import", "download", "report",
    "callback", "webhook", "hook", "notify", "notification",
    "socket", "ws", "websocket", "feed", "rss", "atom",
    "archive", "archives", "blog", "post", "posts", "page", "pages",
    "category", "tag", "comment", "comments", "review", "reviews",
]

_WORDLIST_COMMON = _WORDLIST_SMALL + [
    "access", "about", "contact", "help", "support", "faq",
    "terms", "privacy", "policy", "legal", "disclaimer",
    "sitemap", "map", "index", "home", "main", "default",
    "error", "404", "500", "403", "maintenance",
    "install", "setup", "init", "initialize", "migrate",
    "cron", "job", "jobs", "task", "tasks", "queue", "worker",
    "cache", "redis", "memcached", "elasticsearch", "solr",
    "smtp", "mail", "email", "newsletter", "subscribe",
    "oauth", "oauth2", "sso", "saml", "ldap", "cas",
    "payment", "checkout", "cart", "order", "orders", "invoice",
    "product", "products", "catalog", "shop", "store",
    "image", "img", "photo", "photos", "gallery", "album",
    "video", "videos", "audio", "music", "podcast",
    "file", "document", "documents", "doc", "pdf", "csv",
    "xml", "json", "yaml", "yml", "toml", "ini", "cfg",
    "backup.sql", "backup.zip", "backup.tar.gz", "backup.tar",
    "database.sql", "dump.sql", "db.sql", "data.sql",
    ".env.local", ".env.production", ".env.development",
    ".env.staging", ".env.test", ".env.example", ".env.sample",
    "docker-compose.yml", "Dockerfile", "Makefile", "Vagrantfile",
    "Procfile", "Jenkinsfile", ".travis.yml", ".gitlab-ci.yml",
    "app.py", "main.py", "server.py", "index.php", "index.jsp",
    "index.asp", "index.aspx", "default.asp", "default.aspx",
    "web.xml", "pom.xml", "build.gradle", "build.xml",
    "wp-config.php.bak", "config.php", "config.php.bak",
    "configuration.php", "settings.php", "local.php",
    "actuator", "actuator/health", "actuator/info", "actuator/env",
    "metrics", "monitor", "monitoring", "trace", "traces",
    "admin.php", "login.php", "register.php", "auth.php",
    "filemanager", "elfinder", "ckfinder", "tinymce",
]

_WORDLIST_MEDIUM = _WORDLIST_COMMON  # Can be extended with a larger wordlist


def _get_wordlist(name: str) -> list[str]:
    if name == "small":
        return _WORDLIST_SMALL
    if name == "common":
        return _WORDLIST_COMMON
    return _WORDLIST_MEDIUM


def _origin(url: str) -> tuple[str, str, int]:
    parts = urlsplit(url)
    port = parts.port or (443 if parts.scheme == "https" else 80)
    return parts.scheme.lower(), (parts.hostname or "").lower(), port


def _clean_url(url: str) -> str:
    parts = urlsplit(url)
    return urlunsplit((parts.scheme.lower(), parts.netloc, parts.path or "/", parts.query, ""))


def _is_prohibited(address: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    return address in _BLOCKED_METADATA or address.is_unspecified or address.is_multicast or address.is_link_local


async def _resolve_and_validate(url: str) -> None:
    """Validate that the URL is safe to connect to."""
    parts = urlsplit(url)
    if parts.scheme not in {"http", "https"} or not parts.hostname:
        raise UnsafeWebTargetError("Only absolute HTTP and HTTPS targets are supported.")
    host = parts.hostname.rstrip(".")
    try:
        literal = ipaddress.ip_address(host)
        addresses = [literal]
    except ValueError:
        try:
            records = await to_thread.run_sync(
                socket.getaddrinfo, host, parts.port or (443 if parts.scheme == "https" else 80), 0, socket.SOCK_STREAM
            )
        except socket.gaierror as exc:
            raise WebRequestError("The target hostname could not be resolved.") from exc
        addresses = []
        for record in records:
            try:
                addresses.append(ipaddress.ip_address(record[4][0]))
            except (ValueError, IndexError):
                continue
    if not addresses:
        raise WebRequestError("The target hostname did not resolve to an address.")
    if any(_is_prohibited(a) for a in addresses):
        raise UnsafeWebTargetError("Link-local, metadata, multicast, and unspecified destinations are blocked.")


# ---------------------------------------------------------------------------
# Simple HTML parser for crawling
# ---------------------------------------------------------------------------

class _CrawlParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.links: list[str] = []
        self.forms: list[CrawledForm] = []
        self.title: str | None = None
        self._form_action: str = ""
        self._form_method: str = "GET"
        self._form_inputs: list[FormInput] = []
        self._in_form = False
        self._in_title = False
        self._title_parts: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        values = {n.lower(): v or "" for n, v in attrs}
        tag = tag.lower()
        if tag in {"a", "link"}:
            href = values.get("href", "")
            if href and not href.startswith(("#", "javascript:", "mailto:", "data:")):
                self.links.append(href)
        elif tag == "form":
            self._in_form = True
            self._form_action = values.get("action", "")
            self._form_method = values.get("method", "GET").upper()
            self._form_inputs = []
        elif tag in {"input", "textarea", "select"} and self._in_form:
            name = values.get("name", "").strip()
            if name:
                self._form_inputs.append(FormInput(
                    name=name,
                    input_type=values.get("type", tag).lower(),
                    value=values.get("value"),
                ))
        elif tag == "title":
            self._in_title = True
            self._title_parts = []
        elif tag == "iframe":
            src = values.get("src", "")
            if src and not src.startswith(("javascript:", "data:", "about:")):
                self.links.append(src)

    def handle_endtag(self, tag: str) -> None:
        if tag.lower() == "form" and self._in_form:
            self._in_form = False
            self.forms.append(CrawledForm(
                action=self._form_action,
                method=self._form_method,
                inputs=self._form_inputs,
            ))
        elif tag.lower() == "title" and self._in_title:
            self._in_title = False
            self.title = "".join(self._title_parts).strip()[:500]

    def handle_data(self, data: str) -> None:
        if self._in_title:
            self._title_parts.append(data)


# ---------------------------------------------------------------------------
# Crawler
# ---------------------------------------------------------------------------

async def crawl(
    base_url: str,
    *,
    depth: int = 3,
    max_pages: int = 50,
    headers: dict[str, str] | None = None,
    cookies: dict[str, str] | None = None,
    timeout_ms: int = 8_000,
) -> CrawlResult:
    """Same-origin recursive crawl with bounded depth and page limits."""
    started = time.monotonic()
    target = _clean_url(str(base_url))
    await _resolve_and_validate(target)

    base_origin = _origin(target)
    visited: set[str] = set()
    pages: list[CrawledPage] = []
    queue: deque[tuple[str, int]] = deque([(target, 0)])

    req_headers = {"User-Agent": "CTFKit-Crawler/0.1", "Accept": "text/html,*/*"}
    if headers:
        req_headers.update(headers)
    if cookies:
        req_headers["Cookie"] = "; ".join(f"{k}={v}" for k, v in cookies.items())

    per_timeout = timeout_ms / 1_000

    async with httpx.AsyncClient(
        timeout=httpx.Timeout(per_timeout),
        follow_redirects=True,
        trust_env=False,
        limits=httpx.Limits(max_connections=5, max_keepalive_connections=2),
    ) as client:
        while queue and len(pages) < max_pages:
            url, current_depth = queue.popleft()
            clean = _clean_url(url)

            if clean in visited:
                continue
            if _origin(clean) != base_origin:
                continue
            if current_depth > depth:
                continue

            visited.add(clean)

            try:
                await _resolve_and_validate(clean)
                req_start = time.monotonic()
                response = await client.get(clean, headers=req_headers)
                elapsed = max(0, round((time.monotonic() - req_start) * 1_000))
            except (httpx.HTTPError, UnsafeWebTargetError, WebRequestError) as exc:
                logger.debug("Crawl failed for %s: %s", clean, exc)
                continue

            content_type = response.headers.get("content-type", "")
            body = response.text[:MAX_RESPONSE_BYTES]

            parser = _CrawlParser()
            if "html" in content_type.lower() or body.lstrip().lower().startswith(("<!doctype", "<html")):
                try:
                    parser.feed(body)
                except Exception:
                    pass

            # Collect discovered links
            discovered_links: list[str] = []
            for link in parser.links:
                absolute = _clean_url(urljoin(clean, link))
                if _origin(absolute) == base_origin and absolute not in visited:
                    discovered_links.append(absolute)
                    if current_depth + 1 <= depth and len(visited) + len(queue) < max_pages * 2:
                        queue.append((absolute, current_depth + 1))

            # Collect parameters from forms and query strings
            all_params: list[str] = []
            for form in parser.forms:
                all_params.extend(inp.name for inp in form.inputs)
            parts = urlsplit(clean)
            all_params.extend(name for name, _ in parse_qsl(parts.query, keep_blank_values=True))
            all_params = list(dict.fromkeys(all_params))

            pages.append(CrawledPage(
                url=clean,
                status_code=response.status_code,
                content_type=content_type.split(";")[0].strip() if content_type else None,
                title=parser.title,
                size=len(response.content),
                depth=current_depth,
                links=discovered_links[:100],
                forms=parser.forms[:20],
                parameters=all_params[:50],
                elapsed_ms=elapsed,
            ))

    elapsed_total = max(0, round((time.monotonic() - started) * 1_000))
    max_depth_reached = max((p.depth for p in pages), default=0)
    total_forms = sum(len(p.forms) for p in pages)
    total_links = sum(len(p.links) for p in pages)

    return CrawlResult(
        pages=pages,
        total_pages=len(pages),
        max_depth_reached=max_depth_reached,
        total_forms=total_forms,
        total_links=total_links,
        elapsed_ms=elapsed_total,
    )


# ---------------------------------------------------------------------------
# Directory buster
# ---------------------------------------------------------------------------

async def dirbust(
    base_url: str,
    *,
    wordlist: str = "small",
    extensions: list[str] | None = None,
    concurrency: int = 10,
    status_filter: list[int] | None = None,
    rate_limit_rps: float = 10.0,
    headers: dict[str, str] | None = None,
    cookies: dict[str, str] | None = None,
    timeout_ms: int = 8_000,
) -> DirBustResult:
    """Rate-limited directory and file discovery."""
    started = time.monotonic()
    target = _clean_url(str(base_url))
    await _resolve_and_validate(target)

    parts = urlsplit(target)
    base_path = parts.path.rstrip("/") if parts.path else ""
    base_no_path = urlunsplit((parts.scheme, parts.netloc, "", "", ""))

    exts = extensions or [".php", ".html", ".txt", ".bak"]
    filter_codes = set(status_filter or [200, 201, 204, 301, 302, 307, 401, 403])
    words = _get_wordlist(wordlist)

    # Generate all paths to test
    test_paths: list[str] = []
    for word in words:
        test_paths.append(f"{base_path}/{word}")
        for ext in exts:
            if not word.endswith(ext):
                test_paths.append(f"{base_path}/{word}{ext}")

    req_headers = {"User-Agent": "CTFKit-DirBust/0.1", "Accept": "*/*"}
    if headers:
        req_headers.update(headers)
    if cookies:
        req_headers["Cookie"] = "; ".join(f"{k}={v}" for k, v in cookies.items())

    per_timeout = timeout_ms / 1_000
    entries: list[DirBustEntry] = []
    total_tested = 0
    semaphore = asyncio.Semaphore(concurrency)
    interval = 1.0 / rate_limit_rps if rate_limit_rps > 0 else 0

    # Get baseline 404 response for comparison
    baseline_body = ""
    try:
        async with httpx.AsyncClient(
            timeout=httpx.Timeout(per_timeout),
            follow_redirects=False,
            trust_env=False,
        ) as client:
            baseline_resp = await client.get(
                f"{base_no_path}{base_path}/CTFKIT_BASELINE_404_{uuid4().hex[:8]}",
                headers=req_headers,
            )
            baseline_body = baseline_resp.text[:10_000]
    except Exception:
        pass

    async def test_path(path: str, client: httpx.AsyncClient) -> DirBustEntry | None:
        nonlocal total_tested
        async with semaphore:
            if interval > 0:
                await asyncio.sleep(interval)

            test_url = f"{base_no_path}{path}"
            try:
                req_start = time.monotonic()
                response = await client.get(test_url, headers=req_headers)
                elapsed = max(0, round((time.monotonic() - req_start) * 1_000))
                total_tested += 1

                if response.status_code not in filter_codes:
                    return None

                # Skip if response matches 404 baseline
                if baseline_body and response.status_code == 200:
                    similarity = SequenceMatcher(None, baseline_body[:5_000], response.text[:5_000]).ratio()
                    if similarity > 0.95:
                        return None

                redirect_url = None
                if response.status_code in {301, 302, 307, 308}:
                    redirect_url = response.headers.get("location")

                return DirBustEntry(
                    path=path,
                    url=test_url,
                    status_code=response.status_code,
                    content_type=response.headers.get("content-type", "").split(";")[0].strip() or None,
                    size=len(response.content),
                    redirect_url=redirect_url,
                    elapsed_ms=elapsed,
                )
            except (httpx.HTTPError, Exception):
                total_tested += 1
                return None

    async with httpx.AsyncClient(
        timeout=httpx.Timeout(per_timeout),
        follow_redirects=False,
        trust_env=False,
        limits=httpx.Limits(max_connections=concurrency + 2, max_keepalive_connections=concurrency),
    ) as client:
        tasks = [test_path(path, client) for path in test_paths]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        for result in results:
            if isinstance(result, DirBustEntry):
                entries.append(result)

    entries.sort(key=lambda e: (e.status_code, e.path))
    elapsed_total = max(0, round((time.monotonic() - started) * 1_000))

    return DirBustResult(
        entries=entries[:1_000],
        total_tested=total_tested,
        total_found=len(entries),
        wordlist_used=wordlist,
        extensions_used=exts,
        elapsed_ms=elapsed_total,
    )


# ---------------------------------------------------------------------------
# Parameter fuzzer
# ---------------------------------------------------------------------------

async def fuzz_parameters(
    url: str,
    parameters: list[str],
    *,
    headers: dict[str, str] | None = None,
    cookies: dict[str, str] | None = None,
    timeout_ms: int = 8_000,
) -> ParamFuzzResult:
    """Test each parameter with a unique canary and detect reflections."""
    started = time.monotonic()
    parts = urlsplit(url)
    existing_params = dict(parse_qsl(parts.query, keep_blank_values=True))

    req_headers = {"User-Agent": "CTFKit-Fuzzer/0.1", "Accept": "*/*"}
    if headers:
        req_headers.update(headers)
    if cookies:
        req_headers["Cookie"] = "; ".join(f"{k}={v}" for k, v in cookies.items())

    per_timeout = timeout_ms / 1_000
    entries: list[ParamFuzzEntry] = []

    # Get baseline response
    async with httpx.AsyncClient(
        timeout=httpx.Timeout(per_timeout),
        follow_redirects=True,
        trust_env=False,
        limits=httpx.Limits(max_connections=5, max_keepalive_connections=2),
    ) as client:
        baseline_body = ""
        try:
            baseline_resp = await client.get(url, headers=req_headers)
            baseline_body = baseline_resp.text[:100_000]
        except Exception:
            pass

        for param in parameters[:50]:
            canary = f"CTFKIT_{uuid4().hex[:8]}"

            test_params = dict(existing_params)
            test_params[param] = canary
            test_query = urlencode(test_params)
            test_url = urlunsplit((parts.scheme, parts.netloc, parts.path, test_query, ""))

            try:
                response = await client.get(test_url, headers=req_headers)
                body = response.text[:512_000]

                reflected = canary in body
                context: str | None = None
                if reflected:
                    # Determine reflection context
                    idx = body.find(canary)
                    before = body[max(0, idx - 200):idx].lower()

                    if "<script" in before and "</script" not in before[before.rfind("<script"):]:
                        context = "script"
                    elif "<!--" in before and "-->" not in before[before.rfind("<!--"):]:
                        context = "comment"
                    elif any(f'{q}' not in before[before.rfind("="):] for q in ('"', "'") if "=" in before[-80:]):
                        context = "html_attr"
                    else:
                        context = "html_body"

                similarity = SequenceMatcher(None, baseline_body[:50_000], body[:50_000]).ratio() if baseline_body else 1.0

                entries.append(ParamFuzzEntry(
                    parameter=param,
                    url=test_url,
                    canary=canary,
                    reflected=reflected,
                    reflection_context=context,
                    response_status=response.status_code,
                    response_size=len(response.content),
                    baseline_similarity=round(similarity, 4),
                ))
            except (httpx.HTTPError, Exception):
                continue

    elapsed = max(0, round((time.monotonic() - started) * 1_000))
    return ParamFuzzResult(
        entries=entries,
        total_tested=len(entries),
        total_reflected=sum(1 for e in entries if e.reflected),
        elapsed_ms=elapsed,
    )


# ---------------------------------------------------------------------------
# Full active recon orchestrator
# ---------------------------------------------------------------------------

# In-memory scan storage
_active_scans: dict[str, ScanProgress] = {}
_scan_results: dict[str, ActiveReconResponse] = {}


def get_scan_progress(scan_id: str) -> ScanProgress | None:
    return _active_scans.get(scan_id)


def get_scan_result(scan_id: str) -> ActiveReconResponse | None:
    return _scan_results.get(scan_id)


async def run_active_recon(
    url: str,
    *,
    target_scope: str = "ctf",
    # Crawl
    enable_crawl: bool = True,
    crawl_depth: int = 3,
    crawl_max_pages: int = 50,
    # Dir bust
    enable_dirbust: bool = True,
    dirbust_wordlist: str = "small",
    dirbust_extensions: list[str] | None = None,
    dirbust_concurrency: int = 10,
    dirbust_status_filter: list[int] | None = None,
    rate_limit_rps: float = 10.0,
    # Param fuzz
    enable_param_fuzz: bool = True,
    # Browser
    enable_browser: bool = True,
    browser_timeout_ms: int = 15_000,
    # XSS
    enable_xss: bool = True,
    # Flags
    flag_patterns: list[str] | None = None,
    # General
    headers: dict[str, str] | None = None,
    cookies: dict[str, str] | None = None,
    timeout_ms: int = 8_000,
) -> ActiveReconResponse:
    """Run a complete active recon scan with all enabled modules."""
    scan_id = str(uuid4())
    started = time.monotonic()
    started_at = datetime.now(timezone.utc)
    warnings: list[str] = []

    target = _clean_url(str(url))
    await _resolve_and_validate(target)

    progress = ScanProgress(scan_id=scan_id, status="running", phase="initializing")
    _active_scans[scan_id] = progress

    flag_detector = FlagDetector(flag_patterns)
    flag_sources: list[_TextSource] = []

    # --- Phase 1: Crawl ---
    crawl_result: CrawlResult | None = None
    all_parameters: list[str] = []

    if enable_crawl:
        progress.phase = "crawling"
        try:
            crawl_result = await crawl(
                target, depth=crawl_depth, max_pages=crawl_max_pages,
                headers=headers, cookies=cookies, timeout_ms=timeout_ms,
            )
            progress.pages_crawled = crawl_result.total_pages

            # Collect parameters from crawl
            for page in crawl_result.pages:
                all_parameters.extend(page.parameters)
                # Scan page content for flags (we don't have the body here, but we have URLs)
                flag_sources.append(_TextSource(text=page.url, source="crawled_url", url=page.url))

        except Exception as exc:
            warnings.append(f"Crawl failed: {type(exc).__name__}: {str(exc)[:200]}")

    all_parameters = list(dict.fromkeys(all_parameters))

    # --- Phase 2: Directory busting ---
    dirbust_result: DirBustResult | None = None

    if enable_dirbust:
        progress.phase = "directory_busting"
        try:
            dirbust_result = await dirbust(
                target, wordlist=dirbust_wordlist,
                extensions=dirbust_extensions, concurrency=dirbust_concurrency,
                status_filter=dirbust_status_filter, rate_limit_rps=rate_limit_rps,
                headers=headers, cookies=cookies, timeout_ms=timeout_ms,
            )
            progress.paths_tested = dirbust_result.total_tested

            for entry in dirbust_result.entries:
                flag_sources.append(_TextSource(text=entry.path, source="dirbust_path", url=entry.url))

        except Exception as exc:
            warnings.append(f"Dir busting failed: {type(exc).__name__}: {str(exc)[:200]}")

    # --- Phase 3: Parameter fuzzing ---
    fuzz_result: ParamFuzzResult | None = None

    if enable_param_fuzz and all_parameters:
        progress.phase = "parameter_fuzzing"
        try:
            fuzz_result = await fuzz_parameters(
                target, all_parameters,
                headers=headers, cookies=cookies, timeout_ms=timeout_ms,
            )
        except Exception as exc:
            warnings.append(f"Parameter fuzzing failed: {type(exc).__name__}: {str(exc)[:200]}")

    # --- Phase 4: Browser render ---
    browser_capture: BrowserCapture | None = None

    if enable_browser:
        progress.phase = "browser_rendering"
        try:
            browser_capture = await browser_engine.render_page(
                target, headers=headers, cookies=cookies,
                timeout_ms=browser_timeout_ms,
            )

            # Scan browser evidence for flags
            if browser_capture.dom_snapshot:
                flag_sources.append(_TextSource(text=browser_capture.dom_snapshot, source="rendered_dom", url=target))
            for entry in browser_capture.console_log:
                flag_sources.append(_TextSource(text=entry.text, source="console_log", url=target))
            for entry in browser_capture.storage:
                flag_sources.append(_TextSource(
                    text=f"{entry.key}={entry.value}",
                    source=f"browser_{entry.storage_type}",
                    url=target,
                ))

        except Exception as exc:
            warnings.append(f"Browser render failed: {type(exc).__name__}: {str(exc)[:200]}")

    # --- Phase 5: XSS scanning ---
    xss_result: XssScanResult | None = None

    if enable_xss and all_parameters:
        progress.phase = "xss_scanning"
        try:
            xss_result = await run_xss_scan(
                target, all_parameters,
                headers=headers, cookies=cookies,
                timeout_ms=timeout_ms, browser_timeout_ms=browser_timeout_ms,
                enable_dom=enable_browser and browser_engine.is_available(),
            )
            progress.xss_checks = xss_result.parameters_tested
        except Exception as exc:
            warnings.append(f"XSS scan failed: {type(exc).__name__}: {str(exc)[:200]}")

    # --- Phase 6: Flag detection ---
    progress.phase = "flag_detection"
    flag_result = flag_detector.scan_sources(flag_sources)
    progress.flags_found = len(flag_result.matches)

    # --- Done ---
    elapsed = max(0, round((time.monotonic() - started) * 1_000))
    progress.status = "completed"
    progress.phase = "completed"
    progress.elapsed_ms = elapsed
    progress.progress_pct = 100.0

    response = ActiveReconResponse(
        scan_id=scan_id,
        target_url=target,
        target_scope=target_scope,
        status="completed",
        crawl=crawl_result,
        dirbust=dirbust_result,
        param_fuzz=fuzz_result,
        browser=browser_capture,
        xss=xss_result,
        flags=flag_result,
        warnings=warnings,
        elapsed_ms=elapsed,
        started_at=started_at,
        completed_at=datetime.now(timezone.utc),
    )

    _scan_results[scan_id] = response
    return response
