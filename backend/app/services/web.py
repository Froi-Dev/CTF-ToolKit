from __future__ import annotations

import asyncio
import ipaddress
import re
import socket
import time
from collections.abc import Callable
from urllib.parse import urljoin, urlsplit, urlunsplit
from uuid import uuid4

import httpx
from anyio import to_thread

from app.analyzers.web import WebAnalyzer, WebInput
from app.analyzers.web.analysis import FetchedDocument
from app.analyzers.web.similarity import bounded_body_similarity
from app.core.errors import InvalidAuthenticationSessionError, UnsafeWebTargetError, WebRequestError
from app.schemas.web import WebAnalysisRequest, WebAnalysisResponse, WebLimits

MAX_RESPONSE_BYTES = 512 * 1024
MAX_DOCUMENTS = 96
MAX_JAVASCRIPT_FILES = 8
MAX_REDIRECTS = 4
MAX_ANALYSIS_SECONDS = 45.0
MAX_CONCURRENT_REQUESTS = 10
DNS_RESOLUTION_TIMEOUT_SECONDS = 5.0
_SCRIPT_SRC_RE = re.compile(r"<script\b[^>]*\bsrc\s*=\s*(['\"])(.*?)\1", re.I | re.S)
_SOURCE_MAP_RE = re.compile(r"(?://[#@]|/\*[#@])\s*sourceMappingURL\s*=\s*([^\s*]+)", re.I)
_HREF_RE = re.compile(r"<(?:a|iframe)\b[^>]*(?:href|src)\s*=\s*(['\"])(.*?)\1", re.I | re.S)
_ROBOTS_PATH_RE = re.compile(r"(?im)^\s*(?:allow|disallow)\s*:\s*([^#\s]+)")
_SITEMAP_URL_RE = re.compile(r"(?i)<loc>\s*([^<]+?)\s*</loc>")
_STATIC_SUFFIXES = (".png", ".jpg", ".jpeg", ".gif", ".webp", ".svg", ".ico", ".woff", ".woff2", ".ttf", ".mp3", ".mp4", ".avi", ".mov", ".pdf")
_SENSITIVE_PATHS = (
    "/.env", "/.git/HEAD", "/.git/config", "/config.php", "/config.json", "/settings.py",
    "/backup.zip", "/backup.tar.gz", "/database.sql", "/dump.sql", "/README", "/README.md",
)
_DIRECTORY_PATHS = ("/debug", "/admin")
_API_PATHS = ("/swagger.json", "/openapi.json", "/api", "/graphql")
_BLOCKED_METADATA = {ipaddress.ip_address("169.254.169.254"), ipaddress.ip_address("100.100.100.200")}
_LOGIN_PATH_RE = re.compile(r"(?:^|/)(?:login|log-in|signin|sign-in|auth)(?:/|$)", re.I)
_AUTH_HEADER_NAME_RE = re.compile(r"(?:authorization|auth|token|api[-_]?key|access|session)", re.I)


def _origin(url: str) -> tuple[str, str, int]:
    parts = urlsplit(url)
    port = parts.port or (443 if parts.scheme == "https" else 80)
    return parts.scheme.lower(), (parts.hostname or "").lower(), port


def _clean_url(url: str) -> str:
    parts = urlsplit(url)
    return urlunsplit((parts.scheme.lower(), parts.netloc, parts.path or "/", parts.query, ""))


def _is_prohibited(address: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    return address in _BLOCKED_METADATA or address.is_unspecified or address.is_multicast or address.is_link_local


class WebAnalysisService:
    def __init__(
        self,
        analyzer: WebAnalyzer | None = None,
        transport: httpx.AsyncBaseTransport | None = None,
        resolver: Callable[..., object] | None = None,
    ) -> None:
        self._analyzer = analyzer or WebAnalyzer()
        self._transport = transport
        self._resolver = resolver or socket.getaddrinfo

    async def analyze(self, request: WebAnalysisRequest) -> WebAnalysisResponse:
        target = _clean_url(str(request.url))
        limits = WebLimits(
            max_response_bytes=MAX_RESPONSE_BYTES,
            max_documents=MAX_DOCUMENTS,
            max_javascript_files=MAX_JAVASCRIPT_FILES,
            max_redirects=MAX_REDIRECTS,
            max_pages=request.max_pages,
        )
        timeout = httpx.Timeout(request.timeout_ms / 1_000)
        per_request_timeout = request.timeout_ms / 1_000
        deadline = time.monotonic() + MAX_ANALYSIS_SECONDS
        headers = {"User-Agent": "CTFKit-WebAnalyzer/0.1", "Accept": "*/*", **request.headers}
        if request.cookies:
            headers["Cookie"] = "; ".join(f"{name}={value}" for name, value in request.cookies.items())
        authenticated = bool(
            request.cookies
            or request.authenticated_url is not None
            or any(_AUTH_HEADER_NAME_RE.search(name) for name in request.headers)
        )

        async with httpx.AsyncClient(
            timeout=timeout,
            follow_redirects=False,
            trust_env=False,
            transport=self._transport,
            limits=httpx.Limits(
                max_connections=MAX_CONCURRENT_REQUESTS,
                max_keepalive_connections=MAX_CONCURRENT_REQUESTS,
            ),
        ) as client:
            auth_check: FetchedDocument | None = None
            if request.authenticated_url is not None:
                auth_check_url = _clean_url(str(request.authenticated_url))
                if _origin(auth_check_url) != _origin(target):
                    raise UnsafeWebTargetError("The authenticated session check URL must have the same origin as the crawl target.")
                try:
                    auth_check, auth_chain, _, auth_redirects = await self._fetch_with_redirects(
                        client, auth_check_url, "GET", headers, deadline,
                        per_request_timeout, True, authenticated=authenticated,
                    )
                except httpx.TimeoutException as exc:
                    raise WebRequestError("The authenticated session check timed out.", timed_out=True) from exc
                except httpx.HTTPError as exc:
                    raise WebRequestError(f"The authenticated session check failed: {exc.__class__.__name__}.") from exc
                auth_check.kind = "auth-check"
                redirected_to_login = any(_LOGIN_PATH_RE.search(urlsplit(item).path) for item in auth_chain)
                if auth_check.status_code in {401, 403} or redirected_to_login:
                    raise InvalidAuthenticationSessionError(
                        "The supplied authentication session appears invalid or expired; the crawl was not started."
                    )

            try:
                primary, chain, actual_request_headers, primary_redirects = await self._fetch_with_redirects(
                    client, target, request.method, headers, deadline, per_request_timeout,
                    request.follow_redirects, authenticated=authenticated,
                )
            except httpx.TimeoutException as exc:
                raise WebRequestError("The target did not respond within the configured timeout.", timed_out=True) from exc
            except httpx.HTTPError as exc:
                raise WebRequestError(f"The target request failed: {exc.__class__.__name__}.") from exc

            documents: list[FetchedDocument] = [
                *([] if request.authenticated_url is None else auth_redirects),
                *([] if auth_check is None else [auth_check]),
                *primary_redirects,
            ]
            final_origin = _origin(primary.url)
            discovery_headers = headers
            discovery_authenticated = authenticated
            if final_origin != _origin(target):
                discovery_headers = {
                    key: value for key, value in headers.items()
                    if key.lower() in {"user-agent", "accept"}
                }
                discovery_authenticated = False
            discovery_specs: list[tuple[str, str, str]] = []
            if request.fetch_robots and len(documents) < MAX_DOCUMENTS:
                discovery_specs.append((urljoin(primary.url, "/robots.txt"), "robots", "automatic-discovery"))
            if request.fetch_sitemap and len(documents) < MAX_DOCUMENTS:
                discovery_specs.append((urljoin(primary.url, "/sitemap.xml"), "sitemap", "automatic-discovery"))

            if request.directory_discovery or request.api_discovery or request.sensitive_file_checks:
                for suffix in (uuid4().hex, uuid4().hex):
                    discovery_specs.append((
                        urljoin(primary.url, f"/.ctfkit-not-found-{suffix}"),
                        "wildcard-probe", "wildcard-baseline",
                    ))

                checks = list(dict.fromkeys(
                    (*(_SENSITIVE_PATHS if request.sensitive_file_checks else ()),
                     *(_DIRECTORY_PATHS if request.directory_discovery else ()),
                     *(_API_PATHS if request.api_discovery else ()))
                ))
                discovery_specs.extend(
                    (urljoin(primary.url, path), "sensitive", "targeted-check")
                    for path in checks
                )

            available = max(0, MAX_DOCUMENTS - len(documents))
            if discovery_specs and available:
                fetched = await asyncio.gather(*(
                    self._optional_fetch(
                        client, url, kind, final_origin, deadline,
                        per_request_timeout, discovery_headers, source=source,
                        authenticated=discovery_authenticated,
                    )
                    for url, kind, source in discovery_specs[:available]
                ))
                wildcard_probes = [item for item in fetched if item.kind == "wildcard-probe"]
                for item in fetched:
                    if item.kind != "sensitive":
                        continue
                    item.wildcard_like = self._matches_wildcard(item, wildcard_probes)
                documents.extend(fetched)

            if request.crawl_same_origin and request.method == "GET" and request.scan_depth > 0:
                await self._crawl(
                    client, primary, documents, final_origin, request.scan_depth,
                    request.max_pages, deadline, per_request_timeout,
                    discovery_headers, discovery_authenticated,
                )

            javascript: list[FetchedDocument] = []
            if request.fetch_javascript and request.method == "GET":
                html_documents = [primary, *(item for item in documents if item.kind == "page" and item.status_code == 200)]
                script_candidates: dict[str, str] = {}
                for html_document in html_documents:
                    for match in _SCRIPT_SRC_RE.finditer(html_document.text):
                        script_url = _clean_url(urljoin(html_document.url, match.group(2).strip()))
                        if _origin(script_url) == final_origin:
                            script_candidates.setdefault(script_url, html_document.url)
                        if len(script_candidates) >= MAX_JAVASCRIPT_FILES:
                            break
                    if len(script_candidates) >= MAX_JAVASCRIPT_FILES:
                        break
                available = min(MAX_JAVASCRIPT_FILES, max(0, MAX_DOCUMENTS - len(documents)))
                javascript = list(await asyncio.gather(*(
                    self._optional_fetch(
                        client, script_url, "javascript", final_origin, deadline,
                        per_request_timeout, discovery_headers, parent_url=parent_url, source="HTML script",
                        authenticated=discovery_authenticated,
                    )
                    for script_url, parent_url in list(script_candidates.items())[:available]
                )))
                documents.extend(javascript)

            source_maps: list[str] = []
            for script in javascript:
                if script.status_code is not None:
                    source_maps.extend(urljoin(script.url, value) for value in _SOURCE_MAP_RE.findall(script.text))
                header_map = next((item for key, item in script.headers if key.lower() in {"sourcemap", "x-sourcemap"}), None)
                if header_map:
                    source_maps.append(urljoin(script.url, header_map))
            map_candidates = [
                clean for map_url in dict.fromkeys(source_maps)
                if _origin(clean := _clean_url(map_url)) == final_origin
            ] if request.source_map_discovery else []
            available = max(0, MAX_DOCUMENTS - len(documents))
            if map_candidates and available:
                documents.extend(await asyncio.gather(*(
                    self._optional_fetch(
                        client, clean, "source-map", final_origin, deadline,
                        per_request_timeout, discovery_headers, source="sourceMappingURL",
                        authenticated=discovery_authenticated,
                    )
                    for clean in map_candidates[:available]
                )))

            comparison: FetchedDocument | None = None
            comparison_error: str | None = None
            if request.compare_without_auth:
                comparison_headers = {
                    key: value for key, value in headers.items()
                    if key.lower() not in {"authorization", "cookie"}
                }
                try:
                    if time.monotonic() >= deadline:
                        raise WebRequestError("The overall Web analysis time limit was reached.", timed_out=True)
                    comparison, _, _, _ = await self._fetch_with_redirects(
                        client, target, request.method, comparison_headers, deadline, per_request_timeout,
                        request.follow_redirects, authenticated=False,
                    )
                except (httpx.HTTPError, UnsafeWebTargetError, WebRequestError) as exc:
                    comparison_error = f"Unauthenticated comparison failed: {exc.__class__.__name__}."

        analyzer_input = WebInput(
            analysis_id=str(uuid4()),
            target_scope=request.target_scope,
            method=request.method,
            request_headers=actual_request_headers,
            redirect_chain=chain,
            primary=primary,
            documents=documents,
            comparison=comparison,
            comparison_error=comparison_error,
            limits=limits,
        )
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise WebRequestError("The overall Web analysis time limit was reached.", timed_out=True)
        try:
            return await asyncio.wait_for(
                to_thread.run_sync(self._analyzer.analyze, analyzer_input, abandon_on_cancel=True),
                timeout=remaining,
            )
        except TimeoutError as exc:
            raise WebRequestError("The overall Web analysis time limit was reached.", timed_out=True) from exc

    async def _resolve_and_validate(self, url: str) -> None:
        parts = urlsplit(url)
        if parts.scheme not in {"http", "https"} or not parts.hostname:
            raise UnsafeWebTargetError("Only absolute HTTP and HTTPS targets are supported.")
        if parts.username is not None or parts.password is not None:
            raise UnsafeWebTargetError("Credentials in target URLs are not allowed; use request headers instead.")
        host = parts.hostname.rstrip(".")
        try:
            literal = ipaddress.ip_address(host)
            addresses = [literal]
        except ValueError:
            try:
                records = await asyncio.wait_for(
                    to_thread.run_sync(
                        self._resolver,
                        host,
                        parts.port or (443 if parts.scheme == "https" else 80),
                        0,
                        socket.SOCK_STREAM,
                        abandon_on_cancel=True,
                    ),
                    timeout=DNS_RESOLUTION_TIMEOUT_SECONDS,
                )
            except TimeoutError as exc:
                raise WebRequestError("The target hostname resolution timed out.", timed_out=True) from exc
            except socket.gaierror as exc:
                raise WebRequestError("The target hostname could not be resolved.") from exc
            addresses = []
            for record in records:  # type: ignore[union-attr]
                try:
                    addresses.append(ipaddress.ip_address(record[4][0]))
                except (ValueError, IndexError):
                    continue
        if not addresses:
            raise WebRequestError("The target hostname did not resolve to an address.")
        if any(_is_prohibited(address) for address in addresses):
            raise UnsafeWebTargetError("Link-local, metadata, multicast, and unspecified destinations are blocked.")

    async def _fetch_with_redirects(
        self,
        client: httpx.AsyncClient,
        url: str,
        method: str,
        headers: dict[str, str],
        deadline: float,
        per_request_timeout: float,
        follow_redirects: bool = True,
        *,
        authenticated: bool = False,
    ) -> tuple[FetchedDocument, list[str], list[tuple[str, str]], list[FetchedDocument]]:
        current = url
        current_headers = dict(headers)
        chain: list[str] = []
        initial_origin = _origin(url)
        current_authenticated = authenticated
        actual_headers: list[tuple[str, str]] = []
        redirect_documents: list[FetchedDocument] = []
        for redirect_count in range(MAX_REDIRECTS + 1):
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise WebRequestError("The overall Web analysis time limit was reached.", timed_out=True)
            await self._resolve_and_validate(current)
            started = time.monotonic()
            async with client.stream(method, current, headers=current_headers, timeout=min(per_request_timeout, remaining)) as response:
                if not actual_headers:
                    actual_headers = [(key, value) for key, value in response.request.headers.multi_items()]
                body, truncated = await self._read_bounded(response)
                elapsed = max(0, round((time.monotonic() - started) * 1_000))
                response_headers = [(key, value) for key, value in response.headers.multi_items()]
                response_headers.append(("x-ctfkit-reason", response.reason_phrase))
                document = FetchedDocument(
                    "primary", str(response.url), response.status_code, response_headers,
                    body, elapsed, truncated, authenticated=current_authenticated,
                )
                if response.status_code not in {301, 302, 303, 307, 308} or not response.headers.get("location"):
                    return document, chain, actual_headers, redirect_documents
                if not follow_redirects:
                    return document, chain, actual_headers, redirect_documents
                if redirect_count >= MAX_REDIRECTS:
                    raise WebRequestError(f"The target exceeded the {MAX_REDIRECTS}-redirect limit.")
                next_url = _clean_url(urljoin(str(response.url), response.headers["location"]))
                document.kind = "redirect"
                redirect_documents.append(document)
                chain.append(next_url)
                if _origin(next_url) != initial_origin:
                    current_headers = {
                        key: value for key, value in current_headers.items()
                        if key.lower() in {"user-agent", "accept"}
                    }
                    current_authenticated = False
                current = next_url
                if response.status_code == 303 and method != "HEAD":
                    method = "GET"
        raise WebRequestError("The redirect limit was reached.")

    async def _optional_fetch(
        self,
        client: httpx.AsyncClient,
        url: str,
        kind: str,
        allowed_origin: tuple[str, str, int],
        deadline: float,
        per_request_timeout: float,
        request_headers: dict[str, str] | None = None,
        *,
        depth: int = 0,
        parent_url: str | None = None,
        source: str = "direct",
        authenticated: bool = False,
    ) -> FetchedDocument:
        if _origin(url) != allowed_origin:
            return FetchedDocument(kind, url, None, error="Cross-origin discovery fetch was skipped.")
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            return FetchedDocument(kind, url, None, error="The overall Web analysis time limit was reached.")
        try:
            await self._resolve_and_validate(url)
            started = time.monotonic()
            async with client.stream("GET", url, headers=request_headers or {"User-Agent": "CTFKit-WebAnalyzer/0.1", "Accept": "*/*"}, timeout=min(per_request_timeout, remaining)) as response:
                body, truncated = await self._read_bounded(response)
                return FetchedDocument(
                    kind=kind, url=str(response.url), status_code=response.status_code,
                    headers=[(key, value) for key, value in response.headers.multi_items()],
                    body=body, elapsed_ms=max(0, round((time.monotonic() - started) * 1_000)),
                    truncated=truncated,
                    depth=depth, parent_url=parent_url, source=source,
                    authenticated=authenticated,
                )
        except (httpx.HTTPError, UnsafeWebTargetError, WebRequestError) as exc:
            return FetchedDocument(kind, url, None, error=f"{kind} fetch failed: {exc.__class__.__name__}.")

    @staticmethod
    def _matches_wildcard(document: FetchedDocument, probes: list[FetchedDocument]) -> bool:
        if document.status_code is None:
            return False
        for probe in probes:
            if probe.status_code != document.status_code or probe.content_type != document.content_type:
                continue
            if document.body == probe.body:
                return True
            similarity = bounded_body_similarity(
                document.body,
                probe.body,
                left_substitutions=(document.url, urlsplit(document.url).path),
                right_substitutions=(probe.url, urlsplit(probe.url).path),
            )
            if similarity >= 0.96:
                return True
        return False

    async def _crawl(
        self,
        client: httpx.AsyncClient,
        primary: FetchedDocument,
        documents: list[FetchedDocument],
        allowed_origin: tuple[str, str, int],
        max_depth: int,
        max_pages: int,
        deadline: float,
        per_request_timeout: float,
        request_headers: dict[str, str],
        authenticated: bool,
    ) -> None:
        seen = {_clean_url(primary.url)}
        queued: set[str] = set()
        queue: list[tuple[str, int, str, str]] = []

        def enqueue(raw: str, depth: int, parent: str, source: str) -> None:
            if depth > max_depth:
                return
            clean = _clean_url(urljoin(parent, raw.strip()))
            parts = urlsplit(clean)
            if _origin(clean) != allowed_origin or parts.path.lower().endswith(_STATIC_SUFFIXES):
                return
            lowered = clean.lower()
            if any(marker in lowered for marker in ("logout", "signout", "logoff")):
                return
            if clean not in seen and clean not in queued:
                queued.add(clean)
                queue.append((clean, depth, parent, source))

        for match in _HREF_RE.finditer(primary.text):
            enqueue(match.group(2), 1, primary.url, "HTML link")
        for document in documents:
            if document.kind == "robots" and document.status_code == 200:
                for raw in _ROBOTS_PATH_RE.findall(document.text):
                    enqueue(raw, 1, document.url, "robots.txt")
            elif document.kind == "sitemap" and document.status_code == 200:
                for raw in _SITEMAP_URL_RE.findall(document.text):
                    enqueue(raw, 1, document.url, "sitemap.xml")

        page_count = 1
        for current_depth in range(1, max_depth + 1):
            remaining_pages = max_pages - page_count
            remaining_documents = MAX_DOCUMENTS - len(documents)
            if remaining_pages <= 0 or remaining_documents <= 0 or time.monotonic() >= deadline:
                break
            candidates = [item for item in queue if item[1] == current_depth]
            queue = [item for item in queue if item[1] != current_depth]
            batch: list[tuple[str, int, str, str]] = []
            for item in candidates:
                url, _, _, _ = item
                queued.discard(url)
                if url in seen:
                    continue
                seen.add(url)
                batch.append(item)
                if len(batch) >= min(remaining_pages, remaining_documents):
                    break
            if not batch:
                continue
            pages = await asyncio.gather(*(
                self._optional_fetch(
                    client, url, "page", allowed_origin, deadline, per_request_timeout,
                    request_headers, depth=depth, parent_url=parent, source=source,
                    authenticated=authenticated,
                )
                for url, depth, parent, source in batch
            ))
            documents.extend(pages)
            page_count += len(pages)
            for page in pages:
                if page.status_code != 200 or current_depth >= max_depth or "html" not in (page.content_type or "").lower():
                    continue
                for match in _HREF_RE.finditer(page.text):
                    enqueue(match.group(2), current_depth + 1, page.url, "HTML link")

    async def _read_bounded(self, response: httpx.Response) -> tuple[bytes, bool]:
        content_length = response.headers.get("content-length")
        if content_length and content_length.isdigit() and int(content_length) > MAX_RESPONSE_BYTES:
            # Still consume only the bounded prefix for useful inspection.
            known_oversize = True
        else:
            known_oversize = False
        chunks: list[bytes] = []
        size = 0
        truncated = known_oversize
        async for chunk in response.aiter_bytes():
            remaining = MAX_RESPONSE_BYTES - size
            if len(chunk) > remaining:
                chunks.append(chunk[:remaining])
                truncated = True
                break
            chunks.append(chunk)
            size += len(chunk)
            if size >= MAX_RESPONSE_BYTES:
                truncated = True
                break
        return b"".join(chunks), truncated
