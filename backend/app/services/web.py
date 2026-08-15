from __future__ import annotations

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
from app.core.errors import UnsafeWebTargetError, WebRequestError
from app.schemas.web import WebAnalysisRequest, WebAnalysisResponse, WebLimits

MAX_RESPONSE_BYTES = 512 * 1024
MAX_DOCUMENTS = 16
MAX_JAVASCRIPT_FILES = 8
MAX_REDIRECTS = 4
MAX_ANALYSIS_SECONDS = 30.0
_SCRIPT_SRC_RE = re.compile(r"<script\b[^>]*\bsrc\s*=\s*(['\"])(.*?)\1", re.I | re.S)
_SOURCE_MAP_RE = re.compile(r"(?://[#@]|/\*[#@])\s*sourceMappingURL\s*=\s*([^\s*]+)", re.I)
_BLOCKED_METADATA = {ipaddress.ip_address("169.254.169.254"), ipaddress.ip_address("100.100.100.200")}


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
        )
        timeout = httpx.Timeout(request.timeout_ms / 1_000)
        per_request_timeout = request.timeout_ms / 1_000
        deadline = time.monotonic() + MAX_ANALYSIS_SECONDS
        headers = {"User-Agent": "CTFKit-WebAnalyzer/0.1", "Accept": "*/*", **request.headers}
        if request.cookies:
            headers["Cookie"] = "; ".join(f"{name}={value}" for name, value in request.cookies.items())

        async with httpx.AsyncClient(
            timeout=timeout,
            follow_redirects=False,
            trust_env=False,
            transport=self._transport,
            limits=httpx.Limits(max_connections=4, max_keepalive_connections=2),
        ) as client:
            try:
                primary, chain, actual_request_headers = await self._fetch_with_redirects(
                    client, target, request.method, headers, deadline, per_request_timeout
                )
            except httpx.TimeoutException as exc:
                raise WebRequestError("The target did not respond within the configured timeout.", timed_out=True) from exc
            except httpx.HTTPError as exc:
                raise WebRequestError(f"The target request failed: {exc.__class__.__name__}.") from exc

            documents: list[FetchedDocument] = []
            final_origin = _origin(primary.url)
            if request.fetch_robots and len(documents) < MAX_DOCUMENTS:
                documents.append(await self._optional_fetch(client, urljoin(primary.url, "/robots.txt"), "robots", final_origin, deadline, per_request_timeout))
            if request.fetch_sitemap and len(documents) < MAX_DOCUMENTS:
                documents.append(await self._optional_fetch(client, urljoin(primary.url, "/sitemap.xml"), "sitemap", final_origin, deadline, per_request_timeout))

            javascript: list[FetchedDocument] = []
            if request.fetch_javascript and request.method == "GET":
                for match in _SCRIPT_SRC_RE.finditer(primary.text):
                    script_url = _clean_url(urljoin(primary.url, match.group(2).strip()))
                    if _origin(script_url) != final_origin or any(item.url == script_url for item in javascript):
                        continue
                    if len(javascript) >= MAX_JAVASCRIPT_FILES or len(documents) >= MAX_DOCUMENTS:
                        break
                    item = await self._optional_fetch(client, script_url, "javascript", final_origin, deadline, per_request_timeout)
                    javascript.append(item)
                    documents.append(item)

            source_maps: list[str] = []
            for script in javascript:
                if script.status_code is not None:
                    source_maps.extend(urljoin(script.url, value) for value in _SOURCE_MAP_RE.findall(script.text))
                header_map = next((item for key, item in script.headers if key.lower() in {"sourcemap", "x-sourcemap"}), None)
                if header_map:
                    source_maps.append(urljoin(script.url, header_map))
            for map_url in dict.fromkeys(source_maps):
                clean = _clean_url(map_url)
                if _origin(clean) != final_origin or len(documents) >= MAX_DOCUMENTS:
                    continue
                documents.append(await self._optional_fetch(client, clean, "source-map", final_origin, deadline, per_request_timeout))

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
                    comparison, _, _ = await self._fetch_with_redirects(
                        client, target, request.method, comparison_headers, deadline, per_request_timeout
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
        return await to_thread.run_sync(self._analyzer.analyze, analyzer_input)

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
                records = await to_thread.run_sync(self._resolver, host, parts.port or (443 if parts.scheme == "https" else 80), 0, socket.SOCK_STREAM)
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
    ) -> tuple[FetchedDocument, list[str], list[tuple[str, str]]]:
        current = url
        current_headers = dict(headers)
        chain: list[str] = []
        initial_origin = _origin(url)
        actual_headers: list[tuple[str, str]] = []
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
                document = FetchedDocument("primary", str(response.url), response.status_code, response_headers, body, elapsed, truncated)
                if response.status_code not in {301, 302, 303, 307, 308} or not response.headers.get("location"):
                    return document, chain, actual_headers
                if redirect_count >= MAX_REDIRECTS:
                    raise WebRequestError(f"The target exceeded the {MAX_REDIRECTS}-redirect limit.")
                next_url = _clean_url(urljoin(str(response.url), response.headers["location"]))
                chain.append(next_url)
                if _origin(next_url) != initial_origin:
                    current_headers = {key: value for key, value in current_headers.items() if key.lower() not in {"authorization", "cookie"}}
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
    ) -> FetchedDocument:
        if _origin(url) != allowed_origin:
            return FetchedDocument(kind, url, None, error="Cross-origin discovery fetch was skipped.")
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            return FetchedDocument(kind, url, None, error="The overall Web analysis time limit was reached.")
        try:
            await self._resolve_and_validate(url)
            started = time.monotonic()
            async with client.stream("GET", url, headers={"User-Agent": "CTFKit-WebAnalyzer/0.1", "Accept": "*/*"}, timeout=min(per_request_timeout, remaining)) as response:
                body, truncated = await self._read_bounded(response)
                return FetchedDocument(
                    kind=kind, url=str(response.url), status_code=response.status_code,
                    headers=[(key, value) for key, value in response.headers.multi_items()],
                    body=body, elapsed_ms=max(0, round((time.monotonic() - started) * 1_000)),
                    truncated=truncated,
                )
        except (httpx.HTTPError, UnsafeWebTargetError, WebRequestError) as exc:
            return FetchedDocument(kind, url, None, error=f"{kind} fetch failed: {exc.__class__.__name__}.")

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
