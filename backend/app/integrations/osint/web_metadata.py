from __future__ import annotations

import ipaddress
import socket
import time
from collections.abc import Callable
from html.parser import HTMLParser
from urllib.parse import urljoin, urlsplit

import httpx
from anyio import to_thread

from app.integrations.osint.base import AdapterOutput, clean_error, elapsed_ms


MAX_HTML_BYTES = 512 * 1024
MAX_REDIRECTS = 3


class _MetadataParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.in_title = False
        self.title_parts: list[str] = []
        self.description: str | None = None
        self.author: str | None = None
        self.canonical_url: str | None = None
        self.open_graph: dict[str, str] = {}
        self.json_ld_types: list[str] = []
        self.links: list[str] = []
        self._in_json_ld = False
        self._json_ld_parts: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        values = {key.lower(): value for key, value in attrs if value is not None}
        tag = tag.lower()
        if tag == "title":
            self.in_title = True
        elif tag == "meta":
            name = (values.get("name") or values.get("property") or "").lower()
            content = values.get("content", "")[:2_000]
            if name == "description":
                self.description = content
            elif name == "author":
                self.author = content
            elif name.startswith("og:") and len(self.open_graph) < 30:
                self.open_graph[name] = content
        elif tag == "link" and "canonical" in values.get("rel", "").lower().split():
            self.canonical_url = values.get("href")
        elif tag == "a" and values.get("href") and len(self.links) < 100:
            self.links.append(values["href"])
        elif (
            tag == "script" and values.get("type", "").lower() == "application/ld+json"
        ):
            self._in_json_ld = True
            self._json_ld_parts = []

    def handle_endtag(self, tag: str) -> None:
        if tag.lower() == "title":
            self.in_title = False
        elif tag.lower() == "script" and self._in_json_ld:
            self._in_json_ld = False
            text = "".join(self._json_ld_parts)
            import json

            try:
                value = json.loads(text)
                nodes = value if isinstance(value, list) else [value]
                for node in nodes:
                    if isinstance(node, dict) and node.get("@type"):
                        kinds = (
                            node["@type"]
                            if isinstance(node["@type"], list)
                            else [node["@type"]]
                        )
                        self.json_ld_types.extend(str(kind) for kind in kinds)
            except (json.JSONDecodeError, TypeError):
                pass

    def handle_data(self, data: str) -> None:
        if self.in_title:
            self.title_parts.append(data)
        if self._in_json_ld:
            self._json_ld_parts.append(data)


class WebMetadataAdapter:
    name = "web_metadata"
    source = "target-web-page"

    def __init__(self, resolver: Callable[..., object] | None = None) -> None:
        self._resolver = resolver or socket.getaddrinfo

    async def collect(self, url: str, client: httpx.AsyncClient) -> AdapterOutput:
        started = time.monotonic()
        try:
            current = url
            response: httpx.Response | None = None
            body = b""
            for _ in range(MAX_REDIRECTS + 1):
                await self._require_public_target(current)
                async with client.stream(
                    "GET",
                    current,
                    headers={"Accept": "text/html,application/xhtml+xml"},
                ) as candidate:
                    if candidate.status_code in {
                        301,
                        302,
                        303,
                        307,
                        308,
                    } and candidate.headers.get("location"):
                        current = urljoin(current, candidate.headers["location"])
                        continue
                    response = candidate
                    chunks: list[bytes] = []
                    size = 0
                    async for chunk in candidate.aiter_bytes():
                        size += len(chunk)
                        if size > MAX_HTML_BYTES:
                            raise ValueError(
                                "Web metadata response exceeded the configured size limit."
                            )
                        chunks.append(chunk)
                    body = b"".join(chunks)
                    break
            if response is None:
                raise ValueError("Web metadata redirect limit exceeded.")
            response.raise_for_status()
            content_type = response.headers.get("content-type", "").lower()
            if "html" not in content_type:
                raise ValueError("Web metadata target did not return HTML.")
            parser = _MetadataParser()
            parser.feed(body.decode(response.encoding or "utf-8", errors="replace"))
            record = {
                "url": url,
                "final_url": current,
                "status_code": response.status_code,
                "title": " ".join("".join(parser.title_parts).split())[:500] or None,
                "description": parser.description,
                "author": parser.author,
                "canonical_url": urljoin(current, parser.canonical_url)
                if parser.canonical_url
                else None,
                "open_graph": parser.open_graph,
                "json_ld_types": list(dict.fromkeys(parser.json_ld_types))[:30],
                "links": list(
                    dict.fromkeys(urljoin(current, link) for link in parser.links)
                )[:100],
            }
            return AdapterOutput(
                self.name, self.source, [record], duration_ms=elapsed_ms(started)
            )
        except Exception as exc:
            return AdapterOutput(
                self.name,
                self.source,
                status="error",
                error=clean_error(exc),
                duration_ms=elapsed_ms(started),
            )

    async def _require_public_target(self, url: str) -> None:
        parts = urlsplit(url)
        if (
            parts.scheme not in {"http", "https"}
            or not parts.hostname
            or parts.username
            or parts.password
        ):
            raise ValueError(
                "Web metadata targets must be public HTTP(S) URLs without embedded credentials."
            )
        port = parts.port or (443 if parts.scheme == "https" else 80)
        try:
            addresses = [ipaddress.ip_address(parts.hostname)]
        except ValueError:
            resolved = await to_thread.run_sync(
                self._resolver, parts.hostname, port, 0, socket.SOCK_STREAM
            )
            addresses = list({ipaddress.ip_address(item[4][0]) for item in resolved})
        if not addresses or any(not address.is_global for address in addresses):
            raise ValueError(
                "Web metadata collection is limited to publicly routable targets."
            )
