from __future__ import annotations

import re
import socket
import time
from collections.abc import Callable

from anyio import to_thread

from app.integrations.osint.base import AdapterOutput, clean_error, elapsed_ms


MAX_WHOIS_BYTES = 256 * 1024
_FIELD_MAP = {
    "registrar": "registrar",
    "registrar name": "registrar",
    "registrant organization": "organization",
    "orgname": "organization",
    "country": "country",
    "registrant country": "country",
    "creation date": "created_at",
    "created": "created_at",
    "updated date": "updated_at",
    "last updated": "updated_at",
    "registry expiry date": "expires_at",
    "expiration date": "expires_at",
}


def _socket_query(server: str, query: str, timeout_seconds: float) -> str:
    chunks: list[bytes] = []
    total = 0
    deadline = time.monotonic() + timeout_seconds
    with socket.create_connection((server, 43), timeout=timeout_seconds) as connection:
        connection.sendall(f"{query}\r\n".encode("ascii"))
        while total < MAX_WHOIS_BYTES:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError("WHOIS lookup timed out.")
            connection.settimeout(remaining)
            chunk = connection.recv(min(16_384, MAX_WHOIS_BYTES - total))
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
    return b"".join(chunks).decode("utf-8", errors="replace")


def lookup_domain(domain: str, timeout_seconds: float) -> tuple[str, str]:
    tld = domain.rsplit(".", 1)[-1]
    per_query_timeout = max(0.5, timeout_seconds / 2)
    bootstrap = _socket_query("whois.iana.org", tld, per_query_timeout)
    match = re.search(r"(?im)^whois:\s*(\S+)", bootstrap)
    server = match.group(1).strip().lower() if match else "whois.iana.org"
    return server, _socket_query(server, domain, per_query_timeout)


class WhoisAdapter:
    name = "whois"
    source = "whois://whois.iana.org"

    def __init__(
        self, lookup: Callable[[str, float], tuple[str, str]] | None = None
    ) -> None:
        self._lookup = lookup or lookup_domain

    async def collect(self, domain: str, timeout_seconds: float) -> AdapterOutput:
        started = time.monotonic()
        try:
            server, text = await to_thread.run_sync(
                self._lookup, domain, timeout_seconds
            )
            record = self._parse(server, text)
            status = (
                "success"
                if any(value for key, value in record.items() if key != "server")
                else "no_data"
            )
            return AdapterOutput(
                self.name,
                self.source,
                [record] if status == "success" else [],
                status,
                duration_ms=elapsed_ms(started),
            )
        except Exception as exc:
            return AdapterOutput(
                self.name,
                self.source,
                status="error",
                error=clean_error(exc),
                duration_ms=elapsed_ms(started),
            )

    @staticmethod
    def _parse(server: str, text: str) -> dict[str, object]:
        summary: dict[str, object] = {"server": server}
        nameservers: list[str] = []
        statuses: list[str] = []
        for line in text.splitlines():
            if ":" not in line or line.startswith(("%", "#")):
                continue
            key, value = line.split(":", 1)
            normalized_key = key.strip().lower()
            value = value.strip()
            if not value:
                continue
            mapped = _FIELD_MAP.get(normalized_key)
            if mapped and mapped not in summary:
                summary[mapped] = value[:500]
            elif normalized_key in {"name server", "nserver"}:
                nameservers.append(value.split()[0].lower().rstrip("."))
            elif normalized_key in {"domain status", "status"}:
                statuses.append(value.split()[0])
        summary["nameservers"] = list(dict.fromkeys(nameservers))[:25]
        summary["statuses"] = list(dict.fromkeys(statuses))[:25]
        return summary
