from __future__ import annotations

import socket
import time
from collections.abc import Callable

import httpx
from anyio import to_thread

from app.integrations.osint.base import (
    AdapterOutput,
    bounded_json,
    clean_error,
    elapsed_ms,
)


class RipeNetworkInfoAdapter:
    """Collects routing metadata from RIPEstat and reverse DNS from the local resolver."""

    name = "ip_metadata"
    source = "https://stat.ripe.net/data/network-info/data.json"

    def __init__(
        self,
        reverse_lookup: Callable[[str], tuple[str, list[str], list[str]]] | None = None,
    ) -> None:
        self._reverse_lookup = reverse_lookup or socket.gethostbyaddr

    async def collect(self, address: str, client: httpx.AsyncClient) -> AdapterOutput:
        started = time.monotonic()
        try:
            response, payload = await bounded_json(
                client,
                self.source,
                params={"resource": address},
                maximum_bytes=512 * 1024,
            )
            response.raise_for_status()
            data = payload.get("data", {}) if isinstance(payload, dict) else {}
            if not isinstance(data, dict):
                data = {}
            reverse_dns: str | None = None
            try:
                reverse_dns = (await to_thread.run_sync(self._reverse_lookup, address))[
                    0
                ].rstrip(".")
            except (OSError, IndexError):
                pass
            asns = []
            for asn in (
                data.get("asns", []) if isinstance(data.get("asns"), list) else []
            ):
                try:
                    asns.append(int(asn))
                except (TypeError, ValueError):
                    continue
            record: dict[str, object] = {
                "address": address,
                "reverse_dns": reverse_dns,
                "prefix": data.get("prefix"),
                "asns": asns,
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
