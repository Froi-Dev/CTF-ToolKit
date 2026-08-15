from __future__ import annotations

import asyncio
import time

import httpx

from app.integrations.osint.base import (
    AdapterOutput,
    bounded_json,
    clean_error,
    elapsed_ms,
)


class DnsOverHttpsAdapter:
    """Queries public DNS data through Cloudflare's DNS-over-HTTPS JSON API."""

    name = "dns"
    source = "https://cloudflare-dns.com/dns-query"
    record_types = ("A", "AAAA", "CNAME", "MX", "NS", "TXT", "SOA")

    async def collect(self, domain: str, client: httpx.AsyncClient) -> AdapterOutput:
        started = time.monotonic()
        try:
            results = await asyncio.gather(
                *(
                    self._query(domain, record_type, client)
                    for record_type in self.record_types
                ),
                return_exceptions=True,
            )
            records: list[dict[str, object]] = []
            failures = 0
            for result in results:
                if isinstance(result, BaseException):
                    failures += 1
                else:
                    records.extend(result)
            status = (
                "success"
                if records
                else ("error" if failures == len(results) else "no_data")
            )
            error = f"{failures} DNS record queries failed." if failures else None
            return AdapterOutput(
                self.name,
                self.source,
                records[:250],
                status,
                error,
                elapsed_ms(started),
            )
        except Exception as exc:
            return AdapterOutput(
                self.name,
                self.source,
                status="error",
                error=clean_error(exc),
                duration_ms=elapsed_ms(started),
            )

    async def _query(
        self, domain: str, record_type: str, client: httpx.AsyncClient
    ) -> list[dict[str, object]]:
        response, payload = await bounded_json(
            client,
            self.source,
            params={"name": domain, "type": record_type},
            headers={"Accept": "application/dns-json"},
            maximum_bytes=256 * 1024,
        )
        response.raise_for_status()
        if not isinstance(payload, dict):
            return []
        answers = payload.get("Answer")
        if not isinstance(answers, list):
            return []
        records: list[dict[str, object]] = []
        for answer in answers[:100]:
            if not isinstance(answer, dict):
                continue
            value = str(answer.get("data", "")).strip().rstrip(".")
            priority: int | None = None
            if record_type == "MX" and " " in value:
                raw_priority, value = value.split(" ", 1)
                try:
                    priority = int(raw_priority)
                except ValueError:
                    priority = None
                value = value.rstrip(".")
            if (
                record_type == "TXT"
                and len(value) >= 2
                and value.startswith('"')
                and value.endswith('"')
            ):
                value = value[1:-1]
            record: dict[str, object] = {
                "name": str(answer.get("name", domain)).rstrip("."),
                "record_type": record_type,
                "value": value,
            }
            ttl = answer.get("TTL")
            if isinstance(ttl, int) and ttl >= 0:
                record["ttl"] = ttl
            if priority is not None:
                record["priority"] = priority
            records.append(record)
        return records
