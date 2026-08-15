from __future__ import annotations

import time

import httpx

from app.integrations.osint.base import (
    AdapterOutput,
    bounded_json,
    clean_error,
    elapsed_ms,
)


class CertificateTransparencyAdapter:
    """Reads public Certificate Transparency observations from crt.sh."""

    name = "certificates"
    source = "https://crt.sh/"

    async def collect(
        self, domain: str, client: httpx.AsyncClient, maximum: int
    ) -> AdapterOutput:
        started = time.monotonic()
        try:
            response, payload = await bounded_json(
                client,
                self.source,
                params={"q": f"%.{domain}", "output": "json"},
            )
            response.raise_for_status()
            if not isinstance(payload, list):
                return AdapterOutput(
                    self.name,
                    self.source,
                    status="no_data",
                    duration_ms=elapsed_ms(started),
                )
            records: list[dict[str, object]] = []
            seen: set[str] = set()
            for item in payload:
                if not isinstance(item, dict):
                    continue
                certificate_id = str(item.get("id") or item.get("min_cert_id") or "")
                if not certificate_id or certificate_id in seen:
                    continue
                seen.add(certificate_id)
                dns_names = []
                for name in str(item.get("name_value", "")).splitlines():
                    normalized = name.strip().lower().rstrip(".")
                    if normalized.startswith("*."):
                        normalized = normalized[2:]
                    if normalized and (
                        normalized == domain or normalized.endswith(f".{domain}")
                    ):
                        dns_names.append(normalized)
                records.append(
                    {
                        "certificate_id": certificate_id,
                        "common_name": item.get("common_name"),
                        "dns_names": list(dict.fromkeys(dns_names)),
                        "issuer": item.get("issuer_name"),
                        "not_before": item.get("not_before"),
                        "not_after": item.get("not_after"),
                    }
                )
                if len(records) >= maximum:
                    break
            return AdapterOutput(
                self.name,
                self.source,
                records,
                "success" if records else "no_data",
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
