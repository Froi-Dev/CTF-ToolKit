from __future__ import annotations

import time
from urllib.parse import quote

import httpx

from app.integrations.osint.base import (
    AdapterOutput,
    bounded_json,
    clean_error,
    elapsed_ms,
)


class RdapAdapter:
    """Uses RDAP.org's IANA-bootstrap client for domain and IP registration data."""

    name = "rdap"
    source = "https://rdap.org"

    async def collect(
        self, target: str, target_type: str, client: httpx.AsyncClient
    ) -> AdapterOutput:
        started = time.monotonic()
        path = "domain" if target_type == "domain" else "ip"
        try:
            response, payload = await bounded_json(
                client,
                f"{self.source}/{path}/{quote(target, safe=':')}",
                follow_redirects=True,
            )
            if response.status_code == 404:
                return AdapterOutput(
                    self.name,
                    self.source,
                    status="no_data",
                    duration_ms=elapsed_ms(started),
                )
            response.raise_for_status()
            if not isinstance(payload, dict):
                return AdapterOutput(
                    self.name,
                    self.source,
                    status="no_data",
                    duration_ms=elapsed_ms(started),
                )
            record = self._summarize(target, payload)
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

    @staticmethod
    def _summarize(query: str, payload: dict[str, object]) -> dict[str, object]:
        events: dict[str, str] = {}
        for event in (
            payload.get("events", []) if isinstance(payload.get("events"), list) else []
        ):
            if (
                isinstance(event, dict)
                and event.get("eventAction")
                and event.get("eventDate")
            ):
                events[str(event["eventAction"])] = str(event["eventDate"])

        entities: list[dict[str, object]] = []
        for entity in (
            payload.get("entities", [])
            if isinstance(payload.get("entities"), list)
            else []
        ):
            if not isinstance(entity, dict):
                continue
            summary: dict[str, object] = {
                "handle": entity.get("handle"),
                "roles": [str(role) for role in entity.get("roles", [])]
                if isinstance(entity.get("roles"), list)
                else [],
            }
            vcard = entity.get("vcardArray")
            if (
                isinstance(vcard, list)
                and len(vcard) == 2
                and isinstance(vcard[1], list)
            ):
                for item in vcard[1]:
                    if (
                        isinstance(item, list)
                        and len(item) >= 4
                        and item[0] in {"fn", "org"}
                    ):
                        summary[str(item[0])] = str(item[3])[:300]
            entities.append(summary)

        notices = []
        for notice in (
            payload.get("notices", [])
            if isinstance(payload.get("notices"), list)
            else []
        ):
            if isinstance(notice, dict) and notice.get("title"):
                notices.append(str(notice["title"])[:300])

        nameservers = []
        for server in (
            payload.get("nameservers", [])
            if isinstance(payload.get("nameservers"), list)
            else []
        ):
            if isinstance(server, dict) and server.get("ldhName"):
                nameservers.append(str(server["ldhName"]).lower().rstrip("."))

        return {
            "query": query,
            "object_class": payload.get("objectClassName"),
            "handle": payload.get("handle"),
            "name": payload.get("ldhName") or payload.get("name"),
            "country": payload.get("country"),
            "registry": payload.get("port43"),
            "statuses": [str(item) for item in payload.get("status", [])]
            if isinstance(payload.get("status"), list)
            else [],
            "nameservers": list(dict.fromkeys(nameservers)),
            "events": events,
            "entities": entities[:25],
            "notices": notices[:20],
        }
