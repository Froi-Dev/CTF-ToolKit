from __future__ import annotations

import os
import time

import httpx

from app.integrations.osint.base import (
    AdapterOutput,
    bounded_json,
    clean_error,
    elapsed_ms,
)


class GoogleSearchAdapter:
    """Optional official Google Programmable Search integration for existing customers."""

    name = "google_search"
    source = "https://customsearch.googleapis.com/customsearch/v1"

    def __init__(
        self, api_key: str | None = None, engine_id: str | None = None
    ) -> None:
        self._api_key = (
            api_key if api_key is not None else os.getenv("GOOGLE_CSE_API_KEY")
        )
        self._engine_id = (
            engine_id if engine_id is not None else os.getenv("GOOGLE_CSE_ID")
        )

    async def collect(
        self, query: str, client: httpx.AsyncClient, maximum: int
    ) -> AdapterOutput:
        started = time.monotonic()
        if not self._api_key or not self._engine_id:
            return AdapterOutput(
                self.name,
                self.source,
                status="unavailable",
                error="Google search is not configured; set GOOGLE_CSE_API_KEY and GOOGLE_CSE_ID.",
                duration_ms=elapsed_ms(started),
            )
        try:
            response, payload = await bounded_json(
                client,
                self.source,
                params={
                    "key": self._api_key,
                    "cx": self._engine_id,
                    "q": query,
                    "num": maximum,
                    "safe": "active",
                },
            )
            response.raise_for_status()
            items = payload.get("items", []) if isinstance(payload, dict) else []
            records = []
            for item in items[:maximum] if isinstance(items, list) else []:
                if not isinstance(item, dict) or not item.get("link"):
                    continue
                records.append(
                    {
                        "title": str(item.get("title", "Untitled"))[:500],
                        "url": str(item["link"]),
                        "snippet": str(item.get("snippet"))[:2_000]
                        if item.get("snippet")
                        else None,
                        "display_link": str(item.get("displayLink"))[:300]
                        if item.get("displayLink")
                        else None,
                    }
                )
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
