from __future__ import annotations

import json
import time
from dataclasses import dataclass, field

import httpx


MAX_PROVIDER_RESPONSE_BYTES = 2 * 1024 * 1024


@dataclass(slots=True)
class AdapterOutput:
    name: str
    source: str
    records: list[dict[str, object]] = field(default_factory=list)
    status: str = "success"
    error: str | None = None
    duration_ms: int = 0


class ProviderResponseError(RuntimeError):
    pass


async def bounded_json(
    client: httpx.AsyncClient,
    url: str,
    *,
    params: dict[str, str | int] | None = None,
    headers: dict[str, str] | None = None,
    maximum_bytes: int = MAX_PROVIDER_RESPONSE_BYTES,
    follow_redirects: bool = False,
) -> tuple[httpx.Response, object]:
    async with client.stream(
        "GET",
        url,
        params=params,
        headers=headers,
        follow_redirects=follow_redirects,
    ) as response:
        chunks: list[bytes] = []
        size = 0
        async for chunk in response.aiter_bytes():
            size += len(chunk)
            if size > maximum_bytes:
                raise ProviderResponseError(
                    "Provider response exceeded the configured size limit."
                )
            chunks.append(chunk)
        body = b"".join(chunks)
    if not body:
        return response, None
    try:
        return response, json.loads(body)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ProviderResponseError("Provider returned malformed JSON.") from exc


def elapsed_ms(started: float) -> int:
    return max(0, round((time.monotonic() - started) * 1_000))


def clean_error(exc: Exception) -> str:
    if isinstance(exc, httpx.TimeoutException):
        return "The provider request timed out."
    if isinstance(exc, httpx.HTTPError):
        return "The provider request failed."
    return str(exc)[:300] or exc.__class__.__name__
