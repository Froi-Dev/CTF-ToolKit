from __future__ import annotations

import base64
import binascii
import re

from app.integrations.tshark import ReconstructedStream
from app.schemas.network import PlaintextCredential

_FORM_CREDENTIAL = re.compile(
    rb"(?i)(?:user(?:name)?|login)=([^&\s]{1,256}).{0,512}?(?:pass(?:word)?|pwd)=([^&\s]{1,256})"
)
_BASIC_AUTH = re.compile(rb"(?im)^Authorization:\s*Basic\s+([A-Za-z0-9+/=]{4,2048})\s*$")


def decode_basic(encoded: str | bytes) -> tuple[str, str] | None:
    try:
        raw = base64.b64decode(encoded, validate=True).decode("utf-8")
    except (binascii.Error, UnicodeDecodeError, ValueError):
        return None
    if ":" not in raw:
        return None
    username, secret = raw.split(":", 1)
    return username, secret


def detect_stream_credentials(
    streams: tuple[ReconstructedStream, ...],
) -> list[PlaintextCredential]:
    credentials: list[PlaintextCredential] = []
    for stream in streams:
        for match in _BASIC_AUTH.finditer(stream.data):
            decoded = decode_basic(match.group(1))
            if decoded:
                credentials.append(
                    PlaintextCredential(
                        protocol="http-basic",
                        username=decoded[0],
                        secret=decoded[1],
                        frame_number=None,
                        stream_id=stream.stream_id,
                        source=f"Reconstructed TCP stream {stream.stream_id}",
                        confidence=0.98,
                    )
                )
        for match in _FORM_CREDENTIAL.finditer(stream.data):
            credentials.append(
                PlaintextCredential(
                    protocol="http-form",
                    username=match.group(1).decode("utf-8", errors="replace"),
                    secret=match.group(2).decode("utf-8", errors="replace"),
                    frame_number=None,
                    stream_id=stream.stream_id,
                    source=f"URL-encoded form in TCP stream {stream.stream_id}",
                    confidence=0.90,
                )
            )
    return credentials


def deduplicate_credentials(
    credentials: list[PlaintextCredential],
) -> list[PlaintextCredential]:
    unique: list[PlaintextCredential] = []
    identities: set[tuple[str, str | None, str, int | None]] = set()
    for credential in credentials:
        identity = (
            credential.protocol,
            credential.username,
            credential.secret,
            credential.stream_id,
        )
        if identity not in identities:
            identities.add(identity)
            unique.append(credential)
    return unique
