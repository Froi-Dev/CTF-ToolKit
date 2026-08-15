from __future__ import annotations

import json
import math
from collections import Counter

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa

from app.schemas.crypto import ArtifactDetection, ByteAnalysis


_MAGIC: tuple[tuple[bytes, str, str, str], ...] = (
    (b"\x89PNG\r\n\x1a\n", "png", "PNG image", "image/png"),
    (b"\xff\xd8\xff", "jpeg", "JPEG image", "image/jpeg"),
    (b"GIF87a", "gif", "GIF image", "image/gif"),
    (b"GIF89a", "gif", "GIF image", "image/gif"),
    (b"%PDF-", "pdf", "PDF document", "application/pdf"),
    (b"PK\x03\x04", "zip", "ZIP archive", "application/zip"),
    (b"\x1f\x8b", "gzip", "GZIP stream", "application/gzip"),
    (b"\x78\x01", "zlib", "Zlib compressed stream", "application/zlib"),
    (b"\x78\x9c", "zlib", "Zlib compressed stream", "application/zlib"),
    (b"\x78\xda", "zlib", "Zlib compressed stream", "application/zlib"),
    (b"Rar!\x1a\x07", "rar", "RAR archive", "application/vnd.rar"),
    (b"7z\xbc\xaf'\x1c", "7z", "7z archive", "application/x-7z-compressed"),
    (b"\x7fELF", "elf", "ELF executable", "application/x-elf"),
    (b"MZ", "pe", "PE executable", "application/vnd.microsoft.portable-executable"),
    (b"SQLite format 3\x00", "sqlite", "SQLite database", "application/vnd.sqlite3"),
)


def _key_details(key: object) -> dict[str, str | int | bool]:
    if isinstance(key, (rsa.RSAPrivateKey, rsa.RSAPublicKey)):
        public = key.public_key() if isinstance(key, rsa.RSAPrivateKey) else key
        numbers = public.public_numbers()
        return {
            "algorithm": "RSA",
            "key_size": public.key_size,
            "public_exponent": numbers.e,
            "private": isinstance(key, rsa.RSAPrivateKey),
        }
    if isinstance(key, (ec.EllipticCurvePrivateKey, ec.EllipticCurvePublicKey)):
        public = key.public_key() if isinstance(key, ec.EllipticCurvePrivateKey) else key
        return {
            "algorithm": "EC",
            "curve": public.curve.name,
            "key_size": public.key_size,
            "private": isinstance(key, ec.EllipticCurvePrivateKey),
        }
    return {"algorithm": type(key).__name__}


def _crypto_artifact(data: bytes) -> ArtifactDetection | None:
    if b"-----BEGIN ENCRYPTED PRIVATE KEY-----" in data:
        return ArtifactDetection(
            kind="encrypted-private-key",
            label="Encrypted private key",
            mime="application/x-pem-file",
            confidence=0.99,
            details={"format": "PEM", "private": True, "encrypted": True},
            send_to_decryptor=True,
        )
    loaders: tuple[tuple[str, object], ...]
    if data.lstrip().startswith(b"-----BEGIN"):
        loaders = (
            ("private", lambda: serialization.load_pem_private_key(data, password=None)),
            ("public", lambda: serialization.load_pem_public_key(data)),
            ("certificate", lambda: x509.load_pem_x509_certificate(data)),
        )
        format_name = "PEM"
    elif data.startswith(b"\x30"):
        loaders = (
            ("private", lambda: serialization.load_der_private_key(data, password=None)),
            ("public", lambda: serialization.load_der_public_key(data)),
            ("certificate", lambda: x509.load_der_x509_certificate(data)),
        )
        format_name = "DER"
    else:
        return None

    for kind, loader in loaders:
        try:
            parsed = loader()
        except (TypeError, ValueError):
            continue
        if kind == "certificate":
            public_key = parsed.public_key()
            details = _key_details(public_key)
            details["format"] = format_name
            return ArtifactDetection(
                kind="certificate",
                label=f"{details.get('algorithm', '')} certificate".strip(),
                mime="application/x-x509-ca-cert",
                confidence=0.99,
                details=details,
                send_to_decryptor=True,
            )
        details = _key_details(parsed)
        details["format"] = format_name
        algorithm = str(details.get("algorithm", "cryptographic"))
        return ArtifactDetection(
            kind=f"{algorithm.lower()}-{kind}-key",
            label=f"{algorithm} {kind} key",
            mime="application/x-pem-file" if format_name == "PEM" else "application/pkcs8",
            confidence=0.99,
            details=details,
            send_to_decryptor=True,
        )
    return None


def detect_artifacts(data: bytes) -> list[ArtifactDetection]:
    artifacts: list[ArtifactDetection] = []
    crypto = _crypto_artifact(data)
    if crypto is not None:
        artifacts.append(crypto)

    for magic, kind, label, mime in _MAGIC:
        if data.startswith(magic):
            artifacts.append(
                ArtifactDetection(
                    kind=kind,
                    label=label,
                    mime=mime,
                    confidence=0.99,
                    details={},
                    send_to_decryptor=False,
                )
            )
            break

    stripped = data.lstrip()
    if stripped[:1] in {b"{", b"["}:
        try:
            json.loads(data.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            pass
        else:
            artifacts.append(
                ArtifactDetection(
                    kind="json", label="JSON document", mime="application/json", confidence=0.98
                )
            )
    if stripped.startswith(b"<?xml") or (
        stripped.startswith(b"<") and stripped.rstrip().endswith(b">")
    ):
        artifacts.append(
            ArtifactDetection(
                kind="xml", label="Possible XML document", mime="application/xml", confidence=0.75
            )
        )
    return artifacts


def analyze_bytes(data: bytes, artifacts: list[ArtifactDetection] | None = None) -> ByteAnalysis:
    counts = Counter(data)
    entropy = -sum((count / len(data)) * math.log2(count / len(data)) for count in counts.values()) if data else 0.0
    printable = (
        sum(byte in (9, 10, 13) or 32 <= byte <= 126 for byte in data) / len(data)
        if data
        else 1.0
    )
    try:
        data.decode("utf-8")
    except UnicodeDecodeError:
        utf8 = False
    else:
        utf8 = True
    detected = artifacts if artifacts is not None else detect_artifacts(data)
    return ByteAnalysis(
        length=len(data),
        entropy=round(entropy, 4),
        printable=round(printable, 4),
        utf8=utf8,
        magic=detected[0].label if detected else None,
    )
