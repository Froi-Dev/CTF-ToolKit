from __future__ import annotations

import base64
import binascii
import re
import time
from dataclasses import dataclass
from urllib.parse import unquote_to_bytes

from app.core.errors import DecoderInputError
from app.core.scoring import quick_text_score

_BASE64_RE = re.compile(rb"[A-Za-z0-9+/_-]+={0,2}")
_BASE32_RE = re.compile(rb"[A-Z2-7]+=*", re.IGNORECASE)
_HEX_RE = re.compile(rb"[0-9a-f]+", re.IGNORECASE)
_BINARY_RE = re.compile(rb"[01]+")
_PERCENT_RE = re.compile(rb"%[0-9a-f]{2}", re.IGNORECASE)


@dataclass(frozen=True, slots=True)
class TransformOutput:
    data: bytes
    transform: str
    parameter: str | None = None
    family: str = ""


def _ascii_compact(data: bytes) -> bytes | None:
    try:
        return b"".join(data.split()).strip()
    except (AttributeError, TypeError):
        return None


def decode_base64(data: bytes) -> bytes | None:
    compact = _ascii_compact(data)
    if not compact or len(compact) < 4 or not _BASE64_RE.fullmatch(compact):
        return None
    if len(compact) % 4 == 1:
        return None
    padded = compact + b"=" * ((-len(compact)) % 4)
    try:
        return base64.b64decode(padded, altchars=b"-_", validate=True)
    except (binascii.Error, ValueError):
        return None


def decode_base32(data: bytes) -> bytes | None:
    compact = _ascii_compact(data)
    if not compact or len(compact) < 8 or not _BASE32_RE.fullmatch(compact):
        return None
    unpadded = compact.rstrip(b"=")
    padded = unpadded + b"=" * ((-len(unpadded)) % 8)
    try:
        return base64.b32decode(padded, casefold=True)
    except (binascii.Error, ValueError):
        return None


def decode_base85(data: bytes) -> list[TransformOutput]:
    compact = _ascii_compact(data)
    if not compact or len(compact) < 5:
        return []
    outputs: list[TransformOutput] = []
    ascii85_body = compact[2:-2] if compact.startswith(b"<~") and compact.endswith(b"~>") else compact
    if ascii85_body and all(33 <= byte <= 117 or byte in b"yz" for byte in ascii85_body):
        try:
            decoded = base64.a85decode(compact, adobe=compact.startswith(b"<~"))
        except (binascii.Error, ValueError, OverflowError):
            pass
        else:
            outputs.append(TransformOutput(decoded, "Base85", "Ascii85", "base85"))
    try:
        decoded = base64.b85decode(compact)
    except (binascii.Error, ValueError):
        pass
    else:
        outputs.append(TransformOutput(decoded, "Base85", "RFC 1924", "base85"))
    return outputs


def decode_hex(data: bytes) -> bytes | None:
    compact = re.sub(rb"0x", b"", data, flags=re.IGNORECASE)
    compact = re.sub(rb"[\s:_-]", b"", compact)
    if not compact or len(compact) % 2 or not _HEX_RE.fullmatch(compact):
        return None
    try:
        return bytes.fromhex(compact.decode("ascii"))
    except (ValueError, UnicodeDecodeError):
        return None


def decode_binary(data: bytes) -> bytes | None:
    compact = re.sub(rb"0b", b"", data, flags=re.IGNORECASE)
    compact = re.sub(rb"[\s_]", b"", compact)
    if not compact or len(compact) % 8 or not _BINARY_RE.fullmatch(compact):
        return None
    return bytes(int(compact[index : index + 8], 2) for index in range(0, len(compact), 8))


def decode_url(data: bytes) -> bytes | None:
    if not _PERCENT_RE.search(data):
        return None
    try:
        decoded = unquote_to_bytes(data.decode("ascii").replace("+", " "))
    except UnicodeDecodeError:
        return None
    return decoded if decoded != data else None


def rotate_ascii(data: bytes, shift: int) -> bytes:
    output = bytearray()
    for byte in data:
        if 65 <= byte <= 90:
            output.append((byte - 65 - shift) % 26 + 65)
        elif 97 <= byte <= 122:
            output.append((byte - 97 - shift) % 26 + 97)
        else:
            output.append(byte)
    return bytes(output)


def parse_xor_key(value: str) -> bytes:
    if value.lower().startswith("hex:"):
        raw = value[4:].replace(" ", "")
        if not raw or len(raw) % 2:
            raise DecoderInputError(f"Invalid hexadecimal XOR key: {value!r}")
        try:
            return bytes.fromhex(raw)
        except ValueError as exc:
            raise DecoderInputError(f"Invalid hexadecimal XOR key: {value!r}") from exc
    if value.lower().startswith("0x"):
        raw = value[2:]
        if not 1 <= len(raw) <= 2:
            raise DecoderInputError("0x XOR keys must be a single byte")
        try:
            return bytes([int(raw, 16)])
        except ValueError as exc:
            raise DecoderInputError(f"Invalid XOR key: {value!r}") from exc
    literal = value[5:] if value.lower().startswith("text:") else value
    key = literal.encode("utf-8")
    if not key:
        raise DecoderInputError("XOR keys cannot be empty")
    return key


def apply_xor(data: bytes, key: bytes) -> bytes:
    return bytes(byte ^ key[index % len(key)] for index, byte in enumerate(data))


def _looks_alphabetic(data: bytes) -> bool:
    if not data:
        return False
    printable = sum(byte in (9, 10, 13) or 32 <= byte <= 126 for byte in data) / len(data)
    letters = sum(65 <= byte <= 90 or 97 <= byte <= 122 for byte in data) / len(data)
    return printable > 0.9 and letters > 0.45


def _best_single_byte_xor(data: bytes, deadline: float, limit: int = 4) -> list[TransformOutput]:
    ranked: list[tuple[float, int]] = []
    sample = data[:4_096]
    for key in range(1, 256):
        if key % 16 == 0 and time.monotonic() >= deadline:
            break
        decoded_sample = bytes(byte ^ key for byte in sample)
        ranked.append((quick_text_score(decoded_sample), key))
    ranked.sort(reverse=True)
    return [
        TransformOutput(apply_xor(data, bytes([key])), "XOR", f"0x{key:02x}", "xor")
        for _, key in ranked[:limit]
    ]


def generate_transformations(
    data: bytes,
    *,
    xor_keys: list[str],
    deadline: float,
    previous_family: str | None,
) -> list[TransformOutput]:
    outputs: list[TransformOutput] = []

    for decoder, name, family in (
        (decode_base64, "Base64", "base64"),
        (decode_base32, "Base32", "base32"),
        (decode_hex, "Hex", "hex"),
        (decode_binary, "Binary", "binary"),
        (decode_url, "URL", "url"),
    ):
        decoded = decoder(data)
        if decoded is not None:
            outputs.append(TransformOutput(decoded, name, None, family))

    outputs.extend(decode_base85(data))

    if previous_family != "caesar" and _looks_alphabetic(data):
        outputs.append(TransformOutput(rotate_ascii(data, 13), "ROT13", None, "caesar"))
        for shift in range(1, 26):
            if shift == 13:
                continue
            outputs.append(TransformOutput(rotate_ascii(data, shift), "Caesar", str(shift), "caesar"))

    if previous_family != "xor" and time.monotonic() < deadline:
        outputs.extend(_best_single_byte_xor(data, deadline))
        for value in xor_keys:
            key = parse_xor_key(value)
            parameter = value if value.lower().startswith(("0x", "hex:", "text:")) else f"text:{value}"
            outputs.append(TransformOutput(apply_xor(data, key), "XOR", parameter, "xor"))

    unique: dict[bytes, TransformOutput] = {}
    for output in outputs:
        if output.data and output.data != data and len(output.data) <= 65_536:
            unique.setdefault(output.data, output)
    return list(unique.values())
