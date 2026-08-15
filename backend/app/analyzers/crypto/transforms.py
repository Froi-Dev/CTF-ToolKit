from __future__ import annotations

import base64
import binascii
import codecs
import html
import re
import time
import zlib
from dataclasses import dataclass
from urllib.parse import unquote_to_bytes

from app.core.errors import DecoderInputError

_BASE64_RE = re.compile(rb"[A-Za-z0-9+/_-]+={0,2}")
_BASE32_RE = re.compile(rb"[A-Z2-7]+=*", re.IGNORECASE)
_HEX_RE = re.compile(rb"[0-9a-f]+", re.IGNORECASE)
_BINARY_RE = re.compile(rb"[01]+")
_PERCENT_RE = re.compile(rb"%[0-9a-f]{2}", re.IGNORECASE)
_BASE58_ALPHABET = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
_OCTAL_TOKEN_RE = re.compile(rb"(?:0o)?([0-7]{1,3})")
_DECIMAL_TOKEN_RE = re.compile(rb"[0-9]{1,3}")
_MORSE: dict[str, str] = {
    ".-": "A", "-...": "B", "-.-.": "C", "-..": "D", ".": "E",
    "..-.": "F", "--.": "G", "....": "H", "..": "I", ".---": "J",
    "-.-": "K", ".-..": "L", "--": "M", "-.": "N", "---": "O",
    ".--.": "P", "--.-": "Q", ".-.": "R", "...": "S", "-": "T",
    "..-": "U", "...-": "V", ".--": "W", "-..-": "X", "-.--": "Y",
    "--..": "Z", "-----": "0", ".----": "1", "..---": "2", "...--": "3",
    "....-": "4", ".....": "5", "-....": "6", "--...": "7", "---..": "8",
    "----.": "9",
}


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


def decode_base58(data: bytes) -> bytes | None:
    compact = _ascii_compact(data)
    if not compact or len(compact) < 2 or any(byte not in _BASE58_ALPHABET for byte in compact):
        return None
    number = 0
    for byte in compact:
        number = number * 58 + _BASE58_ALPHABET.index(byte)
    body = number.to_bytes((number.bit_length() + 7) // 8, "big") if number else b""
    leading = len(compact) - len(compact.lstrip(b"1"))
    return b"\x00" * leading + body


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


def decode_octal(data: bytes) -> bytes | None:
    compact = data.strip()
    if not compact:
        return None
    tokens = re.split(rb"[\s,;:_-]+", compact)
    matches = [_OCTAL_TOKEN_RE.fullmatch(token) for token in tokens if token]
    if not matches or any(match is None for match in matches):
        return None
    values = [int(match.group(1), 8) for match in matches if match is not None]
    return bytes(values) if all(value <= 255 for value in values) else None


def decode_decimal_ascii(data: bytes) -> bytes | None:
    tokens = [token for token in re.split(rb"[\s,;:_-]+", data.strip()) if token]
    if len(tokens) < 2 or any(_DECIMAL_TOKEN_RE.fullmatch(token) is None for token in tokens):
        return None
    values = [int(token) for token in tokens]
    return bytes(values) if all(value <= 255 for value in values) else None


def decode_url(data: bytes) -> bytes | None:
    if not _PERCENT_RE.search(data):
        return None
    try:
        decoded = unquote_to_bytes(data.decode("ascii").replace("+", " "))
    except UnicodeDecodeError:
        return None
    return decoded if decoded != data else None


def decode_html_entities(data: bytes) -> bytes | None:
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        return None
    decoded = html.unescape(text)
    return decoded.encode("utf-8") if decoded != text else None


def decode_unicode_escapes(data: bytes) -> bytes | None:
    if not re.search(rb"\\(?:u[0-9a-fA-F]{4}|U[0-9a-fA-F]{8}|x[0-9a-fA-F]{2})", data):
        return None
    try:
        text = data.decode("ascii")
        decoded = codecs.decode(text, "unicode_escape")
    except (UnicodeDecodeError, ValueError):
        return None
    return decoded.encode("utf-8")


def decode_escaped_bytes(data: bytes) -> bytes | None:
    if not re.fullmatch(rb"(?:\\x[0-9a-fA-F]{2}|[\s,;:_-])+", data.strip()):
        return None
    try:
        return bytes.fromhex(re.sub(rb"\\x|[\s,;:_-]", b"", data).decode("ascii"))
    except ValueError:
        return None


def decode_morse(data: bytes) -> bytes | None:
    try:
        text = data.decode("ascii").strip()
    except UnicodeDecodeError:
        return None
    if not text or any(character not in ".-/ |\t\r\n" for character in text):
        return None
    words = re.split(r"\s*(?:/|\|)\s*", text)
    decoded_words: list[str] = []
    for word in words:
        symbols = word.split()
        if not symbols or any(symbol not in _MORSE for symbol in symbols):
            return None
        decoded_words.append("".join(_MORSE[symbol] for symbol in symbols))
    return " ".join(decoded_words).encode("ascii")


def rotate47(data: bytes) -> bytes:
    return bytes(33 + ((byte - 33 + 47) % 94) if 33 <= byte <= 126 else byte for byte in data)


def decode_utf16(data: bytes) -> bytes | None:
    if len(data) < 4 or len(data) % 2:
        return None
    if not (data.startswith((b"\xff\xfe", b"\xfe\xff")) or data[::2].count(0) > len(data) // 6 or data[1::2].count(0) > len(data) // 6):
        return None
    try:
        encoding = "utf-16" if data.startswith((b"\xff\xfe", b"\xfe\xff")) else ("utf-16-le" if data[1::2].count(0) >= data[::2].count(0) else "utf-16-be")
        return data.decode(encoding).encode("utf-8")
    except UnicodeDecodeError:
        return None


def decode_gzip(data: bytes, maximum_output: int = 65_536) -> bytes | None:
    if not data.startswith(b"\x1f\x8b"):
        return None
    try:
        decompressor = zlib.decompressobj(16 + zlib.MAX_WBITS)
        decoded = decompressor.decompress(data, maximum_output + 1)
        if len(decoded) > maximum_output or decompressor.unconsumed_tail or not decompressor.eof:
            return None
        decoded += decompressor.flush(maximum_output + 1 - len(decoded))
    except zlib.error:
        return None
    return decoded if len(decoded) <= maximum_output else None


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
        (decode_base58, "Base58", "base58"),
        (decode_octal, "Octal", "octal"),
        (decode_decimal_ascii, "Decimal ASCII", "decimal-ascii"),
        (decode_html_entities, "HTML Entities", "html"),
        (decode_unicode_escapes, "Unicode Escapes", "unicode"),
        (decode_escaped_bytes, "Escaped Bytes", "escaped-bytes"),
        (decode_morse, "Morse", "morse"),
        (decode_utf16, "UTF-16", "utf16"),
        (decode_gzip, "Gunzip", "gzip"),
    ):
        decoded = decoder(data)
        if decoded is not None:
            outputs.append(TransformOutput(decoded, name, None, family))

    outputs.extend(decode_base85(data))

    if previous_family != "rot47" and data and all(byte in (9, 10, 13) or 32 <= byte <= 126 for byte in data):
        outputs.append(TransformOutput(rotate47(data), "ROT47", None, "rot47"))

    if previous_family != "caesar" and _looks_alphabetic(data):
        outputs.append(TransformOutput(rotate_ascii(data, 13), "ROT13", None, "caesar"))
        for shift in range(1, 26):
            if shift == 13:
                continue
            outputs.append(TransformOutput(rotate_ascii(data, shift), "Caesar", str(shift), "caesar"))

    if previous_family != "xor" and time.monotonic() < deadline:
        for value in xor_keys:
            key = parse_xor_key(value)
            parameter = value if value.lower().startswith(("0x", "hex:", "text:")) else f"text:{value}"
            outputs.append(TransformOutput(apply_xor(data, key), "XOR", parameter, "xor"))

    unique: dict[bytes, TransformOutput] = {}
    for output in outputs:
        if output.data and output.data != data and len(output.data) <= 65_536:
            unique.setdefault(output.data, output)
    return list(unique.values())
