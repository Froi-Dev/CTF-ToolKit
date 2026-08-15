from __future__ import annotations

import base64
import binascii
import math
import re
import statistics
from collections import Counter
from dataclasses import dataclass

from app.schemas.network import SuspicionReason, SuspicionScore

_BASE64 = re.compile(rb"[A-Za-z0-9+/]{16,}={0,2}")
_BASE32 = re.compile(rb"[A-Z2-7]{16,}={0,6}")
_HEX = re.compile(rb"(?:[0-9a-fA-F]{2}){10,}")
_URL = re.compile(rb"https?://[^\s\x00]{5,}", re.IGNORECASE)
_COMMAND = re.compile(
    rb"(?:powershell|cmd\.exe|/bin/(?:ba)?sh|wget\s|curl\s|nc\s+-|whoami|openssl\s)",
    re.IGNORECASE,
)
_CREDENTIAL = re.compile(rb"(?:pass(?:word)?|token|secret|api[_-]?key)\s*[:=]", re.IGNORECASE)
_FLAG = re.compile(rb"[A-Za-z][A-Za-z0-9_-]{1,31}\{[^\r\n{}]{3,256}\}")
_MAGIC = (
    (b"MZ", "PE executable"),
    (b"\x7fELF", "ELF executable"),
    (b"PK\x03\x04", "ZIP archive"),
    (b"\x1f\x8b", "gzip stream"),
    (b"%PDF", "PDF document"),
    (b"\x89PNG\r\n\x1a\n", "PNG image"),
)


@dataclass(frozen=True, slots=True)
class PacketScore:
    frame_number: int
    score: SuspicionScore
    payload: bytes


@dataclass(frozen=True, slots=True)
class VariationAnalysis:
    reasons: tuple[SuspicionReason, ...]
    hypotheses: tuple[str, ...]
    interpretation: str | None
    confidence: float | None
    changing_fields: tuple[str, ...]
    constant_fields: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class NumericHypothesis:
    transformation: str
    offset: int
    decoded: bytes
    printable_ratio: float


def number(value: str | None, default: int = -1) -> int:
    try:
        return int((value or "").split(",", 1)[0], 0)
    except ValueError:
        return default


def decimal(value: str | None, default: float = 0.0) -> float:
    try:
        return float((value or "").split(",", 1)[0])
    except ValueError:
        return default


def decode_hex(value: str) -> bytes:
    output = bytearray()
    for occurrence in value.split(","):
        compact = occurrence.replace(":", "").strip()
        if not compact or len(compact) % 2:
            continue
        try:
            output.extend(bytes.fromhex(compact))
        except ValueError:
            continue
    return bytes(output)


def entropy(data: bytes) -> float:
    if not data:
        return 0.0
    size = len(data)
    return -sum((count / size) * math.log2(count / size) for count in Counter(data).values())


def printable_ratio(data: bytes) -> float:
    if not data:
        return 0.0
    return sum(byte in b"\t\r\n" or 32 <= byte <= 126 for byte in data) / len(data)


def score_from(reasons: list[SuspicionReason] | tuple[SuspicionReason, ...]) -> SuspicionScore:
    ordered = sorted(reasons, key=lambda item: (-item.score, item.category, item.description))
    return SuspicionScore(total=round(min(100.0, sum(item.score for item in ordered)), 1), reasons=ordered)


def payload_reasons(payload: bytes, *, baseline_size: float | None = None) -> list[SuspicionReason]:
    reasons: list[SuspicionReason] = []
    if not payload:
        return reasons
    payload_entropy = entropy(payload)
    ratio = printable_ratio(payload)
    if len(payload) >= 24 and payload_entropy >= 7.2:
        reasons.append(SuspicionReason(category="payload-entropy", description=f"Payload entropy is {payload_entropy:.2f} bits/byte, consistent with compressed or encrypted data", score=16, evidence={"entropy": round(payload_entropy, 3), "bytes": len(payload)}))
    elif len(payload) >= 24 and payload_entropy <= 1.2:
        reasons.append(SuspicionReason(category="payload-entropy", description=f"Payload entropy is unusually low at {payload_entropy:.2f} bits/byte", score=6, evidence={"entropy": round(payload_entropy, 3), "bytes": len(payload)}))

    compact = b"".join(payload.split())
    if len(compact) >= 16 and _BASE64.fullmatch(compact):
        try:
            decoded = base64.b64decode(compact, validate=True)
        except (ValueError, binascii.Error):
            decoded = b""
        decoded_ratio = printable_ratio(decoded)
        score = 18 if decoded and decoded_ratio >= 0.7 else 10
        reasons.append(SuspicionReason(category="encoded", description=f"{len(compact)} payload bytes use a Base64-compatible alphabet" + (f" and decode to {decoded_ratio:.0%} printable data" if decoded else ""), score=score, evidence={"encoding": "base64", "encoded_bytes": len(compact), "decoded_printable_ratio": round(decoded_ratio, 3)}))
    elif len(compact) >= 16 and _BASE32.fullmatch(compact):
        reasons.append(SuspicionReason(category="encoded", description=f"{len(compact)} payload bytes use a Base32-compatible alphabet", score=11, evidence={"encoding": "base32", "encoded_bytes": len(compact)}))
    elif len(compact) >= 20 and _HEX.fullmatch(compact):
        reasons.append(SuspicionReason(category="encoded", description=f"Payload contains a {len(compact)}-character hexadecimal string", score=9, evidence={"encoding": "hex", "characters": len(compact)}))
    if _FLAG.search(payload):
        reasons.append(SuspicionReason(category="flag-pattern", description="Payload contains a brace-delimited flag-like value", score=35, evidence={"pattern": "prefix{value}"}))
    if match := _COMMAND.search(payload):
        reasons.append(SuspicionReason(category="command", description=f"Payload contains command fragment {match.group(0).decode('ascii', errors='replace')!r}", score=22, evidence={"fragment": match.group(0).decode("ascii", errors="replace")}))
    if _CREDENTIAL.search(payload):
        reasons.append(SuspicionReason(category="credential", description="Payload contains a credential or secret assignment marker", score=17, evidence={}))
    if _URL.search(payload):
        reasons.append(SuspicionReason(category="url", description="Payload contains an HTTP or HTTPS URL", score=7, evidence={}))
    for signature, label in _MAGIC:
        if payload.startswith(signature):
            reasons.append(SuspicionReason(category="file-magic", description=f"Payload begins with {label} magic bytes", score=18, evidence={"file_type": label}))
            break
    if len(payload) >= 64 and ratio >= 0.95:
        reasons.append(SuspicionReason(category="printable", description=f"Payload contains {len(payload)} bytes that are {ratio:.0%} printable", score=6, evidence={"printable_ratio": round(ratio, 3), "bytes": len(payload)}))
    if baseline_size and baseline_size > 0 and len(payload) >= max(64, baseline_size * 4):
        deviation = len(payload) / baseline_size
        reasons.append(SuspicionReason(category="capture-baseline", description=f"Payload is {deviation:.1f}x the capture median of {baseline_size:.0f} bytes", score=10, evidence={"payload_bytes": len(payload), "capture_median_bytes": baseline_size, "deviation": round(deviation, 2)}))
    return reasons


def score_packet(
    row: dict[str, str],
    *,
    baseline_payload_size: float | None,
    port_frequency: Counter[tuple[str, int]],
) -> PacketScore:
    transport = "tcp" if row.get("tcp.srcport") or row.get("tcp.dstport") else "udp" if row.get("udp.srcport") or row.get("udp.dstport") else ""
    payload = decode_hex(row.get(f"{transport}.payload", "") or row.get("data.data", "")) if transport else decode_hex(row.get("data.data", ""))
    reasons = payload_reasons(payload, baseline_size=baseline_payload_size)
    destination_port = number(row.get(f"{transport}.dstport")) if transport else -1
    if destination_port > 1024 and port_frequency[(transport, destination_port)] <= 3:
        reasons.append(SuspicionReason(category="rare-port", description=f"Destination {transport.upper()} port {destination_port} appears in only {port_frequency[(transport, destination_port)]} decoded packets", score=8, evidence={"transport": transport, "port": destination_port, "packets": port_frequency[(transport, destination_port)]}))
    ttl = number(row.get("ip.ttl"))
    if ttl not in {-1, 32, 64, 128, 255} and ttl < 16:
        reasons.append(SuspicionReason(category="header", description=f"IPv4 TTL is unusually low at {ttl}", score=5, evidence={"ip.ttl": ttl}))
    flags = number(row.get("tcp.flags"))
    if transport == "tcp" and flags >= 0 and (flags & 0x03) == 0x03:
        reasons.append(SuspicionReason(category="tcp-flags", description="TCP SYN and FIN flags are set together", score=15, evidence={"tcp.flags": hex(flags)}))
    return PacketScore(frame_number=max(1, number(row.get("frame.number"), 1)), score=score_from(reasons), payload=payload)


def capture_baseline(rows: tuple[dict[str, str], ...] | list[dict[str, str]]) -> tuple[float | None, Counter[tuple[str, int]]]:
    sizes: list[int] = []
    ports: Counter[tuple[str, int]] = Counter()
    for row in rows:
        transport = "tcp" if row.get("tcp.srcport") or row.get("tcp.dstport") else "udp" if row.get("udp.srcport") or row.get("udp.dstport") else ""
        if not transport:
            continue
        payload = decode_hex(row.get(f"{transport}.payload", "") or row.get("data.data", ""))
        if payload:
            sizes.append(len(payload))
        for side in ("srcport", "dstport"):
            port = number(row.get(f"{transport}.{side}"))
            if port >= 0:
                ports[(transport, port)] += 1
    return (statistics.median(sizes) if sizes else None), ports


def analyze_field_variation(rows: list[dict[str, str]]) -> VariationAnalysis:
    fields = ("ip.src", "ip.dst", "udp.srcport", "udp.dstport", "tcp.srcport", "tcp.dstport", "ip.id", "ip.ttl")
    values = {field: [(row.get(field) or "").split(",", 1)[0] for row in rows] for field in fields}
    constants = tuple(field for field, items in values.items() if items and items[0] and len(set(items)) == 1)
    changing = tuple(field for field, items in values.items() if len({item for item in items if item}) >= max(3, len(rows) // 2))
    reasons: list[SuspicionReason] = []
    hypotheses: list[str] = []
    interpretation = None
    confidence = None
    if len(rows) >= 4 and constants and changing:
        reasons.append(SuspicionReason(category="field-variation", description=f"{len(changing)} header field(s) vary while {len(constants)} related field(s) remain constant across {len(rows)} packets", score=16, evidence={"changing_fields": list(changing), "constant_fields": list(constants), "packets": len(rows)}))
    best: tuple[str, NumericHypothesis] | None = None
    for field in changing:
        numeric = [number(value) for value in values[field]]
        if any(value < 0 for value in numeric):
            continue
        hypothesis = numeric_hypothesis(numeric)
        if hypothesis and (best is None or hypothesis.printable_ratio > best[1].printable_ratio):
            best = field, hypothesis
    if best and best[1].printable_ratio >= 0.70:
        field, hypothesis = best
        ratio = hypothesis.printable_ratio
        transformation = f"{field}: {hypothesis.transformation}"
        offset = hypothesis.offset
        decoded = hypothesis.decoded
        score = 19 if ratio >= 0.85 else 12
        printable_values = sum(byte in {9, 10, 13} or 32 <= byte <= 126 for byte in decoded)
        reasons.append(SuspicionReason(category="covert-channel", description=f"Applying {transformation} produces printable ASCII for {printable_values}/{len(decoded)} values ({ratio:.0%})", score=score, evidence={"transformation": transformation, "printable_ratio": round(ratio, 3), "offset": offset, "preview": bytes(byte if 32 <= byte <= 126 else 46 for byte in decoded[:80]).decode("ascii")}))
        interpretation = "Possible header-field covert channel"
        confidence = round(min(0.95, 0.45 + ratio * 0.45), 2)
        hypotheses.append(f"Possible covert channel in {transformation.split(':', 1)[0]}; the transformation is a hypothesis, not a confirmed decoder.")
    elif changing:
        hypotheses.append("Structured header-field variation warrants manual inspection; no tested numeric transformation produced reliably printable output.")
    return VariationAnalysis(tuple(reasons), tuple(hypotheses), interpretation, confidence, changing, constants)


def numeric_hypothesis(
    values: list[int],
    *,
    evidence_offsets: tuple[int, ...] = (),
) -> NumericHypothesis | None:
    """Test a small evidence-bounded family of numeric covert-channel transforms."""
    if len(values) < 4 or len(set(values)) < 3:
        return None
    differences = [right - left for left, right in zip(values, values[1:])]
    if differences and len(set(differences)) == 1 and abs(differences[0]) <= 2:
        return None
    transforms = [("value & 0xff", 0, bytes(value & 0xFF for value in values))]
    offsets = tuple(dict.fromkeys((*evidence_offsets, 1000, 2000, 3000, 4000, 5000)))
    transforms.extend(
        (f"value - {offset}", offset, bytes(value - offset for value in values))
        for offset in offsets
        if offset and all(0 <= value - offset <= 255 for value in values)
    )
    best: NumericHypothesis | None = None
    for name, offset, decoded in transforms:
        ratio = printable_ratio(decoded)
        structured = sum(chr(byte).isalnum() or byte in b"{}_-=:/ ." for byte in decoded)
        if len(set(decoded)) < 3 or structured < max(3, len(decoded) // 2):
            continue
        candidate = NumericHypothesis(name, offset, decoded, ratio)
        if best is None or candidate.printable_ratio > best.printable_ratio:
            best = candidate
    return best
