from __future__ import annotations

import base64
import binascii
import codecs
import re
from collections import defaultdict
from dataclasses import dataclass, field

from app.analyzers.network.parsing import hex_bytes, integer
from app.core.flag_detection import DetectedFlag, FlagDetector
from app.integrations.tshark import ReconstructedStream


_BASE64_TOKEN = re.compile(rb"(?<![A-Za-z0-9+/])([A-Za-z0-9+/]{8,4096}={0,2})(?![A-Za-z0-9+/=])")
_BASE64_VALUE = re.compile(rb"[A-Za-z0-9+/]{2,4096}={0,2}")
_CELL_ID = re.compile(r"(?i)\b(?:cell[\s_-]*id|cellid)\s*[:=]\s*['\"]?([0-9]{3,10})")
_IMSI = re.compile(r"(?i)\bimsi\s*[:=]\s*['\"]?([0-9]{14,16})")
_PRINTABLE = frozenset(range(32, 127)) | {9, 10, 13}
_MAX_EVIDENCE_TEXT = 4096


@dataclass(frozen=True, slots=True)
class PacketPayload:
    frame_number: int
    source: str
    destination: str
    source_port: int | None
    destination_port: int | None
    transport: str
    tcp_stream: int | None
    udp_stream: int | None
    data: bytes
    http_body: bytes
    http_method: str
    http_host: str
    http_uri: str
    user_agent: str


@dataclass(frozen=True, slots=True)
class PayloadInsight:
    title: str
    category: str
    value: str
    source: str
    frame_numbers: tuple[int, ...] = ()
    stream_id: int | None = None
    confidence: float = 0.8
    decoding_steps: tuple[str, ...] = ()
    metadata: dict[str, str | int | float | bool | None] = field(default_factory=dict)


@dataclass(frozen=True, slots=True)
class PayloadFlag:
    detected: DetectedFlag
    source: str
    stream_id: int | None = None
    frame_numbers: tuple[int, ...] = ()
    decoding_steps: tuple[str, ...] = ()
    confidence: float | None = None


@dataclass(frozen=True, slots=True)
class PayloadAnalysis:
    insights: tuple[PayloadInsight, ...]
    flags: tuple[PayloadFlag, ...]


@dataclass(frozen=True, slots=True)
class _DecodedAssembly:
    source: str
    frame_numbers: tuple[int, ...]
    stream_id: int | None
    data: bytes
    fragment_count: int


def packet_payloads(rows: tuple[dict[str, str], ...]) -> tuple[PacketPayload, ...]:
    observations: list[PacketPayload] = []
    for row in rows:
        transport = "tcp" if row.get("tcp.srcport") or row.get("tcp.dstport") else "udp" if row.get("udp.srcport") or row.get("udp.dstport") else ""
        if not transport:
            continue
        transport_data = hex_bytes(
            row.get(f"{transport}.payload", "") or row.get("data.data", "")
        )
        http_body = hex_bytes(row.get("http.file_data", ""))
        user_agent = row.get("http.user_agent", "")
        if not transport_data and not http_body and not user_agent:
            continue
        observations.append(
            PacketPayload(
                frame_number=integer(row.get("frame.number", ""), -1),
                source=(row.get("ip.src") or row.get("ipv6.src") or row.get("eth.src") or "").split(",", 1)[0],
                destination=(row.get("ip.dst") or row.get("ipv6.dst") or row.get("eth.dst") or "").split(",", 1)[0],
                source_port=_optional_integer(row.get(f"{transport}.srcport", "")),
                destination_port=_optional_integer(row.get(f"{transport}.dstport", "")),
                transport=transport,
                tcp_stream=_optional_integer(row.get("tcp.stream", "")),
                udp_stream=_optional_integer(row.get("udp.stream", "")),
                data=transport_data,
                http_body=http_body,
                http_method=row.get("http.request.method", "").upper(),
                http_host=row.get("http.host", ""),
                http_uri=row.get("http.request.uri", ""),
                user_agent=user_agent,
            )
        )
    return tuple(observations)


def analyze_hidden_payloads(
    rows: tuple[dict[str, str], ...],
    streams: tuple[ReconstructedStream, ...],
    detector: FlagDetector,
    *,
    max_insights: int,
    max_flags: int,
) -> PayloadAnalysis:
    observations = packet_payloads(rows)
    insights: list[PayloadInsight] = []
    flags: list[PayloadFlag] = []
    insight_keys: set[tuple[str, str, tuple[int, ...]]] = set()
    flag_keys: set[tuple[str, str, tuple[str, ...]]] = set()

    def add_insight(item: PayloadInsight) -> None:
        key = (item.category, item.value, item.frame_numbers)
        if key not in insight_keys and len(insights) < max_insights:
            insight_keys.add(key)
            insights.append(item)

    def add_flags(
        data: bytes,
        source: str,
        *,
        stream_id: int | None = None,
        frame_numbers: tuple[int, ...] = (),
        decoding_steps: tuple[str, ...] = (),
        confidence: float | None = None,
    ) -> bool:
        found = False
        for detected in detector.detect(data):
            key = (detected.value, source, decoding_steps)
            if key in flag_keys or len(flags) >= max_flags:
                continue
            flag_keys.add(key)
            flags.append(
                PayloadFlag(
                    detected=detected,
                    source=source,
                    stream_id=stream_id,
                    frame_numbers=frame_numbers,
                    decoding_steps=decoding_steps,
                    confidence=confidence,
                )
            )
            found = True
        return found

    for observation in observations:
        if observation.data:
            add_flags(
                observation.data,
                f"{observation.transport.upper()} payload in frame {observation.frame_number}",
                stream_id=observation.tcp_stream,
                frame_numbers=(observation.frame_number,),
            )

    encoded_sources: list[tuple[str, bytes, int | None, tuple[int, ...]]] = []
    for stream in streams:
        encoded_sources.append((f"TCP stream {stream.stream_id}", stream.data, stream.stream_id, ()))
    for observation in observations:
        payload = observation.http_body or observation.data
        if payload:
            encoded_sources.append(
                (
                    f"{observation.transport.upper()} payload in frame {observation.frame_number}",
                    payload,
                    observation.tcp_stream,
                    (observation.frame_number,),
                )
            )
    for packets in _group_udp_payloads(observations):
        if len(packets) < 2:
            continue
        data = b"".join(item.data for item in packets)[: 2 * 1024 * 1024]
        stream_id = packets[0].udp_stream
        frames = tuple(item.frame_number for item in packets)
        encoded_sources.append((f"UDP stream {stream_id}", data, None, frames))

    for source, data, stream_id, frame_numbers in encoded_sources:
        rot13 = codecs.decode(data.decode("latin-1"), "rot_13").encode("latin-1")
        if add_flags(
            rot13,
            source,
            stream_id=stream_id,
            frame_numbers=frame_numbers,
            decoding_steps=("ROT13",),
        ):
            add_insight(
                PayloadInsight(
                    title="ROT13-obfuscated flag payload",
                    category="decoded-payload",
                    value=_text_preview(rot13),
                    source=source,
                    frame_numbers=frame_numbers,
                    stream_id=stream_id,
                    confidence=0.95,
                    decoding_steps=("ROT13",),
                )
            )

        for _token, decoded in _base64_fragments(data):
            if add_flags(
                decoded,
                source,
                stream_id=stream_id,
                frame_numbers=frame_numbers,
                decoding_steps=("Base64",),
            ):
                add_insight(
                    PayloadInsight(
                        title="Base64-decoded flag payload",
                        category="decoded-payload",
                        value=_text_preview(decoded),
                        source=source,
                        frame_numbers=frame_numbers,
                        stream_id=stream_id,
                        confidence=0.95,
                        decoding_steps=("Base64",),
                    )
                )

    _detect_udp_broadcasts(observations, add_insight)
    _detect_udp_port_channels(observations, detector, add_insight, add_flags)
    _detect_dns_base64_channel(rows, add_insight, add_flags)

    assemblies = _assemble_base64_fragments(observations)
    for assembly in assemblies:
        has_flag = add_flags(
            assembly.data,
            assembly.source,
            stream_id=assembly.stream_id,
            frame_numbers=assembly.frame_numbers,
            decoding_steps=(f"Base64 decode {assembly.fragment_count} fragments", "capture-order concatenation"),
        )
        if has_flag or _mostly_printable(assembly.data):
            add_insight(
                PayloadInsight(
                    title="Reassembled Base64 payload fragments",
                    category="decoded-payload",
                    value=_text_preview(assembly.data),
                    source=assembly.source,
                    frame_numbers=assembly.frame_numbers,
                    stream_id=assembly.stream_id,
                    confidence=0.95 if has_flag else 0.75,
                    decoding_steps=(f"Base64 decode {assembly.fragment_count} fragments", "capture-order concatenation"),
                    metadata={"fragment_count": assembly.fragment_count},
                )
            )

    _cell_ids, all_imsis, victim_imsis = _correlate_cellular_identifiers(observations, add_insight)
    key_candidates = _imsi_key_candidates(all_imsis, victim_imsis)
    for assembly in assemblies:
        for key, key_description in key_candidates:
            plaintext = _repeating_xor(assembly.data, key.encode("ascii"))
            steps = (
                f"Base64 decode {assembly.fragment_count} fragments",
                "capture-order concatenation",
                f"repeating-key XOR with {key_description}",
            )
            if add_flags(
                plaintext,
                assembly.source,
                stream_id=assembly.stream_id,
                frame_numbers=assembly.frame_numbers,
                decoding_steps=steps,
            ):
                add_insight(
                    PayloadInsight(
                        title="IMSI-derived XOR payload",
                        category="decoded-payload",
                        value=_text_preview(plaintext),
                        source=assembly.source,
                        frame_numbers=assembly.frame_numbers,
                        stream_id=assembly.stream_id,
                        confidence=0.9,
                        decoding_steps=steps,
                        metadata={"key_derivation": key_description},
                    )
                )

    return PayloadAnalysis(tuple(insights), tuple(flags))


def _optional_integer(value: str) -> int | None:
    parsed = integer(value, -1)
    return parsed if parsed >= 0 else None


def _text_preview(data: bytes) -> str:
    return data[:_MAX_EVIDENCE_TEXT].decode("utf-8", errors="replace")


def _mostly_printable(data: bytes) -> bool:
    return bool(data) and sum(byte in _PRINTABLE for byte in data) / len(data) >= 0.85


def _base64_fragments(data: bytes) -> tuple[tuple[bytes, bytes], ...]:
    found: list[tuple[bytes, bytes]] = []
    seen: set[bytes] = set()
    bounded = data[: 2 * 1024 * 1024]
    candidates = [match.group(1) for match in _BASE64_TOKEN.finditer(bounded)]
    stripped = bounded.strip(b" \t\r\n'\"")
    if _BASE64_VALUE.fullmatch(stripped):
        candidates.append(stripped)
    for form_field in re.split(rb"[&;\r\n,]", bounded):
        _separator, found_separator, value = form_field.partition(b"=")
        if found_separator:
            value = value.strip(b" \t'\"")
            if _BASE64_VALUE.fullmatch(value):
                candidates.append(value)

    for token in candidates:
        if token in seen:
            continue
        seen.add(token)
        padded = token + b"=" * (-len(token) % 4)
        try:
            decoded = base64.b64decode(padded, validate=True)
        except (binascii.Error, ValueError):
            continue
        if not decoded:
            continue
        found.append((token, decoded))
    return tuple(found)


def _is_broadcast(destination: str) -> bool:
    lowered = destination.lower()
    return (
        lowered == "255.255.255.255"
        or lowered.endswith(".255")
        or lowered.startswith("ff")
        or lowered == "ff:ff:ff:ff:ff:ff"
    )


def _detect_udp_broadcasts(observations: tuple[PacketPayload, ...], add_insight) -> None:
    for packets in _group_udp_payloads(observations):
        first = packets[0]
        if first.destination_port != 55000 and not _is_broadcast(first.destination):
            continue
        data = b"".join(item.data for item in packets)[:_MAX_EVIDENCE_TEXT]
        if not _mostly_printable(data):
            continue
        frames = tuple(item.frame_number for item in packets)
        add_insight(
            PayloadInsight(
                title="UDP broadcast or test-port payload",
                category="broadcast",
                value=_text_preview(data),
                source=f"UDP stream {first.udp_stream} to {first.destination}:{first.destination_port}",
                frame_numbers=frames,
                confidence=0.8,
                metadata={"destination_port": first.destination_port},
            )
        )


def _detect_udp_port_channels(observations, detector, add_insight, add_flags) -> None:
    grouped: defaultdict[tuple[str, str, int | None], list[PacketPayload]] = defaultdict(list)
    for item in observations:
        if item.transport == "udp":
            grouped[(item.source, item.destination, item.destination_port)].append(item)

    for (_source, _destination, destination_port), packets in grouped.items():
        packets.sort(key=lambda item: item.frame_number)
        start_indices = [index for index, item in enumerate(packets) if b"start" in item.data.lower()]
        end_indices = [index for index, item in enumerate(packets) if b"end" in item.data.lower()]
        for start in start_indices:
            end = next((index for index in end_indices if index > start), None)
            if end is None:
                continue
            encoded = packets[start + 1 : end]
            if len(encoded) < 4 or any(item.source_port is None for item in encoded):
                continue
            ports = [item.source_port for item in encoded if item.source_port is not None]
            base = (min(ports) // 1000) * 1000
            values = [port - base for port in ports]
            if any(value not in _PRINTABLE for value in values):
                continue
            decoded = bytes(values)
            frames = tuple(item.frame_number for item in packets[start : end + 1])
            source = f"UDP source ports to destination port {destination_port}"
            steps = (f"subtract {base} from each source port", "decimal ASCII")
            add_insight(
                PayloadInsight(
                    title="UDP source-port covert channel",
                    category="covert-channel",
                    value=_text_preview(decoded),
                    source=source,
                    frame_numbers=frames,
                    confidence=0.95,
                    decoding_steps=steps,
                    metadata={"port_offset": base, "destination_port": destination_port},
                )
            )
            add_flags(decoded, source, frame_numbers=frames, decoding_steps=steps)
            break


def _detect_dns_base64_channel(rows, add_insight, add_flags) -> None:
    grouped: defaultdict[tuple[str, str, str], list[tuple[int, str]]] = defaultdict(list)
    for row in rows:
        if row.get("dns.flags.response", "").lower() in {"1", "true", "yes", "set"}:
            continue
        query = row.get("dns.qry.name", "").split(",", 1)[0].strip().rstrip(".")
        labels = query.split(".")
        if len(labels) < 3:
            continue
        source = (row.get("ip.src") or row.get("ipv6.src") or "").split(",", 1)[0]
        destination = (row.get("ip.dst") or row.get("ipv6.dst") or "").split(",", 1)[0]
        base_domain = ".".join(labels[1:3]).lower()
        grouped[(source, destination, base_domain)].append(
            (integer(row.get("frame.number", ""), -1), labels[0])
        )

    for (source_address, destination_address, base_domain), queries in grouped.items():
        unique_fragments: list[tuple[int, bytes]] = []
        seen_labels: set[str] = set()
        for frame_number, label in sorted(queries):
            if label in seen_labels:
                continue
            decoded = _base64_fragments(label.encode("ascii", errors="ignore"))
            if len(decoded) != 1 or decoded[0][0] != label.encode("ascii", errors="ignore"):
                continue
            seen_labels.add(label)
            unique_fragments.append((frame_number, decoded[0][1]))
        if len(unique_fragments) < 2:
            continue

        assembled = b"".join(fragment for _frame, fragment in unique_fragments)
        frames = tuple(frame for frame, _fragment in unique_fragments)
        fragment_count = len(unique_fragments)
        source = (
            f"DNS query labels from {source_address or 'unknown'} "
            f"to {destination_address or 'unknown'} for {base_domain}"
        )
        steps = (
            f"Base64 decode {fragment_count} DNS labels",
            "capture-order concatenation",
        )
        if add_flags(
            assembled,
            source,
            frame_numbers=frames,
            decoding_steps=steps,
            confidence=0.98,
        ):
            add_insight(
                PayloadInsight(
                    title="Reassembled Base64 DNS-label payload",
                    category="decoded-payload",
                    value=_text_preview(assembled),
                    source=source,
                    frame_numbers=frames,
                    confidence=0.98,
                    decoding_steps=steps,
                    metadata={"base_domain": base_domain, "fragment_count": fragment_count},
                )
            )


def _assemble_base64_fragments(observations: tuple[PacketPayload, ...]) -> tuple[_DecodedAssembly, ...]:
    grouped: defaultdict[tuple[str, ...], list[PacketPayload]] = defaultdict(list)
    for item in observations:
        if item.http_method == "POST" and item.http_body:
            grouped[("http", item.destination, str(item.destination_port), item.http_host, item.http_uri)].append(item)
        elif item.data:
            grouped[("flow", item.transport, item.source, item.destination, str(item.destination_port))].append(item)

    assemblies: list[_DecodedAssembly] = []
    seen: set[tuple[tuple[int, ...], bytes]] = set()
    for key, packets in grouped.items():
        packets.sort(key=lambda item: item.frame_number)
        pieces: list[tuple[PacketPayload, bytes]] = []
        for packet in packets:
            source_data = packet.http_body if packet.http_method == "POST" and packet.http_body else packet.data
            fragments = _base64_fragments(source_data)
            if len(fragments) == 1:
                pieces.append((packet, fragments[0][1]))
        if len(pieces) < 2:
            continue
        frame_numbers = tuple(packet.frame_number for packet, _decoded in pieces)
        decoded = b"".join(fragment for _packet, fragment in pieces)
        dedupe_key = (frame_numbers, decoded)
        if dedupe_key in seen:
            continue
        seen.add(dedupe_key)
        stream_ids = {packet.tcp_stream for packet, _decoded in pieces if packet.tcp_stream is not None}
        stream_id = next(iter(stream_ids)) if len(stream_ids) == 1 else None
        if key[0] == "http":
            source = f"HTTP POST fragments to {key[3] or key[1]}{key[4] or ''}"
        else:
            source = f"{key[1].upper()} payload fragments from {key[2]} to {key[3]}:{key[4]}"
        assemblies.append(_DecodedAssembly(source, frame_numbers, stream_id, decoded, len(pieces)))
    return tuple(assemblies)


def _correlate_cellular_identifiers(observations: tuple[PacketPayload, ...], add_insight):
    cell_ids: set[str] = set()
    all_imsis: set[str] = set()
    victim_imsis: set[str] = set()
    broadcast_frames: defaultdict[str, list[int]] = defaultdict(list)

    for item in observations:
        text = item.data.decode("utf-8", errors="ignore")
        for cell_id in _CELL_ID.findall(text):
            cell_ids.add(cell_id)
            if item.transport == "udp" and (item.destination_port == 55000 or _is_broadcast(item.destination)):
                broadcast_frames[cell_id].append(item.frame_number)
        all_imsis.update(_IMSI.findall(text))
        all_imsis.update(_IMSI.findall(item.user_agent))

    for packets in _group_udp_payloads(observations):
        text = b"".join(item.data for item in packets).decode("utf-8", errors="ignore")
        frames = [item.frame_number for item in packets]
        for cell_id in _CELL_ID.findall(text):
            cell_ids.add(cell_id)
            first = packets[0]
            if first.destination_port == 55000 or _is_broadcast(first.destination):
                broadcast_frames[cell_id].extend(frames)
        all_imsis.update(_IMSI.findall(text))

    for item in observations:
        if not item.user_agent:
            continue
        ua_imsis = set(_IMSI.findall(item.user_agent))
        matched_cells = {cell_id for cell_id in cell_ids if cell_id in item.user_agent}
        if not matched_cells:
            continue
        victim_imsis.update(ua_imsis)
        frames = tuple(sorted({item.frame_number, *(frame for cell in matched_cells for frame in broadcast_frames[cell])}))
        add_insight(
            PayloadInsight(
                title="Rogue-cell broadcast correlated with HTTP device",
                category="correlation",
                value=item.user_agent[:_MAX_EVIDENCE_TEXT],
                source=f"HTTP User-Agent in frame {item.frame_number}",
                frame_numbers=frames,
                stream_id=item.tcp_stream,
                confidence=0.9,
                metadata={
                    "cell_ids": ",".join(sorted(matched_cells)),
                    "imsis": ",".join(sorted(ua_imsis)),
                },
            )
        )
    return cell_ids, all_imsis, victim_imsis


def _imsi_key_candidates(all_imsis: set[str], victim_imsis: set[str]) -> tuple[tuple[str, str], ...]:
    preferred = victim_imsis or all_imsis
    candidates: list[tuple[str, str]] = []
    seen: set[str] = set()

    def add(value: str, description: str) -> None:
        if len(value) >= 4 and value not in seen:
            seen.add(value)
            candidates.append((value, description))

    for imsi in sorted(preferred):
        add(imsi, "full IMSI")
        for length in range(6, min(10, len(imsi)) + 1):
            add(imsi[-length:], f"IMSI suffix ({length} digits)")

    if len(all_imsis) > 1:
        ordered = sorted(all_imsis)
        prefix_length = 0
        for values in zip(*ordered):
            if len(set(values)) != 1:
                break
            prefix_length += 1
        if prefix_length >= 4:
            for imsi in sorted(preferred):
                add(imsi[prefix_length:], f"IMSI portion after {prefix_length}-digit common prefix")
    return tuple(candidates)


def _repeating_xor(data: bytes, key: bytes) -> bytes:
    if not key:
        return data
    return bytes(value ^ key[index % len(key)] for index, value in enumerate(data))


def _group_udp_payloads(observations: tuple[PacketPayload, ...]) -> tuple[list[PacketPayload], ...]:
    grouped: defaultdict[tuple[int | None, str, str, int | None], list[PacketPayload]] = defaultdict(list)
    for item in observations:
        if item.transport == "udp" and item.data:
            grouped[(item.udp_stream, item.source, item.destination, item.destination_port)].append(item)
    for packets in grouped.values():
        packets.sort(key=lambda item: item.frame_number)
    return tuple(grouped.values())
