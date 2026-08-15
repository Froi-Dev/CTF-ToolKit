from __future__ import annotations

import base64
import hashlib
from collections import Counter, defaultdict

from app.analyzers.network.investigation.packet_scoring import (
    PacketScore,
    analyze_field_variation,
    payload_reasons,
    score_from,
)
from app.analyzers.network.investigation.recommendations import recommendations_for
from app.analyzers.network.investigation.wireshark_filters import WiresharkFilterGenerator
from app.schemas.network import (
    InterestingFrame,
    InvestigationTarget,
    SuspicionReason,
    TcpStream,
    UdpStream,
)


def _identifier(kind: str, value: object) -> str:
    digest = hashlib.sha256(f"{kind}:{value}".encode()).hexdigest()[:16]
    return f"{kind}-{digest}"


def _categories(reasons: list[SuspicionReason]) -> list[str]:
    result = ["streams"]
    mapping = {"encoded": "encoded", "covert-channel": "covert", "field-variation": "covert", "credential": "credentials", "rare-stream": "rare-traffic"}
    result.extend(mapping[item.category] for item in reasons if item.category in mapping)
    return list(dict.fromkeys(result))


def _stream_rows(rows: tuple[dict[str, str], ...], protocol: str, stream_id: int) -> list[dict[str, str]]:
    field = f"{protocol}.stream"
    return [row for row in rows if (row.get(field) or "").split(",", 1)[0] == str(stream_id)]


def score_streams(
    streams: list[tuple[str, TcpStream | UdpStream]],
    rows: tuple[dict[str, str], ...],
    packet_scores: dict[int, PacketScore],
    *,
    capture_wire_bytes: int,
    payload_baseline: float | None,
) -> list[InvestigationTarget]:
    targets: list[InvestigationTarget] = []
    stream_port_counts: Counter[tuple[str, int]] = Counter()
    for protocol, stream in streams:
        for row in _stream_rows(rows, protocol, stream.stream_id):
            destination = (row.get(f"{protocol}.dstport") or "").split(",", 1)[0]
            if destination.isdigit():
                stream_port_counts[(protocol, int(destination))] += 1

    for protocol, stream in streams:
        related_rows = _stream_rows(rows, protocol, stream.stream_id)
        payload = base64.b64decode(stream.reconstructed_base64) if stream.reconstructed_base64 else b""
        reasons = payload_reasons(payload, baseline_size=payload_baseline)
        frame_numbers = sorted({int(row["frame.number"]) for row in related_rows if row.get("frame.number", "").isdigit()})
        if capture_wire_bytes and stream.wire_bytes / capture_wire_bytes < 0.01 and stream.packet_count >= 2:
            share = stream.wire_bytes / capture_wire_bytes
            reasons.append(SuspicionReason(category="rare-stream", description=f"Stream represents only {share:.2%} of decoded capture bytes", score=7, evidence={"capture_byte_share": round(share, 5), "stream_bytes": stream.wire_bytes, "capture_bytes": capture_wire_bytes}))
        payload_lengths = [packet_scores[frame].payload for frame in frame_numbers if frame in packet_scores and packet_scores[frame].payload]
        if len(payload_lengths) >= 5:
            length_counts = Counter(len(item) for item in payload_lengths)
            common_length, common_count = length_counts.most_common(1)[0]
            if common_count / len(payload_lengths) >= 0.8:
                reasons.append(SuspicionReason(category="repeated-size", description=f"{common_count}/{len(payload_lengths)} payload-bearing packets have the same {common_length}-byte payload length", score=11, evidence={"matching_packets": common_count, "payload_packets": len(payload_lengths), "payload_bytes": common_length}))
        if len(related_rows) >= 4:
            variation = analyze_field_variation(related_rows)
            reasons.extend(variation.reasons)
        else:
            variation = analyze_field_variation([])

        destination_ports = [int(value) for row in related_rows if (value := (row.get(f"{protocol}.dstport") or "").split(",", 1)[0]).isdigit()]
        if destination_ports:
            port = Counter(destination_ports).most_common(1)[0][0]
            if port > 1024 and stream_port_counts[(protocol, port)] <= 3:
                reasons.append(SuspicionReason(category="rare-port", description=f"Destination {protocol.upper()} port {port} occurs in only {stream_port_counts[(protocol, port)]} stream packets", score=8, evidence={"port": port, "transport": protocol, "packets": stream_port_counts[(protocol, port)]}))

        packet_reasons: defaultdict[str, list[int]] = defaultdict(list)
        for frame in frame_numbers:
            for reason in packet_scores.get(frame, PacketScore(frame, score_from([]), b"")).score.reasons:
                if reason.category in {"command", "credential", "flag-pattern", "file-magic"}:
                    packet_reasons[reason.category].append(frame)
        for category, frames in packet_reasons.items():
            labels = {"command": "Command material", "credential": "Credential markers", "flag-pattern": "Flag-like text", "file-magic": "File magic"}
            reasons.append(SuspicionReason(category=category, description=f"{labels[category]} occurs in {len(frames)} stream frame(s)", score={"command": 20, "credential": 16, "flag-pattern": 32, "file-magic": 17}[category], evidence={"frames": frames[:32]}))

        score = score_from(reasons)
        ranked_frames = sorted((packet_scores[frame] for frame in frame_numbers if frame in packet_scores), key=lambda item: (-item.score.total, item.frame_number))
        interesting = [InterestingFrame(frame_number=item.frame_number, description=item.score.reasons[0].description if item.score.reasons else "Part of the suspicious stream pattern") for item in ranked_frames[:8] if item.score.total > 0]
        if not interesting and frame_numbers:
            interesting = [InterestingFrame(frame_number=frame_numbers[0], description="First frame in the ranked stream"), InterestingFrame(frame_number=frame_numbers[-1], description="Last frame in the ranked stream")] if len(frame_numbers) > 1 else [InterestingFrame(frame_number=frame_numbers[0], description="Only frame in the ranked stream")]
        target = InvestigationTarget(
            id=_identifier(f"{protocol}-stream", stream.stream_id),
            target_type=f"{protocol}_stream",  # type: ignore[arg-type]
            title=f"{protocol.upper()} Stream {stream.stream_id}",
            suspicion=score,
            interpretation=variation.interpretation,
            interpretation_confidence=variation.confidence,
            protocol=protocol,
            frame_numbers=frame_numbers,
            interesting_frames=interesting,
            stream_id=stream.stream_id,
            endpoints=[stream.endpoint_a, stream.endpoint_b],
            hypotheses=list(variation.hypotheses),
            wireshark_filter=WiresharkFilterGenerator.for_tcp_stream(stream.stream_id) if protocol == "tcp" else WiresharkFilterGenerator.for_udp_stream(stream.stream_id),
            categories=_categories(reasons),  # type: ignore[arg-type]
            first_seen=stream.first_seen,
            last_seen=stream.last_seen,
        )
        target.recommended_actions = recommendations_for(target)
        targets.append(target)
    return targets
