from __future__ import annotations

import hashlib
from collections import Counter, defaultdict
from datetime import datetime

from app.analyzers.network.investigation.artifact_scoring import score_artifacts
from app.analyzers.network.investigation.conversation_scoring import score_conversations
from app.analyzers.network.investigation.packet_scoring import (
    PacketScore,
    analyze_field_variation,
    capture_baseline,
    decode_hex,
    number,
    score_from,
    score_packet,
)
from app.analyzers.network.investigation.protocol_scoring import score_dns_groups, score_http_activity
from app.analyzers.network.investigation.recommendations import recommendations_for
from app.analyzers.network.investigation.stream_scoring import score_streams
from app.analyzers.network.investigation.wireshark_filters import WiresharkFilterGenerator
from app.schemas.network import (
    Conversation,
    DnsRecord,
    HttpMessage,
    InterestingFrame,
    InvestigationTarget,
    NetworkFlagCandidate,
    NetworkInsight,
    NetworkInvestigationSummary,
    PlaintextCredential,
    SuspicionReason,
    TcpStream,
    TransferredFile,
    UdpStream,
)

_MINIMUM_SCORE = 24.0


def _timestamp(row: dict[str, str]) -> datetime | None:
    try:
        return datetime.fromtimestamp(float(row.get("frame.time_epoch", ""))).astimezone()
    except (ValueError, OSError, OverflowError):
        return None


def _transport(row: dict[str, str]) -> str | None:
    if row.get("tcp.srcport") or row.get("tcp.dstport"):
        return "tcp"
    if row.get("udp.srcport") or row.get("udp.dstport"):
        return "udp"
    return None


def _endpoints(row: dict[str, str], protocol: str | None) -> list[str]:
    source = (row.get("ip.src") or row.get("ipv6.src") or row.get("eth.src") or "unknown").split(",", 1)[0]
    destination = (row.get("ip.dst") or row.get("ipv6.dst") or row.get("eth.dst") or "unknown").split(",", 1)[0]
    if protocol:
        source_port = (row.get(f"{protocol}.srcport") or "").split(",", 1)[0]
        destination_port = (row.get(f"{protocol}.dstport") or "").split(",", 1)[0]
        source += f":{source_port}" if source_port else ""
        destination += f":{destination_port}" if destination_port else ""
    return [source, destination]


def _visible(target: InvestigationTarget) -> bool:
    strong_direct = any(reason.category in {"flag-pattern", "command", "credential", "file-magic"} for reason in target.suspicion.reasons)
    measurable_reasons = [reason for reason in target.suspicion.reasons if reason.category != "bounded-preview"]
    return target.suspicion.total >= _MINIMUM_SCORE and (len(measurable_reasons) >= 2 or strong_direct)


class NetworkInvestigationRanker:
    """Rank real capture evidence without treating an unknown technique as failure."""

    def __init__(
        self,
        *,
        rows: tuple[dict[str, str], ...],
        tcp_streams: list[TcpStream],
        udp_streams: list[UdpStream],
        conversations: list[Conversation],
        dns: list[DnsRecord],
        http: list[HttpMessage],
        artifacts: list[TransferredFile],
        credentials: list[PlaintextCredential],
        insights: list[NetworkInsight],
        flags: list[NetworkFlagCandidate],
        capture_wire_bytes: int,
        maximum_targets: int = 100,
    ) -> None:
        self.rows = rows
        self.tcp_streams = tcp_streams
        self.udp_streams = udp_streams
        self.conversations = conversations
        self.dns = dns
        self.http = http
        self.artifacts = artifacts
        self.credentials = credentials
        self.insights = insights
        self.flags = flags
        self.capture_wire_bytes = capture_wire_bytes
        self.maximum_targets = maximum_targets
        self.payload_baseline, self.port_frequency = capture_baseline(rows)
        self.packet_scores = {
            item.frame_number: item
            for item in (
                score_packet(row, baseline_payload_size=self.payload_baseline, port_frequency=self.port_frequency)
                for row in rows
                if number(row.get("frame.number")) >= 1
            )
        }

    def rank_packets(self) -> list[InvestigationTarget]:
        targets = self._rank_packet_groups()
        by_frame = {number(row.get("frame.number")): row for row in self.rows}
        ranked = sorted(self.packet_scores.values(), key=lambda item: (-item.score.total, item.frame_number))
        for item in ranked[:50]:
            row = by_frame.get(item.frame_number)
            if row is None:
                continue
            protocol = _transport(row)
            target = InvestigationTarget(
                id=f"packet-{item.frame_number}",
                target_type="packet",
                title=f"Frame {item.frame_number}: {row.get('_ws.col.Protocol') or protocol or 'Unknown'}",
                suspicion=item.score,
                protocol=(row.get("_ws.col.Protocol") or protocol or "unknown").lower(),
                frame_numbers=[item.frame_number],
                interesting_frames=[InterestingFrame(frame_number=item.frame_number, description=item.score.reasons[0].description)] if item.score.reasons else [],
                stream_id=number(row.get(f"{protocol}.stream"), -1) if protocol and number(row.get(f"{protocol}.stream"), -1) >= 0 else None,
                endpoints=_endpoints(row, protocol),
                hypotheses=["The packet is unusual based on the measured reasons; inspect it in its stream context before drawing a conclusion."],
                wireshark_filter=WiresharkFilterGenerator.for_frame(item.frame_number),
                categories=["packets"] + (["encoded"] if any(reason.category == "encoded" for reason in item.score.reasons) else []),
                first_seen=_timestamp(row),
                last_seen=_timestamp(row),
            )
            target.recommended_actions = recommendations_for(target)
            targets.append(target)
        return [target for target in targets if _visible(target)]

    def _rank_packet_groups(self) -> list[InvestigationTarget]:
        buckets: defaultdict[tuple[str, str, str, str], list[dict[str, str]]] = defaultdict(list)
        for row in self.rows:
            protocol = _transport(row)
            if not protocol:
                continue
            destination = (row.get("ip.dst") or row.get("ipv6.dst") or row.get("eth.dst") or "unknown").split(",", 1)[0]
            destination_port = (row.get(f"{protocol}.dstport") or "").split(",", 1)[0]
            stream = (row.get(f"{protocol}.stream") or "").split(",", 1)[0]
            buckets[(protocol, destination, destination_port, stream)].append(row)

        targets: list[InvestigationTarget] = []
        for (protocol, destination, destination_port, stream), rows in buckets.items():
            if len(rows) < 4:
                continue
            rows.sort(key=lambda row: (float(row.get("frame.time_epoch") or 0), number(row.get("frame.number"))))
            variation = analyze_field_variation(rows)
            reasons = list(variation.reasons)
            payload_lengths = [len(decode_hex(row.get(f"{protocol}.payload", "") or row.get("data.data", ""))) for row in rows]
            common_length, common_count = Counter(payload_lengths).most_common(1)[0]
            if common_count / len(rows) >= 0.8:
                reasons.append(SuspicionReason(category="repeated-size", description=f"{common_count}/{len(rows)} related packets have the same {common_length}-byte payload length", score=12, evidence={"matching_packets": common_count, "packets": len(rows), "payload_bytes": common_length}))
            start = float(rows[0].get("frame.time_epoch") or 0)
            end = float(rows[-1].get("frame.time_epoch") or 0)
            duration = max(0.0, end - start)
            if len(rows) >= 8 and duration <= 2.0:
                reasons.append(SuspicionReason(category="timing", description=f"{len(rows)} related packets occur in a {duration:.3f}-second burst", score=10, evidence={"packets": len(rows), "duration_seconds": round(duration, 6)}))
            score = score_from(reasons)
            frames = [number(row.get("frame.number")) for row in rows if number(row.get("frame.number")) >= 1]
            stream_id = int(stream) if stream.isdigit() else None
            if stream_id is not None:
                display_filter = WiresharkFilterGenerator.for_tcp_stream(stream_id) if protocol == "tcp" else WiresharkFilterGenerator.for_udp_stream(stream_id)
            else:
                display_filter = WiresharkFilterGenerator.for_frames(frames[:50])
            identity = f"{protocol}:{destination}:{destination_port}:{stream}:{frames[0]}:{frames[-1]}"
            target = InvestigationTarget(
                id=f"packet-group-{hashlib.sha256(identity.encode()).hexdigest()[:16]}",
                target_type="packet_group",
                title=f"Frames {frames[0]}-{frames[-1]}: Structured {protocol.upper()} Activity",
                suspicion=score,
                interpretation=variation.interpretation,
                interpretation_confidence=variation.confidence,
                protocol=protocol,
                frame_numbers=frames,
                interesting_frames=[InterestingFrame(frame_number=frames[0], description="First frame in the structured sequence"), InterestingFrame(frame_number=frames[-1], description="Last frame in the structured sequence")],
                stream_id=stream_id,
                endpoints=_endpoints(rows[0], protocol),
                hypotheses=list(variation.hypotheses),
                wireshark_filter=display_filter,
                categories=["packets"] + (["covert"] if variation.reasons else []),
                first_seen=_timestamp(rows[0]),
                last_seen=_timestamp(rows[-1]),
            )
            target.recommended_actions = recommendations_for(target)
            targets.append(target)
        return targets

    def rank_streams(self) -> list[InvestigationTarget]:
        streams = [("tcp", item) for item in self.tcp_streams] + [("udp", item) for item in self.udp_streams]
        return [target for target in score_streams(streams, self.rows, self.packet_scores, capture_wire_bytes=self.capture_wire_bytes, payload_baseline=self.payload_baseline) if _visible(target)]

    def rank_conversations(self) -> list[InvestigationTarget]:
        return [target for target in score_conversations(self.conversations, self.capture_wire_bytes) if _visible(target)]

    def rank_protocol_groups(self) -> list[InvestigationTarget]:
        return [target for target in [*score_dns_groups(self.dns, self.rows), *score_http_activity(self.http)] if _visible(target)]

    def rank_artifacts(self) -> list[InvestigationTarget]:
        return [target for target in score_artifacts(self.artifacts) if _visible(target)]

    def rank_findings(self, targets: list[InvestigationTarget] | None = None) -> list[InvestigationTarget]:
        ranked = list(targets or [])
        for flag in self.flags:
            related = self._find_related(ranked, flag.stream_id, flag.frame_numbers or ([flag.packet_number] if flag.packet_number else []))
            reason = SuspicionReason(category="flag-pattern", description=f"Automatic analysis recovered flag candidate {flag.value!r} with {flag.confidence:.0%} confidence", score=35, evidence={"value": flag.value, "confidence": flag.confidence, "source": flag.source, "decoding_steps": flag.decoding_steps})
            if related:
                self._enrich(related[0], reason, related_flag=flag.value, interpretation="Recovered flag candidate", confidence=flag.confidence)
            else:
                frames = flag.frame_numbers or ([flag.packet_number] if flag.packet_number else [])
                display_filter = WiresharkFilterGenerator.for_tcp_stream(flag.stream_id) if flag.stream_id is not None else WiresharkFilterGenerator.for_frames(frames)
                target = InvestigationTarget(id=f"flag-{hashlib.sha256(flag.value.encode()).hexdigest()[:16]}", target_type="packet_group" if len(frames) > 1 else "packet", title="Recovered Flag Evidence", suspicion=score_from([reason]), interpretation="Recovered flag candidate", interpretation_confidence=flag.confidence, frame_numbers=frames, stream_id=flag.stream_id, hypotheses=[], wireshark_filter=display_filter, related_flags=[flag.value], categories=["packets", "encoded"] if flag.decoding_steps else ["packets"])
                target.recommended_actions = recommendations_for(target)
                ranked.append(target)

        for credential in self.credentials:
            frames = [credential.frame_number] if credential.frame_number else []
            related = self._find_related(ranked, credential.stream_id, frames)
            reason = SuspicionReason(category="credential", description=f"{credential.protocol} analysis recovered a plaintext credential candidate", score=18, evidence={"protocol": credential.protocol, "username_present": credential.username is not None, "confidence": credential.confidence, "frame": credential.frame_number})
            if related:
                self._enrich(related[0], reason, related_finding=f"{credential.protocol} credential", interpretation="Possible plaintext credential exchange", confidence=credential.confidence)

        for insight in self.insights:
            related = self._find_related(ranked, insight.stream_id, insight.frame_numbers)
            reason = SuspicionReason(category="covert-channel" if insight.category == "covert-channel" else "encoded", description=f"Automatic decoder produced {insight.title!r}", score=18, evidence={"category": insight.category, "confidence": insight.confidence, "decoding_steps": insight.decoding_steps})
            if related:
                self._enrich(related[0], reason, related_finding=insight.title, interpretation=insight.title, confidence=insight.confidence)
        return ranked

    @staticmethod
    def _find_related(targets: list[InvestigationTarget], stream_id: int | None, frames: list[int]) -> list[InvestigationTarget]:
        frame_set = set(frames)
        matches = [target for target in targets if (stream_id is not None and target.stream_id == stream_id) or bool(frame_set.intersection(target.frame_numbers))]
        return sorted(matches, key=lambda target: ({"tcp_stream": 0, "udp_stream": 0, "packet_group": 1, "packet": 2}.get(target.target_type, 3), -target.suspicion.total))

    @staticmethod
    def _enrich(target: InvestigationTarget, reason: SuspicionReason, *, related_flag: str | None = None, related_finding: str | None = None, interpretation: str | None = None, confidence: float | None = None) -> None:
        target.suspicion = score_from([*target.suspicion.reasons, reason])
        if related_flag and related_flag not in target.related_flags:
            target.related_flags.append(related_flag)
        if related_finding and related_finding not in target.related_findings:
            target.related_findings.append(related_finding)
        if interpretation and (target.interpretation_confidence or 0) <= (confidence or 0):
            target.interpretation = interpretation
            target.interpretation_confidence = confidence
        target.recommended_actions = recommendations_for(target)

    def rank_all(self) -> tuple[list[InvestigationTarget], NetworkInvestigationSummary]:
        targets = [
            *self.rank_streams(),
            *self.rank_conversations(),
            *self.rank_protocol_groups(),
            *self.rank_artifacts(),
            *self.rank_packets(),
        ]
        targets = self.rank_findings(targets)
        deduplicated = {target.id: target for target in targets}
        ordered = sorted(deduplicated.values(), key=lambda target: (-target.suspicion.total, {"tcp_stream": 0, "udp_stream": 0, "conversation": 1, "packet_group": 2, "dns_group": 3, "http_activity": 3, "artifact": 4, "packet": 5}.get(target.target_type, 6), target.id))[: self.maximum_targets]
        reliable = [flag for flag in self.flags if flag.confidence >= 0.8]
        if reliable:
            outcome = "solved"
            message = f"{len(reliable)} high-confidence flag candidate(s) were recovered. Ranked evidence is retained so the result can be reproduced in Wireshark."
        elif any(target.interpretation and (target.interpretation_confidence or 0) >= 0.65 for target in ordered):
            outcome = "partially-solved"
            message = "No high-confidence flag was automatically recovered. CTFKit identified interpretable suspicious evidence and ranked it for manual verification."
        else:
            outcome = "investigation-targets"
            message = "No high-confidence flag was automatically recovered. CTFKit ranked the strongest measurable anomalies for manual investigation."
        summary = NetworkInvestigationSummary(
            outcome=outcome,
            message=message,
            suspicious_targets=len(ordered),
            suspicious_streams=sum(target.target_type in {"tcp_stream", "udp_stream"} for target in ordered),
            suspicious_packet_groups=sum(target.target_type == "packet_group" for target in ordered),
            suspicious_packets=sum(target.target_type == "packet" for target in ordered),
            suspicious_dns_groups=sum(target.target_type == "dns_group" for target in ordered),
            suspicious_artifacts=sum(target.target_type == "artifact" for target in ordered),
            reliable_flag_candidates=len(reliable),
        )
        return ordered, summary
