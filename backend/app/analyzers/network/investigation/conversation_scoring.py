from __future__ import annotations

import hashlib
from collections import Counter

from app.analyzers.network.investigation.packet_scoring import score_from
from app.analyzers.network.investigation.recommendations import recommendations_for
from app.analyzers.network.investigation.wireshark_filters import WiresharkFilterGenerator
from app.schemas.network import Conversation, InvestigationTarget, SuspicionReason


def _host(endpoint: str) -> str:
    if endpoint.startswith("[") and "]:" in endpoint:
        return endpoint[1:endpoint.rfind("]")]
    return endpoint.rsplit(":", 1)[0]


def score_conversations(conversations: list[Conversation], capture_wire_bytes: int) -> list[InvestigationTarget]:
    targets: list[InvestigationTarget] = []
    protocol_counts = Counter(protocol for item in conversations for protocol in item.application_protocols)
    for item in conversations:
        reasons: list[SuspicionReason] = []
        packets = item.packets_a_to_b + item.packets_b_to_a
        total_bytes = item.bytes_a_to_b + item.bytes_b_to_a
        if packets >= 4 and min(item.packets_a_to_b, item.packets_b_to_a) == 0:
            reasons.append(SuspicionReason(category="directionality", description=f"All {packets} packets travel in one direction", score=10, evidence={"a_to_b_packets": item.packets_a_to_b, "b_to_a_packets": item.packets_b_to_a}))
        if capture_wire_bytes and packets >= 2 and total_bytes / capture_wire_bytes < 0.005:
            share = total_bytes / capture_wire_bytes
            reasons.append(SuspicionReason(category="rare-stream", description=f"Conversation represents only {share:.2%} of decoded capture bytes", score=7, evidence={"capture_byte_share": round(share, 5), "conversation_bytes": total_bytes}))
        rare_protocols = [protocol for protocol in item.application_protocols if protocol_counts[protocol] <= 1 and protocol not in {"tcp", "udp"}]
        if rare_protocols:
            reasons.append(SuspicionReason(category="rare-protocol", description=f"Application protocol(s) {', '.join(rare_protocols)} occur in only one decoded conversation", score=9, evidence={"protocols": rare_protocols}))
        if len(item.stream_ids) > 8:
            reasons.append(SuspicionReason(category="stream-fanout", description=f"Conversation opens {len(item.stream_ids)} transport streams between the same endpoints", score=9, evidence={"stream_count": len(item.stream_ids)}))
        score = score_from(reasons)
        try:
            display_filter = WiresharkFilterGenerator.for_conversation(_host(item.endpoint_a), _host(item.endpoint_b))
        except ValueError:
            display_filter = None
        key = f"{item.transport}:{item.endpoint_a}:{item.endpoint_b}"
        target = InvestigationTarget(
            id=f"conversation-{hashlib.sha256(key.encode()).hexdigest()[:16]}",
            target_type="conversation",
            title=f"{item.transport.upper()} Conversation",
            suspicion=score,
            protocol=item.transport,
            stream_id=item.stream_ids[0] if len(item.stream_ids) == 1 else None,
            endpoints=[item.endpoint_a, item.endpoint_b],
            hypotheses=["The conversation is anomalous relative to this capture; its purpose is not identified automatically."] if reasons else [],
            wireshark_filter=display_filter,
            categories=["streams", "rare-traffic"] if any(reason.category.startswith("rare") for reason in reasons) else ["streams"],
            first_seen=item.first_seen,
            last_seen=item.last_seen,
        )
        target.recommended_actions = recommendations_for(target)
        targets.append(target)
    return targets
