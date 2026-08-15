from __future__ import annotations

import base64
import binascii
import hashlib
import math
import re
from collections import Counter, defaultdict

from app.analyzers.network.investigation.packet_scoring import printable_ratio, score_from
from app.analyzers.network.investigation.recommendations import recommendations_for
from app.analyzers.network.investigation.wireshark_filters import WiresharkFilterGenerator
from app.schemas.network import DnsRecord, HttpMessage, InterestingFrame, InvestigationTarget, SuspicionReason

_BASE64_LABEL = re.compile(r"[A-Za-z0-9_-]{16,}")
_BASE32_LABEL = re.compile(r"[A-Z2-7]{16,}", re.IGNORECASE)
_HEX_LABEL = re.compile(r"[0-9a-f]{20,}", re.IGNORECASE)


def _text_entropy(value: str) -> float:
    if not value:
        return 0.0
    counts = Counter(value)
    return -sum((count / len(value)) * math.log2(count / len(value)) for count in counts.values())


def _row_for_frame(rows: tuple[dict[str, str], ...], frame: int) -> dict[str, str] | None:
    return next((row for row in rows if row.get("frame.number") == str(frame)), None)


def _base_domain(name: str) -> str:
    labels = [label for label in name.rstrip(".").split(".") if label]
    return ".".join(labels[-2:]) if len(labels) >= 2 else name.rstrip(".")


def score_dns_groups(dns: list[DnsRecord], rows: tuple[dict[str, str], ...]) -> list[InvestigationTarget]:
    grouped: defaultdict[tuple[str, str], list[DnsRecord]] = defaultdict(list)
    for record in dns:
        if record.kind != "query" or not record.name:
            continue
        row = _row_for_frame(rows, record.frame_number)
        client = ((row or {}).get("ip.src") or (row or {}).get("ipv6.src") or "unknown").split(",", 1)[0]
        grouped[(client, _base_domain(record.name))].append(record)

    targets: list[InvestigationTarget] = []
    for (client, domain), records in grouped.items():
        labels = [record.name.removesuffix("." + domain).rstrip(".") for record in records if record.name]
        labels = [label for label in labels if label]
        unique = list(dict.fromkeys(labels))
        reasons: list[SuspicionReason] = []
        if len(records) >= 8 and len(unique) / len(records) >= 0.75:
            reasons.append(SuspicionReason(category="dns-unique-labels", description=f"{len(unique)}/{len(records)} DNS queries use unique subdomain labels", score=19, evidence={"queries": len(records), "unique_labels": len(unique), "domain": domain}))
        lengths = [len(label) for label in labels]
        if lengths and sum(lengths) / len(lengths) >= 30:
            average = sum(lengths) / len(lengths)
            reasons.append(SuspicionReason(category="dns-label-length", description=f"Subdomain labels average {average:.1f} characters", score=14, evidence={"average_label_length": round(average, 2), "maximum_label_length": max(lengths)}))
        entropies = [_text_entropy(label) for label in labels if len(label) >= 12]
        if entropies and sum(entropies) / len(entropies) >= 4.0:
            average_entropy = sum(entropies) / len(entropies)
            reasons.append(SuspicionReason(category="dns-label-entropy", description=f"Long subdomain labels average {average_entropy:.2f} bits/character", score=17, evidence={"average_entropy": round(average_entropy, 3), "labels_measured": len(entropies)}))
        encoded = [label for label in labels if _BASE64_LABEL.fullmatch(label) or _BASE32_LABEL.fullmatch(label) or _HEX_LABEL.fullmatch(label)]
        if encoded and len(encoded) / len(labels) >= 0.6:
            reasons.append(SuspicionReason(category="encoded", description=f"{len(encoded)}/{len(labels)} changing DNS labels use Base64/Base32/hex-compatible alphabets", score=18, evidence={"encoded_labels": len(encoded), "labels": len(labels)}))
        combined = "".join(labels)
        decoded_ratio = 0.0
        if len(combined) >= 16 and re.fullmatch(r"[A-Za-z0-9+/=_-]+", combined):
            try:
                padded = combined.replace("-", "+").replace("_", "/") + "=" * (-len(combined) % 4)
                decoded = base64.b64decode(padded, validate=True)
                decoded_ratio = printable_ratio(decoded)
            except (ValueError, binascii.Error):
                decoded = b""
            if decoded and decoded_ratio >= 0.7:
                reasons.append(SuspicionReason(category="decoded", description=f"Concatenated labels decode as Base64 to {decoded_ratio:.0%} printable bytes", score=15, evidence={"decoded_bytes": len(decoded), "printable_ratio": round(decoded_ratio, 3)}))
        timestamps = sorted(record.timestamp for record in records)
        if len(timestamps) >= 6:
            duration = (timestamps[-1] - timestamps[0]).total_seconds()
            if duration > 0 and len(records) / duration >= 2:
                reasons.append(SuspicionReason(category="timing", description=f"{len(records)} DNS queries occur within {duration:.3f} seconds", score=9, evidence={"queries": len(records), "duration_seconds": round(duration, 6), "queries_per_second": round(len(records) / duration, 2)}))
        score = score_from(reasons)
        frame_numbers = [record.frame_number for record in records]
        try:
            display_filter = WiresharkFilterGenerator.for_dns_group(client=client if client != "unknown" else None, domain=domain)
        except ValueError:
            display_filter = WiresharkFilterGenerator.for_dns_group(domain=domain)
        interpretation = "Possible DNS data transfer" if any(reason.category in {"encoded", "decoded"} for reason in reasons) and len(reasons) >= 2 else None
        confidence = min(0.92, 0.35 + score.total / 180) if interpretation else None
        target = InvestigationTarget(
            id=f"dns-{hashlib.sha256(f'{client}:{domain}'.encode()).hexdigest()[:16]}",
            target_type="dns_group",
            title=f"DNS Activity for {domain}",
            suspicion=score,
            interpretation=interpretation,
            interpretation_confidence=round(confidence, 2) if confidence else None,
            protocol="dns",
            frame_numbers=frame_numbers,
            interesting_frames=[InterestingFrame(frame_number=frame_numbers[0], description="First query in the ranked DNS sequence"), InterestingFrame(frame_number=frame_numbers[-1], description="Last query in the ranked DNS sequence")] if len(frame_numbers) > 1 else [],
            endpoints=[client, domain],
            hypotheses=["Changing DNS labels may carry data; inspect and reproduce decoding before treating this as exfiltration."] if interpretation else [],
            wireshark_filter=display_filter,
            categories=["dns", "encoded"] if any(reason.category in {"encoded", "decoded"} for reason in reasons) else ["dns"],
            first_seen=timestamps[0] if timestamps else None,
            last_seen=timestamps[-1] if timestamps else None,
        )
        target.recommended_actions = recommendations_for(target)
        targets.append(target)
    return targets


def score_http_activity(http: list[HttpMessage]) -> list[InvestigationTarget]:
    requests = [item for item in http if item.kind == "request"]
    grouped: defaultdict[tuple[str, str, str], list[HttpMessage]] = defaultdict(list)
    for item in requests:
        grouped[(item.method or "UNKNOWN", item.host or "", item.uri or "")].append(item)
    targets: list[InvestigationTarget] = []
    for (method, host, uri), messages in grouped.items():
        reasons: list[SuspicionReason] = []
        bodies = [base64.b64decode(item.body_base64) for item in messages if item.body_base64]
        if method.upper() == "POST" and bodies:
            reasons.append(SuspicionReason(category="http-post", description=f"{len(messages)} POST request(s) carry {sum(len(body) for body in bodies)} decoded body bytes", score=10, evidence={"requests": len(messages), "body_bytes": sum(len(body) for body in bodies)}))
        if len(messages) >= 4 and bodies:
            sizes = [len(body) for body in bodies]
            if max(sizes) - min(sizes) <= max(4, sum(sizes) / len(sizes) * 0.1):
                reasons.append(SuspicionReason(category="repeated-size", description=f"{len(sizes)} sequential request bodies have nearly identical sizes ({min(sizes)}-{max(sizes)} bytes)", score=12, evidence={"minimum_bytes": min(sizes), "maximum_bytes": max(sizes), "requests": len(sizes)}))
        combined = b"".join(bodies).strip()
        if len(combined) >= 16 and re.fullmatch(rb"[A-Za-z0-9+/=\r\n_-]+", combined):
            reasons.append(SuspicionReason(category="encoded", description=f"Combined HTTP request body uses a Base64-compatible alphabet across {len(combined)} bytes", score=16, evidence={"body_bytes": len(combined)}))
        unusual_agent = [item.user_agent for item in messages if item.user_agent and not re.search(r"Mozilla/|curl/|Wget/", item.user_agent)]
        if unusual_agent and len(messages) >= 2:
            reasons.append(SuspicionReason(category="user-agent", description=f"Non-browser User-Agent {unusual_agent[0]!r} appears in {len(unusual_agent)} request(s)", score=7, evidence={"user_agent": unusual_agent[0], "requests": len(unusual_agent)}))
        score = score_from(reasons)
        frames = [item.frame_number for item in messages]
        target = InvestigationTarget(
            id=f"http-{hashlib.sha256(f'{method}:{host}:{uri}'.encode()).hexdigest()[:16]}",
            target_type="http_activity",
            title=f"HTTP {method} {host}{uri}",
            suspicion=score,
            interpretation="Possible encoded HTTP transfer" if any(reason.category == "encoded" for reason in reasons) and len(reasons) >= 2 else None,
            interpretation_confidence=round(min(0.88, 0.35 + score.total / 180), 2) if any(reason.category == "encoded" for reason in reasons) and len(reasons) >= 2 else None,
            protocol="http",
            frame_numbers=frames,
            interesting_frames=[InterestingFrame(frame_number=frame, description="HTTP request in the ranked activity") for frame in frames[:8]],
            stream_id=messages[0].stream_id if len({item.stream_id for item in messages}) == 1 else None,
            endpoints=[value for value in (host, uri) if value],
            hypotheses=["Repeated encoded-looking HTTP bodies may carry challenge data; inspect the exact request bytes."] if any(reason.category == "encoded" for reason in reasons) else [],
            wireshark_filter=WiresharkFilterGenerator.for_http_request(method=method, host=host or None, uri=uri or None),
            categories=["http", "encoded"] if any(reason.category == "encoded" for reason in reasons) else ["http"],
            first_seen=min(item.timestamp for item in messages),
            last_seen=max(item.timestamp for item in messages),
        )
        target.recommended_actions = recommendations_for(target)
        targets.append(target)
    return targets
