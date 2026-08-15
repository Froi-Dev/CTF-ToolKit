from __future__ import annotations

import base64
from datetime import UTC, datetime, timedelta

import pytest

from app.analyzers.network.investigation import NetworkInvestigationRanker, WiresharkFilterGenerator
from app.schemas.network import NetworkFlagCandidate, StreamChunk, UdpStream


def _covert_rows() -> tuple[dict[str, str], ...]:
    encoded = [ord(character) + 5000 for character in "CTF{PORT}"]
    return tuple(
        {
            "frame.number": str(index + 1),
            "frame.time_epoch": f"{1_700_000_000 + index / 10:.6f}",
            "frame.len": "64",
            "frame.cap_len": "64",
            "frame.protocols": "eth:ip:udp:data",
            "ip.src": "192.0.2.10",
            "ip.dst": "198.51.100.7",
            "ip.id": str(100 + index),
            "ip.ttl": "64",
            "tcp.srcport": "",
            "tcp.dstport": "",
            "tcp.stream": "",
            "udp.srcport": str(source_port),
            "udp.dstport": "4444",
            "udp.stream": "7",
            "udp.payload": "41414141",
            "data.data": "",
            "_ws.col.Protocol": "UDP",
        }
        for index, source_port in enumerate(encoded)
    )


def _ranker(flags: list[NetworkFlagCandidate] | None = None) -> NetworkInvestigationRanker:
    started = datetime(2023, 11, 14, tzinfo=UTC)
    stream = UdpStream(
        stream_id=7,
        endpoint_a="192.0.2.10:5067",
        endpoint_b="198.51.100.7:4444",
        packet_count=9,
        wire_bytes=576,
        first_seen=started,
        last_seen=started + timedelta(seconds=0.8),
        application_protocols=["data"],
        reconstructed_bytes=36,
        reconstructed_base64=base64.b64encode(b"A" * 36).decode(),
        ascii_preview="A" * 36,
        chunks=[StreamChunk(direction="a_to_b", offset=0, length=36)],
        reconstruction_truncated=False,
    )
    return NetworkInvestigationRanker(
        rows=_covert_rows(),
        tcp_streams=[],
        udp_streams=[stream],
        conversations=[],
        dns=[],
        http=[],
        artifacts=[],
        credentials=[],
        insights=[],
        flags=flags or [],
        capture_wire_bytes=100_000,
    )


def test_udp_header_variation_becomes_an_explainable_wireshark_target() -> None:
    targets, summary = _ranker().rank_all()

    stream = next(target for target in targets if target.target_type == "udp_stream")
    assert stream.wireshark_filter == "udp.stream eq 7"
    assert stream.suspicion.total <= 100
    assert stream.suspicion.total == sum(reason.score for reason in stream.suspicion.reasons)
    covert = next(reason for reason in stream.suspicion.reasons if reason.category == "covert-channel")
    assert covert.evidence["transformation"] == "udp.srcport: value - 5000"
    assert covert.evidence["printable_ratio"] == 1.0
    assert stream.interpretation == "Possible header-field covert channel"
    assert stream.interpretation_confidence is not None
    assert any("hypothesis" in item.lower() for item in stream.recommended_actions)
    assert summary.outcome == "partially-solved"
    assert summary.reliable_flag_candidates == 0
    assert "No high-confidence flag" in summary.message


def test_recovered_flag_is_correlated_with_stream_and_keeps_handoff() -> None:
    flag = NetworkFlagCandidate(
        value="CTF{PORT}",
        matched_pattern="CTF",
        source="UDP source-port decoder",
        stream_id=7,
        offset=0,
        confidence=0.93,
        context="CTF{PORT}",
        frame_numbers=list(range(1, 10)),
        decoding_steps=["udp.srcport - 5000"],
    )

    targets, summary = _ranker([flag]).rank_all()

    stream = next(target for target in targets if target.target_type == "udp_stream")
    assert stream.related_flags == ["CTF{PORT}"]
    assert stream.wireshark_filter == "udp.stream eq 7"
    assert stream.interpretation == "Recovered flag candidate"
    assert summary.outcome == "solved"


def test_wireshark_filter_generator_emits_supported_conservative_filters() -> None:
    assert WiresharkFilterGenerator.for_frames([9, 3, 9]) == "frame.number == 3 || frame.number == 9"
    assert WiresharkFilterGenerator.for_conversation("192.0.2.1", "2001:db8::2") == "ip.addr == 192.0.2.1 && ipv6.addr == 2001:db8::2"
    assert WiresharkFilterGenerator.for_dns_group(client="192.0.2.1", domain='example.com') == 'dns && ip.src == 192.0.2.1 && dns.qry.name contains "example.com"'
    assert WiresharkFilterGenerator.for_http_request(method="post") == 'http.request && http.request.method == "POST"'
    with pytest.raises(ValueError):
        WiresharkFilterGenerator.for_protocol("udp || tcp")
