from __future__ import annotations

import base64
import codecs

from app.analyzers.network.payloads import analyze_hidden_payloads
from app.core.flag_detection import FlagDetector
from app.integrations.tshark import ReconstructedStream


def _hex(data: bytes) -> str:
    return ":".join(f"{value:02x}" for value in data)


def _row(frame: int, **values: str) -> dict[str, str]:
    row = {
        "frame.number": str(frame),
        "ip.src": "10.0.0.1",
        "ip.dst": "10.0.0.2",
        "eth.src": "",
        "eth.dst": "",
        "tcp.srcport": "40000",
        "tcp.dstport": "80",
        "udp.srcport": "",
        "udp.dstport": "",
        "tcp.stream": "0",
        "udp.stream": "",
        "tcp.payload": "",
        "udp.payload": "",
        "data.data": "",
        "http.request.method": "",
        "http.host": "",
        "http.request.uri": "",
        "http.user_agent": "",
        "http.file_data": "",
    }
    row.update(values)
    return row


def _analyze(rows=(), streams=()):
    return analyze_hidden_payloads(
        tuple(rows),
        tuple(streams),
        FlagDetector(["flag", "CTF", "picoCTF", "HTB", "H4G"]),
        max_insights=100,
        max_flags=100,
    )


def test_rot13_flag_is_recovered_from_a_reconstructed_stream() -> None:
    plaintext = b"The flag is picoCTF{rot13_stream_evidence}"
    encoded = codecs.decode(plaintext.decode("ascii"), "rot_13").encode("ascii")

    result = _analyze(
        streams=(ReconstructedStream(5, encoded, (("a_to_b", 0, len(encoded)),), False),)
    )

    assert any(item.detected.value == "picoCTF{rot13_stream_evidence}" for item in result.flags)
    assert any(item.decoding_steps == ("ROT13",) for item in result.flags)
    assert any(item.title == "ROT13-obfuscated flag payload" for item in result.insights)


def test_udp_source_ports_between_markers_are_decoded_as_ascii() -> None:
    plaintext = b"picoCTF{port_channel}"
    rows = [
        _row(
            1,
            **{
                "tcp.srcport": "",
                "tcp.dstport": "",
                "tcp.stream": "",
                "udp.srcport": "5001",
                "udp.dstport": "22",
                "udp.stream": "3",
                "udp.payload": _hex(b"start"),
            },
        )
    ]
    rows.extend(
        _row(
            index + 2,
            **{
                "tcp.srcport": "",
                "tcp.dstport": "",
                "tcp.stream": "",
                "udp.srcport": str(5000 + value),
                "udp.dstport": "22",
                "udp.stream": "3",
                "udp.payload": _hex(b"x"),
            },
        )
        for index, value in enumerate(plaintext)
    )
    rows.append(
        _row(
            len(rows) + 1,
            **{
                "tcp.srcport": "",
                "tcp.dstport": "",
                "tcp.stream": "",
                "udp.srcport": "5002",
                "udp.dstport": "22",
                "udp.stream": "3",
                "udp.payload": _hex(b"end"),
            },
        )
    )

    result = _analyze(rows=rows)

    channel = next(item for item in result.insights if item.category == "covert-channel")
    assert channel.value == plaintext.decode("ascii")
    assert channel.metadata["port_offset"] == 5000
    assert any(item.detected.value == plaintext.decode("ascii") for item in result.flags)


def test_base64_fragments_are_decoded_and_joined_in_capture_order() -> None:
    pieces = [b"picoCTF", b"{fragmented_", b"post_data", b"}"]
    rows = [
        _row(
            index,
            **{
                "tcp.stream": str(index),
                "http.request.method": "POST",
                "http.host": "collector.test",
                "http.request.uri": "/upload",
                "http.file_data": _hex(base64.b64encode(piece)),
            },
        )
        for index, piece in enumerate(pieces, start=1)
    ]

    result = _analyze(rows=rows)

    assert any(item.detected.value == "picoCTF{fragmented_post_data}" for item in result.flags)
    assembly = next(item for item in result.insights if item.title == "Reassembled Base64 payload fragments")
    assert assembly.value == "picoCTF{fragmented_post_data}"
    assert assembly.frame_numbers == (1, 2, 3, 4)


def test_broadcast_cell_id_user_agent_imsi_and_xor_exfiltration_are_correlated() -> None:
    imsi = "310410337059687"
    xor_key = imsi[-8:].encode("ascii")
    plaintext = b"picoCTF{rogue_cell_pipeline}"
    ciphertext = bytes(value ^ xor_key[index % len(xor_key)] for index, value in enumerate(plaintext))
    chunks = [ciphertext[:9], ciphertext[9:18], ciphertext[18:]]
    rows = [
        _row(
            1,
            **{
                "ip.dst": "255.255.255.255",
                "tcp.srcport": "",
                "tcp.dstport": "",
                "tcp.stream": "",
                "udp.srcport": "49000",
                "udp.dstport": "55000",
                "udp.stream": "8",
                "udp.payload": _hex(b"TEST CELL_"),
            },
        ),
        _row(
            2,
            **{
                "ip.dst": "255.255.255.255",
                "tcp.srcport": "",
                "tcp.dstport": "",
                "tcp.stream": "",
                "udp.srcport": "49000",
                "udp.dstport": "55000",
                "udp.stream": "8",
                "udp.payload": _hex(b"ID=90461"),
            },
        ),
    ]
    for index, chunk in enumerate(chunks, start=3):
        rows.append(
            _row(
                index,
                **{
                    "tcp.stream": str(index),
                    "http.request.method": "POST",
                    "http.host": "collector.test",
                    "http.request.uri": "/exfil",
                    "http.user_agent": f"TestPhone CELL_ID=90461 IMSI={imsi}" if index == 3 else "",
                    "http.file_data": _hex(base64.b64encode(chunk)),
                },
            )
        )

    result = _analyze(rows=rows)

    assert any(item.category == "broadcast" and "90461" in item.value for item in result.insights)
    correlation = next(item for item in result.insights if item.category == "correlation")
    assert correlation.metadata == {"cell_ids": "90461", "imsis": imsi}
    assert any(item.detected.value == "picoCTF{rogue_cell_pipeline}" for item in result.flags)
    decoded = next(item for item in result.insights if item.title == "IMSI-derived XOR payload")
    assert decoded.metadata["key_derivation"] == "IMSI suffix (8 digits)"


def test_base64_dns_labels_are_deduplicated_and_reassembled_in_capture_order() -> None:
    pieces = [b"picoCT", b"F{dns_", b"3xf1l_", b"ftw_de", b"adbeef", b"}"]
    rows: list[dict[str, str]] = []
    frame = 100
    for piece in pieces:
        label = base64.b64encode(piece).decode("ascii")
        for suffix in (
            "reddshrimpandherring.com",
            "reddshrimpandherring.com.windomain.local",
        ):
            rows.append(
                _row(
                    frame,
                    **{
                        "ip.src": "192.168.38.104",
                        "ip.dst": "18.217.1.57",
                        "tcp.srcport": "",
                        "tcp.dstport": "",
                        "tcp.stream": "",
                        "dns.flags.response": "0",
                        "dns.qry.name": f"{label}.{suffix}",
                    },
                )
            )
            frame += 1

    result = _analyze(rows=rows)

    expected = "picoCTF{dns_3xf1l_ftw_deadbeef}"
    candidate = next(item for item in result.flags if item.detected.value == expected)
    assert candidate.confidence == 0.98
    insight = next(item for item in result.insights if "DNS-label" in item.title)
    assert insight.value == expected
    assert insight.metadata == {
        "base_domain": "reddshrimpandherring.com",
        "fragment_count": 6,
    }
