from __future__ import annotations

import struct
from pathlib import Path

import pytest

from app.analyzers.network.capture_loader import inspect_capture
from app.core.errors import InvalidArtifactError


def _pcap(payload: bytes = b"") -> bytes:
    header = b"\xd4\xc3\xb2\xa1" + struct.pack("<HHiIII", 2, 4, 0, 0, 65_535, 1)
    if not payload:
        return header
    return header + struct.pack("<IIII", 1, 500_000, len(payload), len(payload)) + payload


def test_pcap_loader_reports_structural_metadata(tmp_path: Path) -> None:
    capture = tmp_path / "capture.cap"
    capture.write_bytes(_pcap(b"packet"))

    result = inspect_capture(capture)

    assert result.format == "pcap"
    assert result.packet_count == 1
    assert result.byte_order == "little"
    assert result.timestamp_resolution == "microseconds"
    assert result.snap_length == 65_535
    assert result.encapsulations == ("Ethernet",)


def test_pcap_loader_rejects_a_truncated_packet(tmp_path: Path) -> None:
    capture = tmp_path / "corrupt.pcap"
    capture.write_bytes(
        _pcap() + struct.pack("<IIII", 1, 0, 100, 100) + b"too short"
    )

    with pytest.raises(InvalidArtifactError, match="truncated packet payload"):
        inspect_capture(capture)


def test_pcapng_loader_requires_matching_block_trailers(tmp_path: Path) -> None:
    capture = tmp_path / "corrupt.pcapng"
    capture.write_bytes(
        b"\x0a\x0d\x0d\x0a"
        + struct.pack("<I", 28)
        + b"\x4d\x3c\x2b\x1a"
        + struct.pack("<HHqI", 1, 0, -1, 24)
    )

    with pytest.raises(InvalidArtifactError, match="does not match"):
        inspect_capture(capture)


def test_pcapng_loader_reports_interfaces_and_packet_blocks(tmp_path: Path) -> None:
    capture = tmp_path / "capture.pcapng"
    section = (
        b"\x0a\x0d\x0d\x0a"
        + struct.pack("<I", 28)
        + b"\x4d\x3c\x2b\x1a"
        + struct.pack("<HHqI", 1, 0, -1, 28)
    )
    interface = struct.pack("<IIHHII", 1, 20, 1, 0, 65_535, 20)
    simple_packet = struct.pack("<III4sI", 3, 20, 4, b"data", 20)
    capture.write_bytes(section + interface + simple_packet)

    result = inspect_capture(capture)

    assert result.format == "pcapng"
    assert result.packet_count == 1
    assert result.interfaces[0].encapsulation == "Ethernet"
    assert result.interfaces[0].snap_length == 65_535
