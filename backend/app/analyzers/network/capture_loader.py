from __future__ import annotations

import struct
from dataclasses import dataclass
from pathlib import Path

from app.core.errors import InvalidArtifactError


_PCAP_MAGICS: dict[bytes, tuple[str, str]] = {
    b"\xd4\xc3\xb2\xa1": ("<", "microseconds"),
    b"\xa1\xb2\xc3\xd4": (">", "microseconds"),
    b"\x4d\x3c\xb2\xa1": ("<", "nanoseconds"),
    b"\xa1\xb2\x3c\x4d": (">", "nanoseconds"),
}
_PCAPNG_MAGIC = b"\x0a\x0d\x0d\x0a"
_PCAPNG_BYTE_ORDER = {
    b"\x4d\x3c\x2b\x1a": "<",
    b"\x1a\x2b\x3c\x4d": ">",
}
_LINK_TYPES = {
    0: "BSD loopback",
    1: "Ethernet",
    6: "IEEE 802.5 Token Ring",
    101: "Raw IP",
    105: "IEEE 802.11",
    113: "Linux cooked capture",
    127: "IEEE 802.11 radiotap",
    228: "Raw IPv4",
    229: "Raw IPv6",
    276: "Linux cooked capture v2",
}
_MAX_BLOCK_BYTES = 64 * 1024 * 1024


@dataclass(frozen=True, slots=True)
class CaptureInterfaceInfo:
    interface_id: int
    link_type: int
    encapsulation: str
    snap_length: int | None
    name: str | None = None


@dataclass(frozen=True, slots=True)
class CaptureDescriptor:
    format: str
    file_size: int
    packet_count: int
    byte_order: str
    timestamp_resolution: str | None
    interfaces: tuple[CaptureInterfaceInfo, ...]

    @property
    def encapsulations(self) -> tuple[str, ...]:
        return tuple(dict.fromkeys(item.encapsulation for item in self.interfaces))

    @property
    def snap_length(self) -> int | None:
        values = [item.snap_length for item in self.interfaces if item.snap_length is not None]
        return max(values) if values else None


def inspect_capture(path: Path, expected_format: str | None = None) -> CaptureDescriptor:
    """Structurally validate a bounded capture without trusting its extension."""

    try:
        size = path.stat().st_size
        with path.open("rb") as source:
            magic = source.read(4)
            source.seek(0)
            if magic in _PCAP_MAGICS:
                descriptor = _inspect_pcap(source, size)
            elif magic == _PCAPNG_MAGIC:
                descriptor = _inspect_pcapng(source, size)
            else:
                raise InvalidArtifactError(
                    "The upload is not a PCAP or PCAPNG capture based on its file signature."
                )
    except InvalidArtifactError:
        raise
    except OSError as exc:
        raise InvalidArtifactError("The capture could not be read safely.") from exc

    if expected_format is not None and descriptor.format != expected_format:
        raise InvalidArtifactError("The capture signature changed during validation.")
    return descriptor


def _inspect_pcap(source, file_size: int) -> CaptureDescriptor:
    header = source.read(24)
    if len(header) != 24:
        raise InvalidArtifactError("The PCAP global header is truncated.")
    endian, resolution = _PCAP_MAGICS[header[:4]]
    version_major, version_minor, _zone, _sigfigs, snap_length, link_type = struct.unpack(
        f"{endian}HHiIII", header[4:]
    )
    if version_major != 2 or version_minor > 4:
        raise InvalidArtifactError(
            f"Unsupported PCAP version {version_major}.{version_minor}."
        )
    if snap_length <= 0:
        raise InvalidArtifactError("The PCAP declares an invalid snapshot length.")

    packet_count = 0
    offset = 24
    while offset < file_size:
        packet_header = source.read(16)
        if len(packet_header) != 16:
            raise InvalidArtifactError("The PCAP contains a truncated packet header.")
        _seconds, _fraction, captured_length, _original_length = struct.unpack(
            f"{endian}IIII", packet_header
        )
        offset += 16
        if captured_length > file_size - offset:
            raise InvalidArtifactError("The PCAP contains a truncated packet payload.")
        source.seek(captured_length, 1)
        offset += captured_length
        packet_count += 1

    interface = CaptureInterfaceInfo(
        interface_id=0,
        link_type=link_type,
        encapsulation=_link_type_name(link_type),
        snap_length=snap_length,
    )
    return CaptureDescriptor(
        format="pcap",
        file_size=file_size,
        packet_count=packet_count,
        byte_order="little" if endian == "<" else "big",
        timestamp_resolution=resolution,
        interfaces=(interface,),
    )


def _inspect_pcapng(source, file_size: int) -> CaptureDescriptor:
    packet_count = 0
    interfaces: list[CaptureInterfaceInfo] = []
    endian: str | None = None
    section_interface_id = 0
    offset = 0

    while offset < file_size:
        prefix = source.read(12)
        if len(prefix) != 12:
            raise InvalidArtifactError("The PCAPNG contains a truncated block header.")
        raw_type = prefix[:4]
        if raw_type == _PCAPNG_MAGIC:
            endian = _PCAPNG_BYTE_ORDER.get(prefix[8:12])
            if endian is None:
                raise InvalidArtifactError("The PCAPNG section has an invalid byte-order marker.")
            block_type = 0x0A0D0D0A
            block_length = struct.unpack(f"{endian}I", prefix[4:8])[0]
            section_interface_id = 0
        elif endian is None:
            raise InvalidArtifactError("The PCAPNG does not start with a section header.")
        else:
            block_type, block_length = struct.unpack(f"{endian}II", prefix[:8])

        if block_length < 12 or block_length % 4 or block_length > _MAX_BLOCK_BYTES:
            raise InvalidArtifactError("The PCAPNG contains an invalid block length.")
        remaining = block_length - 12
        if remaining > file_size - offset - 12:
            raise InvalidArtifactError("The PCAPNG contains a truncated block.")
        body_and_trailer = source.read(remaining)
        if len(body_and_trailer) != remaining:
            raise InvalidArtifactError("The PCAPNG contains a truncated block.")
        trailer = struct.unpack(f"{endian}I", body_and_trailer[-4:])[0]
        if trailer != block_length:
            raise InvalidArtifactError("The PCAPNG block length trailer does not match its header.")
        body = prefix[8:] + body_and_trailer[:-4]

        if block_type == 1:
            if len(body) < 8:
                raise InvalidArtifactError("The PCAPNG interface block is truncated.")
            link_type, _reserved, snap_length = struct.unpack(f"{endian}HHI", body[:8])
            name = _pcapng_interface_name(body[8:], endian)
            interfaces.append(
                CaptureInterfaceInfo(
                    interface_id=section_interface_id,
                    link_type=link_type,
                    encapsulation=_link_type_name(link_type),
                    snap_length=snap_length or None,
                    name=name,
                )
            )
            section_interface_id += 1
        elif block_type in {2, 3, 6}:
            packet_count += 1

        offset += block_length

    if not interfaces:
        raise InvalidArtifactError("The PCAPNG does not contain an interface description block.")
    return CaptureDescriptor(
        format="pcapng",
        file_size=file_size,
        packet_count=packet_count,
        byte_order="little" if endian == "<" else "big",
        timestamp_resolution=None,
        interfaces=tuple(interfaces),
    )


def _pcapng_interface_name(options: bytes, endian: str) -> str | None:
    offset = 0
    while offset + 4 <= len(options):
        code, length = struct.unpack(f"{endian}HH", options[offset : offset + 4])
        offset += 4
        if code == 0:
            return None
        if length > len(options) - offset:
            return None
        value = options[offset : offset + length]
        offset += (length + 3) & ~3
        if code == 2:
            name = value.decode("utf-8", errors="replace").strip("\x00")
            return name[:255] or None
    return None


def _link_type_name(link_type: int) -> str:
    return _LINK_TYPES.get(link_type, f"DLT {link_type}")
