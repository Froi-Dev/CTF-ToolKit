from __future__ import annotations

from datetime import datetime, timezone

from app.schemas.network import ProtocolHierarchyNode

PCAP_MAGICS = {
    b"\xd4\xc3\xb2\xa1",
    b"\xa1\xb2\xc3\xd4",
    b"\x4d\x3c\xb2\xa1",
    b"\xa1\xb2\x3c\x4d",
}
PCAPNG_MAGIC = b"\x0a\x0d\x0d\x0a"
BASE_PROTOCOLS = {
    "eth",
    "ethertype",
    "ip",
    "ipv6",
    "tcp",
    "udp",
    "frame",
    "data",
    "sll",
    "sll2",
    "null",
}
INTERESTING_PORTS: dict[tuple[str, int], tuple[str, str]] = {
    ("tcp", 20): ("FTP data", "Unencrypted FTP data transfer"),
    ("tcp", 21): ("FTP", "Plaintext authentication and file transfer"),
    ("tcp", 22): ("SSH", "Remote administration traffic"),
    ("tcp", 23): ("Telnet", "Plaintext remote terminal traffic"),
    ("tcp", 25): ("SMTP", "Email traffic that may contain plaintext authentication"),
    ("udp", 53): ("DNS", "Name-resolution traffic"),
    ("tcp", 53): ("DNS", "Name-resolution traffic over TCP"),
    ("tcp", 80): ("HTTP", "Unencrypted web traffic"),
    ("tcp", 110): ("POP3", "Potential plaintext mailbox authentication"),
    ("tcp", 143): ("IMAP", "Potential plaintext mailbox authentication"),
    ("udp", 161): ("SNMP", "Management traffic and possible community strings"),
    ("tcp", 445): ("SMB", "Windows file-sharing traffic"),
    ("tcp", 1080): ("SOCKS", "Proxy traffic"),
    ("tcp", 1337): ("Common CTF service", "Frequently used custom challenge port"),
    ("tcp", 3306): ("MySQL", "Database service traffic"),
    ("tcp", 3389): ("RDP", "Remote desktop traffic"),
    ("tcp", 4444): ("Common callback", "Frequently used shell or CTF service port"),
    ("tcp", 5432): ("PostgreSQL", "Database service traffic"),
    ("tcp", 6379): ("Redis", "Data-store service traffic"),
    ("tcp", 8080): ("HTTP alternate", "Common alternate web-service port"),
}


def capture_format(data: bytes) -> str | None:
    magic = data[:4]
    if magic == PCAPNG_MAGIC:
        return "pcapng"
    if magic in PCAP_MAGICS:
        return "pcap"
    return None


def timestamp(value: str) -> datetime:
    return datetime.fromtimestamp(float(value), tz=timezone.utc)


def integer(value: str, default: int = 0) -> int:
    try:
        return int(value.split(",", 1)[0])
    except (TypeError, ValueError):
        return default


def truthy(value: str) -> bool:
    return value.lower() in {"1", "true", "yes", "set"}


def split_values(*values: str) -> list[str]:
    found: list[str] = []
    for value in values:
        for item in value.split(","):
            normalized = item.strip()
            if normalized and normalized not in found:
                found.append(normalized)
    return found


def address(row: dict[str, str], source: bool) -> str | None:
    side = "src" if source else "dst"
    for field in (f"ip.{side}", f"ipv6.{side}", f"eth.{side}"):
        if row.get(field):
            return row[field].split(",", 1)[0]
    return None


def transport(row: dict[str, str]) -> tuple[str | None, int | None, int | None]:
    if row.get("tcp.srcport") or row.get("tcp.dstport"):
        return "tcp", integer(row.get("tcp.srcport", ""), -1), integer(row.get("tcp.dstport", ""), -1)
    if row.get("udp.srcport") or row.get("udp.dstport"):
        return "udp", integer(row.get("udp.srcport", ""), -1), integer(row.get("udp.dstport", ""), -1)
    return None, None, None


def endpoint(address_value: str | None, port: int | None) -> str:
    if address_value is None:
        return "unknown"
    if port is None or port < 0:
        return address_value
    return f"[{address_value}]:{port}" if ":" in address_value else f"{address_value}:{port}"


def application_protocols(row: dict[str, str]) -> set[str]:
    stack = [item for item in row.get("frame.protocols", "").split(":") if item]
    return {item for item in stack if item not in BASE_PROTOCOLS}


def protocol_hierarchy(rows: tuple[dict[str, str], ...]) -> list[ProtocolHierarchyNode]:
    roots: dict[str, dict] = {}
    for row in rows:
        cursor = roots
        seen: set[str] = set()
        for protocol in filter(None, row.get("frame.protocols", "").split(":")):
            if protocol in seen:
                continue
            seen.add(protocol)
            node = cursor.setdefault(protocol, {"count": 0, "children": {}})
            node["count"] += 1
            cursor = node["children"]

    denominator = max(1, len(rows))

    def build(nodes: dict[str, dict]) -> list[ProtocolHierarchyNode]:
        return [
            ProtocolHierarchyNode(
                protocol=name,
                packets=value["count"],
                percentage=round(value["count"] * 100 / denominator, 3),
                children=build(value["children"]),
            )
            for name, value in sorted(
                nodes.items(), key=lambda item: (-item[1]["count"], item[0])
            )
        ]

    return build(roots)


def ascii_preview(data: bytes, maximum: int = 16_384) -> str:
    preview = data[:maximum]
    return "".join(
        chr(byte) if byte in (9, 10, 13) or 32 <= byte <= 126 else "."
        for byte in preview
    )
