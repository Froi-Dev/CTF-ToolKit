from __future__ import annotations

import ipaddress


def _quoted(value: str) -> str:
    return '"' + value.replace("\\", "\\\\").replace('"', '\\"') + '"'


class WiresharkFilterGenerator:
    """Generate conservative Wireshark display filters from decoded fields."""

    @staticmethod
    def for_frame(frame_number: int) -> str:
        if frame_number < 1:
            raise ValueError("frame_number must be positive")
        return f"frame.number == {frame_number}"

    @classmethod
    def for_frames(cls, frame_numbers: list[int] | tuple[int, ...]) -> str | None:
        values = sorted(set(frame_numbers))
        if not values:
            return None
        return " || ".join(cls.for_frame(value) for value in values)

    @staticmethod
    def for_tcp_stream(stream_id: int) -> str:
        if stream_id < 0:
            raise ValueError("stream_id must not be negative")
        return f"tcp.stream eq {stream_id}"

    @staticmethod
    def for_udp_stream(stream_id: int) -> str:
        if stream_id < 0:
            raise ValueError("stream_id must not be negative")
        return f"udp.stream eq {stream_id}"

    @staticmethod
    def for_host(host: str) -> str:
        parsed = ipaddress.ip_address(host)
        field = "ip.addr" if parsed.version == 4 else "ipv6.addr"
        return f"{field} == {parsed.compressed}"

    @classmethod
    def for_conversation(cls, host_a: str, host_b: str) -> str:
        return f"{cls.for_host(host_a)} && {cls.for_host(host_b)}"

    @classmethod
    def for_dns_group(cls, *, client: str | None = None, domain: str | None = None) -> str:
        parts = ["dns"]
        if client:
            parsed = ipaddress.ip_address(client)
            field = "ip.src" if parsed.version == 4 else "ipv6.src"
            parts.append(f"{field} == {parsed.compressed}")
        if domain:
            parts.append(f"dns.qry.name contains {_quoted(domain)}")
        return " && ".join(parts)

    @staticmethod
    def for_http_request(
        *, method: str | None = None, host: str | None = None, uri: str | None = None
    ) -> str:
        parts = ["http.request"]
        if method:
            parts.append(f"http.request.method == {_quoted(method.upper())}")
        if host:
            parts.append(f"http.host == {_quoted(host)}")
        if uri:
            parts.append(f"http.request.uri == {_quoted(uri)}")
        return " && ".join(parts)

    @staticmethod
    def for_protocol(protocol: str) -> str:
        normalized = protocol.strip().lower()
        if not normalized or not all(character.isalnum() or character in "_.-" for character in normalized):
            raise ValueError("protocol contains unsupported display-filter characters")
        return normalized

    @staticmethod
    def for_port(port: int, transport: str | None = None) -> str:
        if not 0 <= port <= 65535:
            raise ValueError("port must be between 0 and 65535")
        normalized = transport.lower() if transport else None
        if normalized not in {None, "tcp", "udp"}:
            raise ValueError("transport must be tcp or udp")
        return f"{normalized + '.' if normalized else ''}port == {port}"
