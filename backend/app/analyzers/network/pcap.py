from __future__ import annotations

import base64
import hashlib
from collections import defaultdict
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from uuid import uuid4

from app.analyzers.network.credentials import (
    decode_basic,
    deduplicate_credentials,
    detect_stream_credentials,
)
from app.analyzers.network.parsing import (
    INTERESTING_PORTS,
    address,
    application_protocols,
    ascii_preview,
    endpoint,
    integer,
    protocol_hierarchy,
    split_values,
    timestamp,
    transport,
    truthy,
)
from app.core.analyzers import BaseAnalyzer
from app.core.flag_detection import FlagDetector
from app.integrations.tshark import ReconstructedStream, TSharkIntegration
from app.schemas.network import (
    CaptureMetadata,
    Conversation,
    DnsRecord,
    FtpMessage,
    HttpMessage,
    InterestingPort,
    NetworkAnalysisResponse,
    NetworkFlagCandidate,
    NetworkLimits,
    PacketRecord,
    PlaintextCredential,
    StreamChunk,
    TcpStream,
    TimelineEvent,
    ToolExecutionSummary,
    TransferredFile,
)

DEFAULT_FLAG_PREFIXES = ["flag", "CTF", "picoCTF", "HTB", "H4G"]


@dataclass(frozen=True, slots=True)
class NetworkPolicy:
    max_upload_bytes: int = 128 * 1024 * 1024
    max_packets: int = 200_000
    max_packet_records: int = 10_000
    max_tcp_streams: int = 32
    max_stream_bytes: int = 2 * 1024 * 1024
    max_exported_files: int = 100
    max_exported_bytes: int = 64 * 1024 * 1024
    max_export_preview_bytes: int = 1024 * 1024
    max_application_records: int = 10_000
    max_timeline_events: int = 20_000
    max_conversations: int = 10_000
    max_discovered_tcp_streams: int = 10_000
    max_credentials: int = 500
    max_flags: int = 1_000
    tool_timeout_seconds: float = 60.0


@dataclass(frozen=True, slots=True)
class PcapInput:
    path: Path
    original_filename: str
    artifact_id: str
    workspace: Path
    capture_format: str


class NetworkPcapAnalyzer(BaseAnalyzer[PcapInput, NetworkAnalysisResponse]):
    name = "network_pcap"
    category = "network"

    def __init__(
        self,
        policy: NetworkPolicy | None = None,
        tshark: TSharkIntegration | None = None,
    ) -> None:
        self.policy = policy or NetworkPolicy()
        self._tshark = tshark or TSharkIntegration()

    def supports(self, value: object) -> bool:
        return (
            isinstance(value, PcapInput)
            and value.path.is_file()
            and value.capture_format in {"pcap", "pcapng"}
        )

    def analyze(self, value: PcapInput) -> NetworkAnalysisResponse:
        if not self.supports(value):
            raise TypeError("NetworkPcapAnalyzer requires a PCAP or PCAPNG file")
        result = self._tshark.analyze(
            value.path,
            value.workspace,
            max_packets=self.policy.max_packets,
            max_streams=self.policy.max_tcp_streams,
            max_stream_bytes=self.policy.max_stream_bytes,
            max_exported_files=self.policy.max_exported_files,
            max_exported_bytes=self.policy.max_exported_bytes,
            timeout_seconds=self.policy.tool_timeout_seconds,
        )
        rows = result.rows
        packet_records: list[PacketRecord] = []
        conversations_data: dict[tuple[str, str, str], dict] = {}
        stream_data: dict[int, dict] = {}
        dns: list[DnsRecord] = []
        http: list[HttpMessage] = []
        ftp: list[FtpMessage] = []
        credentials: list[PlaintextCredential] = []
        timeline: list[TimelineEvent] = []
        port_counts: defaultdict[tuple[str, int], int] = defaultdict(int)
        hosts: set[str] = set()
        captured_bytes = 0
        wire_bytes = 0
        timestamps: list[datetime] = []
        pending_ftp_users: dict[int, tuple[str, int]] = {}

        for row in rows:
            try:
                packet_timestamp = timestamp(row["frame.time_epoch"])
                number = integer(row["frame.number"])
            except (KeyError, ValueError, OSError, OverflowError):
                continue
            timestamps.append(packet_timestamp)
            captured_length = max(0, integer(row.get("frame.cap_len", "")))
            wire_length = max(0, integer(row.get("frame.len", "")))
            captured_bytes += captured_length
            wire_bytes += wire_length
            source = address(row, True)
            destination = address(row, False)
            if source:
                hosts.add(source)
            if destination:
                hosts.add(destination)
            transport_name, source_port, destination_port = transport(row)
            source_port = source_port if source_port is not None and source_port >= 0 else None
            destination_port = destination_port if destination_port is not None and destination_port >= 0 else None
            stream_id = integer(row.get("tcp.stream", ""), -1)
            stream_id = stream_id if stream_id >= 0 else None
            stack = [item for item in row.get("frame.protocols", "").split(":") if item]

            if len(packet_records) < self.policy.max_packet_records:
                packet_records.append(
                    PacketRecord(
                        number=number,
                        timestamp=packet_timestamp,
                        captured_length=captured_length,
                        wire_length=wire_length,
                        source=source,
                        destination=destination,
                        source_port=source_port,
                        destination_port=destination_port,
                        transport=transport_name,
                        displayed_protocol=row.get("_ws.col.Protocol", "") or (stack[-1] if stack else "unknown"),
                        protocol_stack=stack,
                        tcp_stream=stream_id,
                        info=row.get("_ws.col.Info", "")[:2_048],
                    )
                )

            if transport_name:
                for port in {source_port, destination_port} - {None}:
                    port_counts[(transport_name, port)] += 1  # type: ignore[arg-type]
                endpoint_source = endpoint(source, source_port)
                endpoint_destination = endpoint(destination, destination_port)
                endpoint_a, endpoint_b = sorted((endpoint_source, endpoint_destination))
                key = (transport_name, endpoint_a, endpoint_b)
                conversation = conversations_data.get(key)
                if conversation is None and len(conversations_data) < self.policy.max_conversations:
                    conversation = {
                        "a_to_b_packets": 0,
                        "b_to_a_packets": 0,
                        "a_to_b_bytes": 0,
                        "b_to_a_bytes": 0,
                        "first": packet_timestamp,
                        "last": packet_timestamp,
                        "protocols": set(),
                    }
                    conversations_data[key] = conversation
                if conversation is not None:
                    if endpoint_source == endpoint_a:
                        conversation["a_to_b_packets"] += 1
                        conversation["a_to_b_bytes"] += wire_length
                    else:
                        conversation["b_to_a_packets"] += 1
                        conversation["b_to_a_bytes"] += wire_length
                    conversation["first"] = min(conversation["first"], packet_timestamp)
                    conversation["last"] = max(conversation["last"], packet_timestamp)
                    conversation["protocols"].update(application_protocols(row))

            if stream_id is not None:
                stream = stream_data.get(stream_id)
                if stream is None and len(stream_data) < self.policy.max_discovered_tcp_streams:
                    stream = {
                        "endpoint_a": endpoint(source, source_port),
                        "endpoint_b": endpoint(destination, destination_port),
                        "packets": 0,
                        "bytes": 0,
                        "first": packet_timestamp,
                        "last": packet_timestamp,
                        "protocols": set(),
                        "syn": False,
                        "fin": False,
                        "reset": False,
                    }
                    stream_data[stream_id] = stream
                if stream is not None:
                    stream["packets"] += 1
                    stream["bytes"] += wire_length
                    stream["first"] = min(stream["first"], packet_timestamp)
                    stream["last"] = max(stream["last"], packet_timestamp)
                    stream["protocols"].update(application_protocols(row))
                    stream["syn"] |= truthy(row.get("tcp.flags.syn", ""))
                    stream["fin"] |= truthy(row.get("tcp.flags.fin", ""))
                    stream["reset"] |= truthy(row.get("tcp.flags.reset", ""))

            if row.get("dns.id") or row.get("dns.qry.name"):
                is_response = truthy(row.get("dns.flags.response", ""))
                record = DnsRecord(
                    frame_number=number,
                    timestamp=packet_timestamp,
                    stream_id=stream_id,
                    kind="response" if is_response else "query",
                    transaction_id=row.get("dns.id") or None,
                    name=row.get("dns.qry.name") or None,
                    query_type=row.get("dns.qry.type") or None,
                    answers=split_values(row.get("dns.a", ""), row.get("dns.aaaa", ""), row.get("dns.cname", "")),
                )
                if len(dns) < self.policy.max_application_records:
                    dns.append(record)
                if len(timeline) < self.policy.max_timeline_events:
                    timeline.append(
                    TimelineEvent(
                        timestamp=packet_timestamp,
                        event_type=f"dns.{record.kind}",
                        title=f"DNS {record.kind}",
                        description=(record.name or "Unknown DNS name")[:512],
                        frame_number=number,
                        stream_id=stream_id,
                        metadata={"transaction_id": record.transaction_id, "query_type": record.query_type},
                    )
                    )

            if row.get("http.request.method") or row.get("http.response.code"):
                is_request = bool(row.get("http.request.method"))
                message = HttpMessage(
                    frame_number=number,
                    timestamp=packet_timestamp,
                    stream_id=stream_id,
                    kind="request" if is_request else "response",
                    method=row.get("http.request.method") or None,
                    host=row.get("http.host") or None,
                    uri=row.get("http.request.uri") or None,
                    status_code=integer(row.get("http.response.code", ""), -1) if not is_request else None,
                    content_type=row.get("http.content_type") or None,
                    content_length=integer(row.get("http.content_length", ""), -1) if row.get("http.content_length") else None,
                    user_agent=row.get("http.user_agent") or None,
                )
                if message.status_code == -1:
                    message.status_code = None
                if len(http) < self.policy.max_application_records:
                    http.append(message)
                description = (
                    f"{message.method} {message.host or ''}{message.uri or ''}" if is_request
                    else f"HTTP status {message.status_code or 'unknown'}"
                )
                if len(timeline) < self.policy.max_timeline_events:
                    timeline.append(
                    TimelineEvent(
                        timestamp=packet_timestamp,
                        event_type=f"http.{message.kind}",
                        title=f"HTTP {message.kind}",
                        description=description[:512],
                        frame_number=number,
                        stream_id=stream_id,
                        metadata={"host": message.host, "uri": message.uri, "status_code": message.status_code},
                    )
                    )
                authorization = row.get("http.authorization", "")
                if authorization.lower().startswith("basic "):
                    decoded = decode_basic(authorization[6:].strip())
                    if decoded:
                        username, secret = decoded
                        if len(credentials) < self.policy.max_credentials:
                            credentials.append(
                            PlaintextCredential(
                                protocol="http-basic",
                                username=username,
                                secret=secret,
                                frame_number=number,
                                stream_id=stream_id,
                                source=f"HTTP Authorization header in frame {number}",
                                confidence=1.0,
                            )
                        )

            if row.get("ftp.request.command") or row.get("ftp.response.code"):
                command = row.get("ftp.request.command", "").upper() or None
                message = FtpMessage(
                    frame_number=number,
                    timestamp=packet_timestamp,
                    stream_id=stream_id,
                    kind="request" if command else "response",
                    command=command,
                    argument=row.get("ftp.request.arg") or None,
                    response_code=integer(row.get("ftp.response.code", ""), -1) if row.get("ftp.response.code") else None,
                    response_text=row.get("ftp.response.arg") or None,
                )
                if message.response_code == -1:
                    message.response_code = None
                if len(ftp) < self.policy.max_application_records:
                    ftp.append(message)
                detail = f"{command} {message.argument or ''}" if command else f"{message.response_code or ''} {message.response_text or ''}"
                if len(timeline) < self.policy.max_timeline_events:
                    timeline.append(
                    TimelineEvent(
                        timestamp=packet_timestamp,
                        event_type=f"ftp.{message.kind}",
                        title=f"FTP {message.kind}",
                        description=detail.strip()[:512],
                        frame_number=number,
                        stream_id=stream_id,
                        metadata={"command": command, "response_code": message.response_code},
                    )
                    )
                if stream_id is not None and command == "USER" and message.argument:
                    pending_ftp_users[stream_id] = (message.argument, number)
                elif stream_id is not None and command == "PASS" and message.argument:
                    username, user_frame = pending_ftp_users.get(stream_id, (None, number))
                    if len(credentials) < self.policy.max_credentials:
                        credentials.append(
                        PlaintextCredential(
                            protocol="ftp",
                            username=username,
                            secret=message.argument,
                            frame_number=number,
                            stream_id=stream_id,
                            source=f"FTP USER/PASS commands in frames {user_frame} and {number}",
                            confidence=1.0,
                        )
                    )

        reconstructed = {item.stream_id: item for item in result.streams}
        tcp_streams = [
            self._stream_schema(stream_id, data, reconstructed.get(stream_id))
            for stream_id, data in sorted(stream_data.items())
        ]
        credentials.extend(detect_stream_credentials(result.streams))
        credentials = deduplicate_credentials(credentials)[: self.policy.max_credentials]

        flag_detector = FlagDetector(DEFAULT_FLAG_PREFIXES)
        flags: list[NetworkFlagCandidate] = []
        for stream in result.streams:
            for flag in flag_detector.detect(stream.data):
                if len(flags) < self.policy.max_flags:
                    flags.append(
                    NetworkFlagCandidate(
                        value=flag.value,
                        matched_pattern=flag.matched_pattern,
                        source=f"TCP stream {stream.stream_id}",
                        stream_id=stream.stream_id,
                        offset=flag.offset,
                        confidence=flag.confidence,
                        context=flag.context,
                    )
                )

        transferred_files: list[TransferredFile] = []
        for exported in result.exported_objects:
            data = exported.path.read_bytes()
            for flag in flag_detector.detect(data):
                if len(flags) < self.policy.max_flags:
                    flags.append(
                    NetworkFlagCandidate(
                        value=flag.value,
                        matched_pattern=flag.matched_pattern,
                        source=f"{exported.protocol} object {exported.source_name}",
                        stream_id=None,
                        offset=flag.offset,
                        confidence=flag.confidence,
                        context=flag.context,
                    )
                )
            preview = data[: self.policy.max_export_preview_bytes]
            transferred_files.append(
                TransferredFile(
                    artifact_id=str(uuid4()),
                    parent_artifact_id=value.artifact_id,
                    protocol=exported.protocol,  # type: ignore[arg-type]
                    source_name=exported.source_name,
                    size=len(data),
                    sha256=hashlib.sha256(data).hexdigest(),
                    content_base64=base64.b64encode(preview).decode("ascii"),
                    content_truncated=len(preview) < len(data),
                )
            )

        conversations = [
            Conversation(
                transport=transport,
                endpoint_a=endpoint_a,
                endpoint_b=endpoint_b,
                packets_a_to_b=data["a_to_b_packets"],
                packets_b_to_a=data["b_to_a_packets"],
                bytes_a_to_b=data["a_to_b_bytes"],
                bytes_b_to_a=data["b_to_a_bytes"],
                first_seen=data["first"],
                last_seen=data["last"],
                application_protocols=sorted(data["protocols"]),
            )
            for (transport, endpoint_a, endpoint_b), data in conversations_data.items()
        ]
        conversations.sort(
            key=lambda item: -(item.bytes_a_to_b + item.bytes_b_to_a)
        )
        interesting_ports = [
            InterestingPort(
                port=port,
                transport=transport,  # type: ignore[arg-type]
                service=INTERESTING_PORTS[(transport, port)][0],
                packet_count=count,
                reason=INTERESTING_PORTS[(transport, port)][1],
            )
            for (transport, port), count in sorted(port_counts.items())
            if (transport, port) in INTERESTING_PORTS
        ]
        first_seen = min(timestamps) if timestamps else None
        last_seen = max(timestamps) if timestamps else None
        file_data = value.path.read_bytes()
        warnings = list(result.warnings)
        if len(rows) >= self.policy.max_packets:
            warnings.append(
                f"Packet analysis reached the configured {self.policy.max_packets}-packet limit."
            )
        if len(rows) > self.policy.max_packet_records:
            warnings.append(
                f"Per-packet response records were limited to {self.policy.max_packet_records}."
            )
        if len(conversations_data) >= self.policy.max_conversations:
            warnings.append(f"Conversation results were limited to {self.policy.max_conversations}.")
        if len(stream_data) >= self.policy.max_discovered_tcp_streams:
            warnings.append(
                f"TCP stream discovery results were limited to {self.policy.max_discovered_tcp_streams}."
            )
        if any(len(records) >= self.policy.max_application_records for records in (dns, http, ftp)):
            warnings.append(
                f"DNS, HTTP, or FTP records reached the per-protocol limit of {self.policy.max_application_records}."
            )
        if len(timeline) >= self.policy.max_timeline_events:
            warnings.append(f"Timeline results were limited to {self.policy.max_timeline_events} events.")
        if len(credentials) >= self.policy.max_credentials:
            warnings.append(f"Credential results were limited to {self.policy.max_credentials} candidates.")
        if len(flags) >= self.policy.max_flags:
            warnings.append(f"Flag results were limited to {self.policy.max_flags} candidates.")

        timeline.sort(key=lambda item: (item.timestamp, item.frame_number or 0))
        return NetworkAnalysisResponse(
            analysis_id=str(uuid4()),
            analyzer=self.name,
            capture=CaptureMetadata(
                artifact_id=value.artifact_id,
                original_filename=value.original_filename,
                format=value.capture_format,  # type: ignore[arg-type]
                size=len(file_data),
                sha256=hashlib.sha256(file_data).hexdigest(),
                packet_count=len(rows),
                analyzed_packet_count=len(rows),
                captured_bytes=captured_bytes,
                wire_bytes=wire_bytes,
                first_seen=first_seen,
                last_seen=last_seen,
                duration_seconds=round((last_seen - first_seen).total_seconds(), 6) if first_seen and last_seen else 0.0,
                unique_hosts=len(hosts),
                packet_limit_reached=len(rows) >= self.policy.max_packets,
            ),
            packets=packet_records,
            packet_records_truncated=len(rows) > len(packet_records),
            protocol_hierarchy=protocol_hierarchy(rows),
            conversations=conversations,
            dns=dns,
            http=http,
            ftp=ftp,
            tcp_streams=tcp_streams,
            transferred_files=transferred_files,
            plaintext_credentials=credentials,
            interesting_ports=interesting_ports,
            flags=flags,
            timeline=timeline,
            tool_executions=[
                ToolExecutionSummary(
                    operation=operation,
                    returncode=execution.returncode,
                    duration_ms=execution.duration_ms,
                )
                for operation, execution in result.executions
            ],
            warnings=list(dict.fromkeys(warnings)),
            limits=NetworkLimits(
                max_upload_bytes=self.policy.max_upload_bytes,
                max_packets=self.policy.max_packets,
                max_packet_records=self.policy.max_packet_records,
                max_tcp_streams=self.policy.max_tcp_streams,
                max_stream_bytes=self.policy.max_stream_bytes,
                max_exported_files=self.policy.max_exported_files,
                max_exported_bytes=self.policy.max_exported_bytes,
                max_application_records=self.policy.max_application_records,
                max_timeline_events=self.policy.max_timeline_events,
                max_conversations=self.policy.max_conversations,
                max_discovered_tcp_streams=self.policy.max_discovered_tcp_streams,
                max_credentials=self.policy.max_credentials,
                max_flags=self.policy.max_flags,
            ),
        )

    @staticmethod
    def _stream_schema(stream_id: int, data: dict, reconstructed: ReconstructedStream | None) -> TcpStream:
        payload = reconstructed.data if reconstructed else b""
        return TcpStream(
            stream_id=stream_id,
            endpoint_a=data["endpoint_a"],
            endpoint_b=data["endpoint_b"],
            packet_count=data["packets"],
            wire_bytes=data["bytes"],
            first_seen=data["first"],
            last_seen=data["last"],
            application_protocols=sorted(data["protocols"]),
            syn_seen=data["syn"],
            fin_seen=data["fin"],
            reset_seen=data["reset"],
            reconstructed_bytes=len(payload),
            reconstructed_base64=base64.b64encode(payload).decode("ascii"),
            ascii_preview=ascii_preview(payload),
            chunks=[StreamChunk(direction=direction, offset=offset, length=length) for direction, offset, length in (reconstructed.chunks if reconstructed else ())],
            reconstruction_truncated=reconstructed.truncated if reconstructed else False,
        )
