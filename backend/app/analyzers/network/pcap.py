from __future__ import annotations

import base64
import hashlib
from collections import defaultdict
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from time import perf_counter
from typing import Callable
from uuid import uuid4

from app.analyzers.network.credentials import (
    decode_basic,
    deduplicate_credentials,
    detect_stream_credentials,
)
from app.analyzers.network.capture_loader import CaptureDescriptor, inspect_capture
from app.analyzers.network.flag_hunter import RawFlagHunter
from app.analyzers.network.investigation import NetworkInvestigationRanker
from app.analyzers.network.parsing import (
    INTERESTING_PORTS,
    address,
    application_protocols,
    ascii_preview,
    endpoint,
    hex_byte_length,
    hex_bytes,
    integer,
    protocol_hierarchy,
    split_values,
    timestamp,
    transport,
    truthy,
)
from app.analyzers.network.payloads import analyze_hidden_payloads
from app.core.analyzers import BaseAnalyzer
from app.core.flag_detection import FlagDetector
from app.integrations.tshark import ReconstructedStream, TSharkIntegration
from app.schemas.network import (
    CaptureMetadata,
    CaptureInterface,
    AnalysisStageTiming,
    Conversation,
    DnsRecord,
    FtpMessage,
    HttpMessage,
    InterestingPort,
    NetworkAnalysisResponse,
    NetworkFlagCandidate,
    NetworkInsight,
    NetworkLimits,
    NetworkEndpoints,
    PacketRecord,
    PlaintextCredential,
    StreamChunk,
    TcpStream,
    TimelineEvent,
    ToolExecutionSummary,
    TransferredFile,
    UdpStream,
)

DEFAULT_FLAG_PREFIXES = ["flag", "CTF", "picoCTF", "HTB", "THM", "H4G"]
ProgressCallback = Callable[[str, str | None], None]


def _deduplicate_flags(flags: list[NetworkFlagCandidate]) -> list[NetworkFlagCandidate]:
    merged: dict[tuple[str, tuple[str, ...]], NetworkFlagCandidate] = {}
    for candidate in flags:
        key = (candidate.value, tuple(candidate.decoding_steps))
        existing = merged.get(key)
        if existing is None:
            merged[key] = candidate
            continue
        sources = existing.source.split("; ")
        if candidate.source not in sources:
            sources.append(candidate.source)
        merged[key] = existing.model_copy(
            update={
                "source": "; ".join(sources),
                "stream_id": existing.stream_id if existing.stream_id == candidate.stream_id else None,
                "frame_numbers": sorted(set(existing.frame_numbers + candidate.frame_numbers)),
                "offset": min(existing.offset, candidate.offset),
                "confidence": max(existing.confidence, candidate.confidence),
                "context": min((existing.context, candidate.context), key=len),
            }
        )
    return list(merged.values())


@dataclass(frozen=True, slots=True)
class NetworkPolicy:
    max_upload_bytes: int = 128 * 1024 * 1024
    max_packets: int = 200_000
    max_packet_records: int = 10_000
    max_tcp_streams: int = 32
    max_udp_streams: int = 128
    max_stream_bytes: int = 2 * 1024 * 1024
    max_exported_files: int = 100
    max_exported_bytes: int = 64 * 1024 * 1024
    max_export_preview_bytes: int = 1024 * 1024
    max_application_records: int = 10_000
    max_timeline_events: int = 20_000
    max_conversations: int = 10_000
    max_discovered_tcp_streams: int = 10_000
    max_discovered_udp_streams: int = 10_000
    max_credentials: int = 500
    max_flags: int = 1_000
    max_insights: int = 500
    max_investigation_targets: int = 100
    tool_timeout_seconds: float = 60.0


@dataclass(frozen=True, slots=True)
class PcapInput:
    path: Path
    original_filename: str
    artifact_id: str
    workspace: Path
    capture_format: str
    capture_descriptor: CaptureDescriptor | None = None
    flag_prefixes: tuple[str, ...] = ()


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

    def analyze(
        self,
        value: PcapInput,
        *,
        progress: ProgressCallback | None = None,
    ) -> NetworkAnalysisResponse:
        if not self.supports(value):
            raise TypeError("NetworkPcapAnalyzer requires a PCAP or PCAPNG file")
        analysis_started = perf_counter()
        stage_timings: list[AnalysisStageTiming] = []
        _progress(progress, "network.capture", "Inspecting capture metadata and raw flag patterns")
        stage_started = perf_counter()
        descriptor = value.capture_descriptor or inspect_capture(value.path, value.capture_format)
        prefixes = list(dict.fromkeys([*DEFAULT_FLAG_PREFIXES, *value.flag_prefixes]))
        raw_matches = RawFlagHunter(prefixes, maximum_matches=self.policy.max_flags).analyze(
            value.path
        )
        stage_timings.append(_stage("capture-scan", "Capture validation and raw scan", stage_started))
        _progress(progress, "network.tshark", "Starting bounded TShark analysis")
        stage_started = perf_counter()
        result = self._tshark.analyze(
            value.path,
            value.workspace,
            max_packets=self.policy.max_packets,
            max_streams=self.policy.max_tcp_streams,
            max_stream_bytes=self.policy.max_stream_bytes,
            max_exported_files=self.policy.max_exported_files,
            max_exported_bytes=self.policy.max_exported_bytes,
            timeout_seconds=self.policy.tool_timeout_seconds,
            max_udp_streams=self.policy.max_udp_streams,
            progress=progress,
        )
        stage_timings.append(
            _stage(
                "tshark",
                "TShark decode, batched stream reconstruction, and observed exports",
                stage_started,
                f"{len(result.executions)} external execution(s)",
            )
        )
        _progress(progress, "network.packet-models", "Building packet, protocol, and conversation models")
        stage_started = perf_counter()
        rows = result.rows
        packet_records: list[PacketRecord] = []
        conversations_data: dict[tuple[str, str, str], dict] = {}
        stream_data: dict[int, dict] = {}
        udp_stream_data: dict[int, dict] = {}
        dns: list[DnsRecord] = []
        http: list[HttpMessage] = []
        ftp: list[FtpMessage] = []
        credentials: list[PlaintextCredential] = []
        timeline: list[TimelineEvent] = []
        port_counts: defaultdict[tuple[str, int], int] = defaultdict(int)
        hosts: set[str] = set()
        ipv4_hosts: set[str] = set()
        ipv6_hosts: set[str] = set()
        mac_addresses: set[str] = set()
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
            for host in split_values(row.get("ip.src", ""), row.get("ip.dst", "")):
                ipv4_hosts.add(host)
            for host in split_values(row.get("ipv6.src", ""), row.get("ipv6.dst", "")):
                ipv6_hosts.add(host)
            for mac in split_values(row.get("eth.src", ""), row.get("eth.dst", "")):
                mac_addresses.add(mac.lower())
            transport_name, source_port, destination_port = transport(row)
            source_port = source_port if source_port is not None and source_port >= 0 else None
            destination_port = destination_port if destination_port is not None and destination_port >= 0 else None
            stream_id = integer(row.get("tcp.stream", ""), -1)
            stream_id = stream_id if stream_id >= 0 else None
            udp_stream_id = integer(row.get("udp.stream", ""), -1)
            udp_stream_id = udp_stream_id if udp_stream_id >= 0 else None
            packet_payload = hex_bytes(
                row.get(f"{transport_name}.payload", "") or row.get("data.data", "")
            ) if transport_name else hex_bytes(row.get("data.data", ""))
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
                        udp_stream=udp_stream_id,
                        payload_length=len(packet_payload),
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
                        "stream_ids": set(),
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
                    conversation["stream_ids"].update(
                        item
                        for item in (stream_id if transport_name == "tcp" else udp_stream_id,)
                        if item is not None
                    )

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

            if udp_stream_id is not None:
                udp_stream = udp_stream_data.get(udp_stream_id)
                if udp_stream is None and len(udp_stream_data) < self.policy.max_discovered_udp_streams:
                    udp_stream = {
                        "endpoint_a": endpoint(source, source_port),
                        "endpoint_b": endpoint(destination, destination_port),
                        "packets": 0,
                        "bytes": 0,
                        "first": packet_timestamp,
                        "last": packet_timestamp,
                        "protocols": set(),
                    }
                    udp_stream_data[udp_stream_id] = udp_stream
                if udp_stream is not None:
                    udp_stream["packets"] += 1
                    udp_stream["bytes"] += wire_length
                    udp_stream["first"] = min(udp_stream["first"], packet_timestamp)
                    udp_stream["last"] = max(udp_stream["last"], packet_timestamp)
                    udp_stream["protocols"].update(application_protocols(row))

            if row.get("dns.id") or row.get("dns.qry.name"):
                is_response = truthy(row.get("dns.flags.response", ""))
                record = DnsRecord(
                    frame_number=number,
                    timestamp=packet_timestamp,
                    stream_id=stream_id if stream_id is not None else udp_stream_id,
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
                http_body_field = row.get("http.file_data", "")
                http_body = hex_bytes(http_body_field)
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
                    body_base64=base64.b64encode(http_body).decode("ascii"),
                    body_ascii_preview=ascii_preview(http_body),
                    body_truncated=hex_byte_length(http_body_field) > len(http_body),
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

        stage_timings.append(
            _stage("packet-models", "Packet and protocol model construction", stage_started, f"{len(rows)} decoded rows")
        )
        _progress(progress, "network.stream-models", "Finalizing reconstructed stream and credential evidence")
        stage_started = perf_counter()

        reconstructed = {item.stream_id: item for item in result.streams}
        tcp_streams = [
            self._stream_schema(stream_id, data, reconstructed.get(stream_id))
            for stream_id, data in sorted(stream_data.items())
        ]
        reconstructed_udp = {item.stream_id: item for item in result.udp_streams}
        udp_streams = [
            self._udp_stream_schema(stream_id, data, reconstructed_udp.get(stream_id))
            for stream_id, data in sorted(udp_stream_data.items())
        ]
        credentials.extend(detect_stream_credentials(result.streams))
        credentials = deduplicate_credentials(credentials)[: self.policy.max_credentials]
        stage_timings.append(
            _stage("stream-models", "Stream and credential model construction", stage_started)
        )

        _progress(progress, "network.flags", "Scanning reconstructed streams for flag candidates")
        stage_started = perf_counter()
        flag_detector = FlagDetector(prefixes)
        flags: list[NetworkFlagCandidate] = [
            NetworkFlagCandidate(
                value=item.detected.value,
                matched_pattern=item.detected.matched_pattern,
                source=f"Raw capture ({item.encoding})",
                stream_id=None,
                offset=item.detected.offset,
                confidence=0.45 if item.encoding.startswith("UTF-16") else 0.35,
                context=item.detected.context,
                decoding_steps=[item.encoding] if item.encoding.startswith("UTF-16") else [],
                artifact_id=value.artifact_id,
            )
            for item in raw_matches
        ]
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

        stage_timings.append(
            _stage("flags", "Raw capture and TCP stream flag scanning", stage_started)
        )

        _progress(progress, "network.payloads", "Analyzing hidden payloads and decoded evidence")
        stage_started = perf_counter()
        hidden_payloads = analyze_hidden_payloads(
            result.rows,
            result.streams,
            flag_detector,
            max_insights=self.policy.max_insights,
            max_flags=self.policy.max_flags,
        )
        insights = [
            NetworkInsight(
                title=item.title,
                category=item.category,  # type: ignore[arg-type]
                value=item.value,
                source=item.source,
                frame_numbers=list(item.frame_numbers),
                stream_id=item.stream_id,
                confidence=item.confidence,
                decoding_steps=list(item.decoding_steps),
                metadata=item.metadata,
            )
            for item in hidden_payloads.insights
        ]
        for item in hidden_payloads.flags:
            if len(flags) >= self.policy.max_flags:
                break
            flags.append(
                NetworkFlagCandidate(
                    value=item.detected.value,
                    matched_pattern=item.detected.matched_pattern,
                    source=item.source,
                    stream_id=item.stream_id,
                    offset=item.detected.offset,
                    confidence=item.confidence or item.detected.confidence,
                    context=item.detected.context,
                    frame_numbers=list(item.frame_numbers),
                    decoding_steps=list(item.decoding_steps),
                )
            )

        stage_timings.append(
            _stage("payloads", "Hidden payload, decoder, and flag analysis", stage_started)
        )
        _progress(progress, "network.artifacts", "Hashing and registering transferred artifacts")
        stage_started = perf_counter()

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

        stage_timings.append(
            _stage("artifacts", "Transferred artifact processing", stage_started, f"{len(transferred_files)} artifact(s)")
        )
        _progress(progress, "network.ranking", "Ranking evidence and generating investigation handoffs")
        stage_started = perf_counter()

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
                stream_ids=sorted(data["stream_ids"]),
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
        flags = _deduplicate_flags(flags)
        flags.sort(
            key=lambda item: (
                -item.confidence,
                not bool(item.decoding_steps),
                item.value,
            )
        )
        investigation_targets, investigation_summary = NetworkInvestigationRanker(
            rows=rows,
            tcp_streams=tcp_streams,
            udp_streams=udp_streams,
            conversations=conversations,
            dns=dns,
            http=http,
            artifacts=transferred_files,
            credentials=credentials,
            insights=insights,
            flags=flags,
            capture_wire_bytes=wire_bytes,
            maximum_targets=self.policy.max_investigation_targets,
        ).rank_all()
        stage_timings.append(
            _stage("ranking", "Evidence correlation and investigation ranking", stage_started, f"{len(investigation_targets)} ranked target(s)")
        )
        first_seen = min(timestamps) if timestamps else None
        last_seen = max(timestamps) if timestamps else None
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
        if len(udp_stream_data) >= self.policy.max_discovered_udp_streams:
            warnings.append(
                f"UDP stream discovery results were limited to {self.policy.max_discovered_udp_streams}."
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
        if len(insights) >= self.policy.max_insights:
            warnings.append(f"Decoded payload insights were limited to {self.policy.max_insights} results.")

        timeline.sort(key=lambda item: (item.timestamp, item.frame_number or 0))
        stage_timings.append(
            AnalysisStageTiming(
                stage="total",
                label="Backend analysis total",
                duration_ms=max(0, round((perf_counter() - analysis_started) * 1000)),
            )
        )
        _progress(progress, "network.response", "Serializing the completed analysis response")
        return NetworkAnalysisResponse(
            analysis_id=str(uuid4()),
            analyzer=self.name,
            capture=CaptureMetadata(
                artifact_id=value.artifact_id,
                original_filename=value.original_filename,
                format=value.capture_format,  # type: ignore[arg-type]
                size=descriptor.file_size,
                sha256=_sha256(value.path),
                byte_order=descriptor.byte_order,  # type: ignore[arg-type]
                timestamp_resolution=descriptor.timestamp_resolution,
                encapsulations=list(descriptor.encapsulations),
                snap_length=descriptor.snap_length,
                interfaces=[
                    CaptureInterface(
                        interface_id=item.interface_id,
                        name=item.name,
                        link_type=item.link_type,
                        encapsulation=item.encapsulation,
                        snap_length=item.snap_length,
                    )
                    for item in descriptor.interfaces
                ],
                packet_count=max(descriptor.packet_count, len(rows)),
                analyzed_packet_count=len(rows),
                captured_bytes=captured_bytes,
                wire_bytes=wire_bytes,
                first_seen=first_seen,
                last_seen=last_seen,
                duration_seconds=round((last_seen - first_seen).total_seconds(), 6) if first_seen and last_seen else 0.0,
                unique_hosts=len(hosts),
                packet_limit_reached=descriptor.packet_count > len(rows),
            ),
            packets=packet_records,
            packet_records_truncated=len(rows) > len(packet_records),
            endpoints=NetworkEndpoints(
                ipv4_hosts=sorted(ipv4_hosts),
                ipv6_hosts=sorted(ipv6_hosts),
                mac_addresses=sorted(mac_addresses),
                tcp_ports=sorted(port for transport, port in port_counts if transport == "tcp"),
                udp_ports=sorted(port for transport, port in port_counts if transport == "udp"),
            ),
            protocol_hierarchy=protocol_hierarchy(rows),
            conversations=conversations,
            dns=dns,
            http=http,
            ftp=ftp,
            tcp_streams=tcp_streams,
            udp_streams=udp_streams,
            transferred_files=transferred_files,
            plaintext_credentials=credentials,
            interesting_ports=interesting_ports,
            insights=insights,
            flags=flags,
            investigation_summary=investigation_summary,
            investigation_targets=investigation_targets,
            timeline=timeline,
            tool_executions=[
                ToolExecutionSummary(
                    operation=operation,
                    returncode=execution.returncode,
                    duration_ms=execution.duration_ms,
                )
                for operation, execution in result.executions
            ],
            stage_timings=stage_timings,
            warnings=list(dict.fromkeys(warnings)),
            limits=NetworkLimits(
                max_upload_bytes=self.policy.max_upload_bytes,
                max_packets=self.policy.max_packets,
                max_packet_records=self.policy.max_packet_records,
                max_tcp_streams=self.policy.max_tcp_streams,
                max_udp_streams=self.policy.max_udp_streams,
                max_stream_bytes=self.policy.max_stream_bytes,
                max_exported_files=self.policy.max_exported_files,
                max_exported_bytes=self.policy.max_exported_bytes,
                max_application_records=self.policy.max_application_records,
                max_timeline_events=self.policy.max_timeline_events,
                max_conversations=self.policy.max_conversations,
                max_discovered_tcp_streams=self.policy.max_discovered_tcp_streams,
                max_discovered_udp_streams=self.policy.max_discovered_udp_streams,
                max_credentials=self.policy.max_credentials,
                max_flags=self.policy.max_flags,
                max_insights=self.policy.max_insights,
                max_investigation_targets=self.policy.max_investigation_targets,
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

    @staticmethod
    def _udp_stream_schema(stream_id: int, data: dict, reconstructed: ReconstructedStream | None) -> UdpStream:
        payload = reconstructed.data if reconstructed else b""
        return UdpStream(
            stream_id=stream_id,
            endpoint_a=data["endpoint_a"],
            endpoint_b=data["endpoint_b"],
            packet_count=data["packets"],
            wire_bytes=data["bytes"],
            first_seen=data["first"],
            last_seen=data["last"],
            application_protocols=sorted(data["protocols"]),
            reconstructed_bytes=len(payload),
            reconstructed_base64=base64.b64encode(payload).decode("ascii"),
            ascii_preview=ascii_preview(payload),
            chunks=[
                StreamChunk(direction=direction, offset=offset, length=length)
                for direction, offset, length in (reconstructed.chunks if reconstructed else ())
            ],
            reconstruction_truncated=reconstructed.truncated if reconstructed else False,
        )


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        while chunk := source.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def _stage(
    stage: str,
    label: str,
    started: float,
    detail: str | None = None,
) -> AnalysisStageTiming:
    return AnalysisStageTiming(
        stage=stage,
        label=label,
        duration_ms=max(0, round((perf_counter() - started) * 1000)),
        detail=detail,
    )


def _progress(callback: ProgressCallback | None, stage: str, detail: str | None = None) -> None:
    if callback is not None:
        callback(stage, detail)
