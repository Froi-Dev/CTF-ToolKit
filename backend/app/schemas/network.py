from __future__ import annotations

from datetime import datetime
from typing import Literal

from pydantic import BaseModel, Field


class CaptureMetadata(BaseModel):
    artifact_id: str
    original_filename: str
    format: Literal["pcap", "pcapng"]
    size: int = Field(ge=0)
    sha256: str
    byte_order: Literal["little", "big"]
    timestamp_resolution: str | None
    encapsulations: list[str]
    snap_length: int | None = Field(default=None, ge=0)
    interfaces: list["CaptureInterface"]
    packet_count: int = Field(ge=0)
    analyzed_packet_count: int = Field(ge=0)
    captured_bytes: int = Field(ge=0)
    wire_bytes: int = Field(ge=0)
    first_seen: datetime | None
    last_seen: datetime | None
    duration_seconds: float = Field(ge=0.0)
    unique_hosts: int = Field(ge=0)
    packet_limit_reached: bool


class CaptureInterface(BaseModel):
    interface_id: int = Field(ge=0)
    name: str | None
    link_type: int = Field(ge=0)
    encapsulation: str
    snap_length: int | None = Field(default=None, ge=0)


class NetworkEndpoints(BaseModel):
    ipv4_hosts: list[str]
    ipv6_hosts: list[str]
    mac_addresses: list[str]
    tcp_ports: list[int]
    udp_ports: list[int]


class PacketRecord(BaseModel):
    number: int = Field(ge=1)
    timestamp: datetime
    captured_length: int = Field(ge=0)
    wire_length: int = Field(ge=0)
    source: str | None
    destination: str | None
    source_port: int | None = Field(default=None, ge=0, le=65535)
    destination_port: int | None = Field(default=None, ge=0, le=65535)
    transport: str | None
    displayed_protocol: str
    protocol_stack: list[str]
    tcp_stream: int | None = Field(default=None, ge=0)
    udp_stream: int | None = Field(default=None, ge=0)
    payload_length: int = Field(default=0, ge=0)
    info: str


class ProtocolHierarchyNode(BaseModel):
    protocol: str
    packets: int = Field(ge=0)
    percentage: float = Field(ge=0.0, le=100.0)
    children: list["ProtocolHierarchyNode"] = Field(default_factory=list)


class Conversation(BaseModel):
    transport: str
    endpoint_a: str
    endpoint_b: str
    packets_a_to_b: int = Field(ge=0)
    packets_b_to_a: int = Field(ge=0)
    bytes_a_to_b: int = Field(ge=0)
    bytes_b_to_a: int = Field(ge=0)
    first_seen: datetime
    last_seen: datetime
    application_protocols: list[str]
    stream_ids: list[int] = Field(default_factory=list)


class DnsRecord(BaseModel):
    frame_number: int
    timestamp: datetime
    stream_id: int | None = None
    kind: Literal["query", "response"]
    transaction_id: str | None
    name: str | None
    query_type: str | None
    answers: list[str]


class HttpMessage(BaseModel):
    frame_number: int
    timestamp: datetime
    stream_id: int | None = None
    kind: Literal["request", "response"]
    method: str | None
    host: str | None
    uri: str | None
    status_code: int | None
    content_type: str | None
    content_length: int | None
    user_agent: str | None
    body_base64: str = ""
    body_ascii_preview: str = ""
    body_truncated: bool = False


class FtpMessage(BaseModel):
    frame_number: int
    timestamp: datetime
    stream_id: int | None = None
    kind: Literal["request", "response"]
    command: str | None
    argument: str | None
    response_code: int | None
    response_text: str | None


class StreamChunk(BaseModel):
    direction: Literal["a_to_b", "b_to_a"]
    offset: int = Field(ge=0)
    length: int = Field(ge=0)


class TcpStream(BaseModel):
    stream_id: int = Field(ge=0)
    endpoint_a: str
    endpoint_b: str
    packet_count: int = Field(ge=0)
    wire_bytes: int = Field(ge=0)
    first_seen: datetime
    last_seen: datetime
    application_protocols: list[str]
    syn_seen: bool
    fin_seen: bool
    reset_seen: bool
    reconstructed_bytes: int = Field(ge=0)
    reconstructed_base64: str
    ascii_preview: str
    chunks: list[StreamChunk]
    reconstruction_truncated: bool


class UdpStream(BaseModel):
    stream_id: int = Field(ge=0)
    endpoint_a: str
    endpoint_b: str
    packet_count: int = Field(ge=0)
    wire_bytes: int = Field(ge=0)
    first_seen: datetime
    last_seen: datetime
    application_protocols: list[str]
    reconstructed_bytes: int = Field(ge=0)
    reconstructed_base64: str
    ascii_preview: str
    chunks: list[StreamChunk]
    reconstruction_truncated: bool


class TransferredFile(BaseModel):
    artifact_id: str
    parent_artifact_id: str
    protocol: Literal["http", "ftp-data"]
    source_name: str
    size: int = Field(ge=0)
    sha256: str
    content_base64: str
    content_truncated: bool
    retained: Literal[False] = False


class PlaintextCredential(BaseModel):
    protocol: str
    username: str | None
    secret: str
    frame_number: int | None
    stream_id: int | None
    source: str
    confidence: float = Field(ge=0.0, le=1.0)


class InterestingPort(BaseModel):
    port: int = Field(ge=0, le=65535)
    transport: Literal["tcp", "udp"]
    service: str
    packet_count: int = Field(ge=0)
    reason: str


class NetworkFlagCandidate(BaseModel):
    value: str
    matched_pattern: str
    source: str
    stream_id: int | None
    offset: int = Field(ge=0)
    confidence: float = Field(ge=0.0, le=1.0)
    context: str
    frame_numbers: list[int] = Field(default_factory=list)
    decoding_steps: list[str] = Field(default_factory=list)
    artifact_id: str | None = None
    packet_number: int | None = Field(default=None, ge=1)
    state: Literal["candidate"] = "candidate"


class NetworkInsight(BaseModel):
    title: str
    category: Literal["decoded-payload", "covert-channel", "broadcast", "correlation"]
    value: str
    source: str
    frame_numbers: list[int] = Field(default_factory=list)
    stream_id: int | None = Field(default=None, ge=0)
    confidence: float = Field(ge=0.0, le=1.0)
    decoding_steps: list[str] = Field(default_factory=list)
    metadata: dict[str, str | int | float | bool | None] = Field(default_factory=dict)


class SuspicionReason(BaseModel):
    category: str
    description: str
    score: float = Field(gt=0.0)
    evidence: dict[str, object] = Field(default_factory=dict)


class SuspicionScore(BaseModel):
    total: float = Field(ge=0.0, le=100.0)
    reasons: list[SuspicionReason] = Field(default_factory=list)


class InterestingFrame(BaseModel):
    frame_number: int = Field(ge=1)
    description: str


class InvestigationTarget(BaseModel):
    id: str
    target_type: Literal[
        "packet",
        "packet_group",
        "tcp_stream",
        "udp_stream",
        "conversation",
        "dns_group",
        "http_activity",
        "artifact",
        "wireless_activity",
        "unknown",
    ]
    title: str
    suspicion: SuspicionScore
    interpretation: str | None = None
    interpretation_confidence: float | None = Field(default=None, ge=0.0, le=1.0)
    protocol: str | None = None
    frame_numbers: list[int] = Field(default_factory=list)
    interesting_frames: list[InterestingFrame] = Field(default_factory=list)
    stream_id: int | None = Field(default=None, ge=0)
    endpoints: list[str] = Field(default_factory=list)
    hypotheses: list[str] = Field(default_factory=list)
    wireshark_filter: str | None = None
    recommended_actions: list[str] = Field(default_factory=list)
    related_findings: list[str] = Field(default_factory=list)
    related_artifacts: list[str] = Field(default_factory=list)
    related_flags: list[str] = Field(default_factory=list)
    categories: list[Literal[
        "streams",
        "packets",
        "dns",
        "http",
        "files",
        "credentials",
        "covert",
        "encoded",
        "wireless",
        "tls",
        "rare-traffic",
    ]] = Field(default_factory=list)
    first_seen: datetime | None = None
    last_seen: datetime | None = None


class NetworkInvestigationSummary(BaseModel):
    outcome: Literal["solved", "partially-solved", "investigation-targets"]
    message: str
    suspicious_targets: int = Field(ge=0)
    suspicious_streams: int = Field(ge=0)
    suspicious_packet_groups: int = Field(ge=0)
    suspicious_packets: int = Field(ge=0)
    suspicious_dns_groups: int = Field(ge=0)
    suspicious_artifacts: int = Field(ge=0)
    reliable_flag_candidates: int = Field(ge=0)


class TimelineEvent(BaseModel):
    timestamp: datetime
    event_type: str
    title: str
    description: str
    frame_number: int | None
    stream_id: int | None
    metadata: dict[str, str | int | float | bool | None]


class ToolExecutionSummary(BaseModel):
    operation: str
    tool: Literal["tshark"] = "tshark"
    returncode: int
    duration_ms: int = Field(ge=0)


class AnalysisStageTiming(BaseModel):
    stage: str
    label: str
    duration_ms: int = Field(ge=0)
    detail: str | None = None


class NetworkAnalysisProgress(BaseModel):
    progress_id: str
    status: Literal["uploading", "analyzing", "complete", "failed"]
    stage: str
    detail: str
    elapsed_ms: int = Field(ge=0)
    updated_at: datetime


class NetworkLimits(BaseModel):
    max_upload_bytes: int
    max_packets: int
    max_packet_records: int
    max_tcp_streams: int
    max_udp_streams: int
    max_stream_bytes: int
    max_exported_files: int
    max_exported_bytes: int
    max_application_records: int
    max_timeline_events: int
    max_conversations: int
    max_discovered_tcp_streams: int
    max_discovered_udp_streams: int
    max_credentials: int
    max_flags: int
    max_insights: int
    max_investigation_targets: int


class NetworkAnalysisResponse(BaseModel):
    analysis_id: str
    analyzer: str
    category: Literal["network"] = "network"
    capture: CaptureMetadata
    packets: list[PacketRecord]
    packet_records_truncated: bool
    endpoints: NetworkEndpoints
    protocol_hierarchy: list[ProtocolHierarchyNode]
    conversations: list[Conversation]
    dns: list[DnsRecord]
    http: list[HttpMessage]
    ftp: list[FtpMessage]
    tcp_streams: list[TcpStream]
    udp_streams: list[UdpStream]
    transferred_files: list[TransferredFile]
    plaintext_credentials: list[PlaintextCredential]
    interesting_ports: list[InterestingPort]
    insights: list[NetworkInsight]
    flags: list[NetworkFlagCandidate]
    investigation_summary: NetworkInvestigationSummary
    investigation_targets: list[InvestigationTarget]
    timeline: list[TimelineEvent]
    tool_executions: list[ToolExecutionSummary]
    stage_timings: list[AnalysisStageTiming]
    warnings: list[str]
    limits: NetworkLimits
