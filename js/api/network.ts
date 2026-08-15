import { apiRequest } from './client.ts';

export interface CaptureMetadata {
  artifact_id: string;
  original_filename: string;
  format: 'pcap' | 'pcapng';
  size: number;
  sha256: string;
  packet_count: number;
  analyzed_packet_count: number;
  captured_bytes: number;
  wire_bytes: number;
  first_seen: string | null;
  last_seen: string | null;
  duration_seconds: number;
  unique_hosts: number;
  packet_limit_reached: boolean;
}

export interface PacketRecord {
  number: number;
  timestamp: string;
  captured_length: number;
  wire_length: number;
  source: string | null;
  destination: string | null;
  source_port: number | null;
  destination_port: number | null;
  transport: string | null;
  displayed_protocol: string;
  protocol_stack: string[];
  tcp_stream: number | null;
  info: string;
}

export interface ProtocolHierarchyNode {
  protocol: string;
  packets: number;
  percentage: number;
  children: ProtocolHierarchyNode[];
}

export interface Conversation {
  transport: string;
  endpoint_a: string;
  endpoint_b: string;
  packets_a_to_b: number;
  packets_b_to_a: number;
  bytes_a_to_b: number;
  bytes_b_to_a: number;
  first_seen: string;
  last_seen: string;
  application_protocols: string[];
}

export interface DnsRecord {
  frame_number: number;
  timestamp: string;
  stream_id: number | null;
  kind: 'query' | 'response';
  transaction_id: string | null;
  name: string | null;
  query_type: string | null;
  answers: string[];
}

export interface HttpMessage {
  frame_number: number;
  timestamp: string;
  stream_id: number | null;
  kind: 'request' | 'response';
  method: string | null;
  host: string | null;
  uri: string | null;
  status_code: number | null;
  content_type: string | null;
  content_length: number | null;
  user_agent: string | null;
}

export interface FtpMessage {
  frame_number: number;
  timestamp: string;
  stream_id: number | null;
  kind: 'request' | 'response';
  command: string | null;
  argument: string | null;
  response_code: number | null;
  response_text: string | null;
}

export interface TcpStream {
  stream_id: number;
  endpoint_a: string;
  endpoint_b: string;
  packet_count: number;
  wire_bytes: number;
  first_seen: string;
  last_seen: string;
  application_protocols: string[];
  syn_seen: boolean;
  fin_seen: boolean;
  reset_seen: boolean;
  reconstructed_bytes: number;
  reconstructed_base64: string;
  ascii_preview: string;
  chunks: Array<{ direction: 'a_to_b' | 'b_to_a'; offset: number; length: number }>;
  reconstruction_truncated: boolean;
}

export interface TransferredFile {
  artifact_id: string;
  parent_artifact_id: string;
  protocol: 'http' | 'ftp-data';
  source_name: string;
  size: number;
  sha256: string;
  content_base64: string;
  content_truncated: boolean;
  retained: false;
}

export interface PlaintextCredential {
  protocol: string;
  username: string | null;
  secret: string;
  frame_number: number | null;
  stream_id: number | null;
  source: string;
  confidence: number;
}

export interface InterestingPort {
  port: number;
  transport: 'tcp' | 'udp';
  service: string;
  packet_count: number;
  reason: string;
}

export interface NetworkFlagCandidate {
  value: string;
  matched_pattern: string;
  source: string;
  stream_id: number | null;
  offset: number;
  confidence: number;
  context: string;
  state: 'candidate';
}

export interface TimelineEvent {
  timestamp: string;
  event_type: string;
  title: string;
  description: string;
  frame_number: number | null;
  stream_id: number | null;
  metadata: Record<string, string | number | boolean | null>;
}

export interface NetworkAnalysisResponse {
  analysis_id: string;
  analyzer: string;
  category: 'network';
  capture: CaptureMetadata;
  packets: PacketRecord[];
  packet_records_truncated: boolean;
  protocol_hierarchy: ProtocolHierarchyNode[];
  conversations: Conversation[];
  dns: DnsRecord[];
  http: HttpMessage[];
  ftp: FtpMessage[];
  tcp_streams: TcpStream[];
  transferred_files: TransferredFile[];
  plaintext_credentials: PlaintextCredential[];
  interesting_ports: InterestingPort[];
  flags: NetworkFlagCandidate[];
  timeline: TimelineEvent[];
  tool_executions: Array<{
    operation: string;
    tool: 'tshark';
    returncode: number;
    duration_ms: number;
  }>;
  warnings: string[];
  limits: Record<string, number>;
}

export function analyzePcapFile(
  file: File,
  signal?: AbortSignal,
): Promise<NetworkAnalysisResponse> {
  const body = new FormData();
  body.append('file', file, file.name);
  return apiRequest<NetworkAnalysisResponse>('/network/analyze', {
    method: 'POST',
    body,
    signal,
  });
}
