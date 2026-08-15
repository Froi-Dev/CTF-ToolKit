import { apiRequest } from './client.ts';

export interface CaptureMetadata {
  artifact_id: string;
  original_filename: string;
  format: 'pcap' | 'pcapng';
  size: number;
  sha256: string;
  byte_order: 'little' | 'big';
  timestamp_resolution: string | null;
  encapsulations: string[];
  snap_length: number | null;
  interfaces: Array<{
    interface_id: number;
    name: string | null;
    link_type: number;
    encapsulation: string;
    snap_length: number | null;
  }>;
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

export interface NetworkEndpoints {
  ipv4_hosts: string[];
  ipv6_hosts: string[];
  mac_addresses: string[];
  tcp_ports: number[];
  udp_ports: number[];
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
  udp_stream: number | null;
  payload_length: number;
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
  stream_ids: number[];
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
  body_base64: string;
  body_ascii_preview: string;
  body_truncated: boolean;
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

export interface UdpStream {
  stream_id: number;
  endpoint_a: string;
  endpoint_b: string;
  packet_count: number;
  wire_bytes: number;
  first_seen: string;
  last_seen: string;
  application_protocols: string[];
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
  frame_numbers: number[];
  decoding_steps: string[];
  artifact_id: string | null;
  packet_number: number | null;
  state: 'candidate';
}

export interface NetworkInsight {
  title: string;
  category: 'decoded-payload' | 'covert-channel' | 'broadcast' | 'correlation';
  value: string;
  source: string;
  frame_numbers: number[];
  stream_id: number | null;
  confidence: number;
  decoding_steps: string[];
  metadata: Record<string, string | number | boolean | null>;
}

export type InvestigationCategory =
  | 'streams' | 'packets' | 'dns' | 'http' | 'files' | 'credentials'
  | 'covert' | 'encoded' | 'wireless' | 'tls' | 'rare-traffic';

export interface SuspicionReason {
  category: string;
  description: string;
  score: number;
  evidence: Record<string, unknown>;
}

export interface InvestigationTarget {
  id: string;
  target_type: 'packet' | 'packet_group' | 'tcp_stream' | 'udp_stream' | 'conversation'
    | 'dns_group' | 'http_activity' | 'artifact' | 'wireless_activity' | 'unknown';
  title: string;
  suspicion: { total: number; reasons: SuspicionReason[] };
  interpretation: string | null;
  interpretation_confidence: number | null;
  protocol: string | null;
  frame_numbers: number[];
  interesting_frames: Array<{ frame_number: number; description: string }>;
  stream_id: number | null;
  endpoints: string[];
  hypotheses: string[];
  wireshark_filter: string | null;
  recommended_actions: string[];
  related_findings: string[];
  related_artifacts: string[];
  related_flags: string[];
  categories: InvestigationCategory[];
  first_seen: string | null;
  last_seen: string | null;
}

export interface NetworkInvestigationSummary {
  outcome: 'solved' | 'partially-solved' | 'investigation-targets';
  message: string;
  suspicious_targets: number;
  suspicious_streams: number;
  suspicious_packet_groups: number;
  suspicious_packets: number;
  suspicious_dns_groups: number;
  suspicious_artifacts: number;
  reliable_flag_candidates: number;
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

export interface AnalysisStageTiming {
  stage: string;
  label: string;
  duration_ms: number;
  detail: string | null;
}

export interface NetworkAnalysisProgress {
  progress_id: string;
  status: 'uploading' | 'analyzing' | 'complete' | 'failed';
  stage: string;
  detail: string;
  elapsed_ms: number;
  updated_at: string;
}

export interface NetworkAnalysisResponse {
  analysis_id: string;
  analyzer: string;
  category: 'network';
  capture: CaptureMetadata;
  packets: PacketRecord[];
  packet_records_truncated: boolean;
  endpoints: NetworkEndpoints;
  protocol_hierarchy: ProtocolHierarchyNode[];
  conversations: Conversation[];
  dns: DnsRecord[];
  http: HttpMessage[];
  ftp: FtpMessage[];
  tcp_streams: TcpStream[];
  udp_streams: UdpStream[];
  transferred_files: TransferredFile[];
  plaintext_credentials: PlaintextCredential[];
  interesting_ports: InterestingPort[];
  insights: NetworkInsight[];
  flags: NetworkFlagCandidate[];
  investigation_summary: NetworkInvestigationSummary;
  investigation_targets: InvestigationTarget[];
  timeline: TimelineEvent[];
  tool_executions: Array<{
    operation: string;
    tool: 'tshark';
    returncode: number;
    duration_ms: number;
  }>;
  stage_timings: AnalysisStageTiming[];
  warnings: string[];
  limits: Record<string, number>;
}

export function analyzePcapFile(
  file: File,
  signal?: AbortSignal,
  customFlagPrefix?: string,
  progressId?: string,
): Promise<NetworkAnalysisResponse> {
  const body = new FormData();
  body.append('file', file, file.name);
  if (customFlagPrefix?.trim()) body.append('custom_flag_prefix', customFlagPrefix.trim());
  if (progressId) body.append('progress_id', progressId);
  return apiRequest<NetworkAnalysisResponse>('/network/analyze', {
    method: 'POST',
    body,
    signal,
  });
}

export function getPcapAnalysisProgress(
  progressId: string,
  signal?: AbortSignal,
): Promise<NetworkAnalysisProgress> {
  return apiRequest<NetworkAnalysisProgress>(`/network/progress/${encodeURIComponent(progressId)}`, { signal });
}
