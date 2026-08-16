import { apiRequest } from './client.ts';

export interface Hashes {
  md5: string;
  sha1: string;
  sha256: string;
}

export interface EntropyResult {
  bits_per_byte: number;
  classification: 'very-low' | 'low' | 'normal' | 'high' | 'very-high';
  sample_size: number;
}

export interface ArchiveMember {
  path: string;
  size: number;
  compressed_size: number | null;
  kind: 'file' | 'directory' | 'symlink' | 'other';
  encrypted: boolean;
  extractable: boolean;
  skipped_reason: string | null;
  extracted_artifact_id: string | null;
}

export type ForensicSeverity = 'critical' | 'high' | 'medium' | 'low' | 'info';

export interface ForensicFinding {
  finding_id: string;
  severity: ForensicSeverity;
  title: string;
  reason: string;
  analyzer: 'metadata' | 'qr_barcode' | 'file';
  section: string;
  field: string | null;
  value: string | null;
}

export interface RecoveryStep {
  operation: string;
  tool: string;
  parameters: Record<string, string | number | boolean>;
}

export interface DecodeStep {
  transform: string;
  parameter: string | null;
  output: string;
}

export interface MetadataAnalysis {
  tool_available: boolean;
  tool: string;
  tool_version: string | null;
  summary: string;
  categories: Record<string, Array<{
    group: string; tag: string; key: string; category: string;
    value: unknown; display_value: string; importance: ForensicSeverity;
  }>>;
  notable: ForensicFinding[];
  decoded: Array<{
    field: string; original: string; detected_encoding: string; confidence: number;
    chain: DecodeStep[]; decoded: string; flags: string[];
  }>;
  timeline: Array<{ field: string; timestamp: string; normalized_timestamp: string | null; description: string }>;
  timestamp_anomalies: string[];
  gps: null | { latitude: number; longitude: number; altitude: number | null; timestamp: string | null; direction: string | null; location: string | null };
  embedded_objects: Array<{ tag: string; kind: string; description: string; byte_size: number | null; mime_type: string | null; data_base64: string | null }>;
  all_metadata: Array<{ group: string; tag: string; key: string; category: string; value: unknown; display_value: string; importance: ForensicSeverity }>;
  raw_exiftool: string;
  warnings: string[];
}

export interface QRBarcodeAnalysis {
  findings: Array<{
    finding_id: string; symbology: string; decoded_value: string; source: string;
    page: number | null; frame: number | null; timestamp_seconds: number | null;
    bounding_box: null | { x: number; y: number; width: number; height: number };
    decoder: string; confidence: 'high' | 'medium' | 'low'; recovery_method: string;
    provenance: RecoveryStep[];
    secondary_analysis: null | { detected_encodings: string[]; chain: DecodeStep[]; decoded: string | null; flags: string[] };
  }>;
  attempts: Array<{ source: string; variant: string; decoder: string; success: boolean; detail: string }>;
  variants: Array<{ variant_id: string; label: string; source: string; width: number; height: number; mime_type: 'image/png'; image_base64: string; transformations: RecoveryStep[]; best_candidate: boolean }>;
  structures: Array<{ source: string; finder_patterns: number | null; estimated_version: number | null; estimated_modules: string | null; orientation_degrees: number | null; decode_failed: boolean }>;
  decoders_available: string[];
  decoders_unavailable: string[];
  scanned_sources: string[];
  warnings: string[];
}

export interface ForensicsTriageResponse {
  analysis_id: string;
  artifact_id: string;
  analyzer: string;
  category: 'forensics';
  original_filename: string;
  size: number;
  magic: {
    detected_type: string;
    mime_type: string;
    description: string;
    signature: string | null;
    confidence: number;
  };
  hashes: Hashes;
  metadata: Array<{ key: string; value: string | number | boolean }>;
  metadata_analysis: MetadataAnalysis;
  qr_barcode: QRBarcodeAnalysis;
  notable_findings: ForensicFinding[];
  strings: Array<{ offset: number; value: string; encoding: 'ascii' | 'utf-16le' | 'utf-16be' }>;
  strings_truncated: boolean;
  entropy: EntropyResult;
  signatures: Array<{ name: string; mime_type: string; offset: number; signature: string; is_embedded: boolean }>;
  extension: {
    provided_extension: string | null;
    expected_extensions: string[];
    mismatch: boolean;
    reason: string;
  };
  embedded_files: Array<{
    name: string;
    detected_type: string;
    mime_type: string;
    offset: number;
    estimated_size: number | null;
    extracted_artifact_id: string | null;
  }>;
  archives: Array<{
    format: string;
    member_count: number;
    total_uncompressed_size: number;
    members_truncated: boolean;
    members: ArchiveMember[];
  }>;
  flags: Array<{
    value: string;
    matched_pattern: string;
    source: string;
    offset: number;
    confidence: number;
    context: string;
    state: 'candidate';
  }>;
  extracted_artifacts: Array<{
    artifact_id: string;
    parent_artifact_id: string;
    source_path: string;
    extraction_method: 'archive-member' | 'embedded-carve';
    size: number;
    detected_type: string;
    mime_type: string;
    hashes: Hashes;
    entropy: EntropyResult;
    retained: false;
  }>;
  warnings: string[];
  limits: {
    max_upload_bytes: number;
    max_strings: number;
    max_archive_members: number;
    max_extracted_bytes: number;
    max_compression_ratio: number;
  };
}

export function triageForensicsFile(
  file: File,
  signal?: AbortSignal,
  customFlagRegex?: string,
): Promise<ForensicsTriageResponse> {
  const body = new FormData();
  body.append('file', file, file.name);
  if (customFlagRegex) body.append('custom_flag_regex', customFlagRegex);
  return apiRequest<ForensicsTriageResponse>('/forensics/triage', {
    method: 'POST',
    body,
    signal,
  });
}
