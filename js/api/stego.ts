import { apiRequest } from './client.ts';
import type { EntropyResult, Hashes } from './forensics.ts';

export interface ExtractionMethod {
  notation: string;
  bits_per_channel: number;
  channels: string;
  bit_plane: number | null;
  bit_order: 'lsb' | 'msb';
  byte_bit_order: 'msb-first' | 'lsb-first';
  traversal: 'xy' | 'yx' | 'reverse-xy' | 'reverse-yx';
}

export interface StegoFinding {
  finding_id: string;
  title: string;
  source: 'pixel_steganography' | 'metadata' | 'png_structure' | 'trailing_data' | 'embedded_file' | 'qr_barcode' | 'external_tool';
  severity: 'critical' | 'high' | 'medium' | 'low' | 'noise';
  confidence: number;
  score: number;
  detected_type: string;
  explanation: string;
  method: ExtractionMethod | null;
  offset: number;
  length: number;
  entropy: number;
  printable_ratio: number;
  utf8_valid: boolean;
  null_ratio: number;
  preview_text: string;
  preview_hex: string;
  data_base64: string;
  data_truncated: boolean;
  signatures: Array<{ detected_type: string; mime_type: string; offset: number }>;
  encodings: Array<{ name: string; confidence: number; evidence: string }>;
  flags: StegoAnalysisResponse['flags'];
  analysis_chain: Array<{ operation: string; detail: string }>;
  equivalent_methods: string[];
}

export interface StegoAnalysisResponse {
  analysis_id: string;
  artifact_id: string;
  analyzer: string;
  category: 'steganography';
  original_filename: string;
  size: number;
  hashes: Hashes;
  image: {
    format: string;
    mode: string;
    width: number;
    height: number;
    frames: number;
    animated: boolean;
    has_alpha: boolean;
  };
  metadata: Array<{
    key: string;
    value: string | number | boolean;
    source: 'image' | 'exif' | 'xmp' | 'png-text' | 'icc' | 'container';
  }>;
  png_chunks: Array<{
    index: number;
    chunk_type: string;
    offset: number;
    data_length: number;
    critical: boolean;
    crc_expected: string;
    crc_actual: string;
    crc_valid: boolean;
    known: boolean;
    suspicious: boolean;
    explanation: string | null;
    text_preview: string | null;
  }>;
  png_chunks_truncated: boolean;
  jpeg_segments: Array<{
    index: number;
    marker: string;
    name: string;
    offset: number;
    segment_length: number;
  }>;
  jpeg_segments_truncated: boolean;
  trailing_bytes: {
    present: boolean;
    offset: number;
    size: number;
    detected_type: string | null;
    preview_hex: string;
  };
  channels: Array<{
    channel: string;
    minimum: number;
    maximum: number;
    mean: number;
    standard_deviation: number;
    entropy: number;
    lsb_zeros: number;
    lsb_ones: number;
    lsb_one_ratio: number;
  }>;
  bit_planes: Array<{
    channel: string;
    bit: number;
    zeros: number;
    ones: number;
    one_ratio: number;
    entropy: number;
    biased: boolean;
  }>;
  lsb: Array<{
    stream: string;
    channel_order: string;
    bits_per_sample: 1;
    available_bits: number;
    extracted_bytes: number;
    truncated: boolean;
    printable_ratio: number;
    entropy: EntropyResult;
    preview_ascii: string;
    preview_hex: string;
    signatures: Array<{ detected_type: string; mime_type: string; offset: number }>;
    flags: Array<{
      value: string;
      matched_pattern: string;
      source: string;
      offset: number;
      confidence: number;
      context: string;
      state: 'candidate';
    }>;
    suspicious: boolean;
  }>;
  entropy: {
    file: EntropyResult;
    pixel_data: EntropyResult;
    channels: Record<string, EntropyResult>;
  };
  signatures: Array<{
    detected_type: string;
    mime_type: string;
    offset: number;
    source: 'embedded-signature' | 'trailing-bytes';
    estimated_size: number | null;
    carved_artifact_id: string | null;
  }>;
  carved_artifacts: Array<{
    artifact_id: string;
    parent_artifact_id: string;
    source_offset: number;
    source: 'embedded-signature' | 'trailing-bytes';
    detected_type: string;
    mime_type: string;
    size: number;
    hashes: Hashes;
    entropy: EntropyResult;
    retained: false;
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
  findings: StegoFinding[];
  bit_plane_visuals: Array<{
    channel: string;
    bit: number;
    label: string;
    width: number;
    height: number;
    png_base64: string;
    one_ratio: number;
    qr_payloads: string[];
  }>;
  barcodes: Array<{
    symbology: string;
    payload: string;
    source: string;
    method: ExtractionMethod | null;
  }>;
  pixel_scan: {
    mode: 'quick' | 'deep';
    candidates_evaluated: number;
    unique_streams: number;
    retained_findings: number;
    noise_hidden: number;
    elapsed_ms: number;
    truncated: boolean;
    stages: string[];
  } | null;
  external_validation: Array<{
    tool: string;
    available: boolean;
    executed: boolean;
    duration_ms: number | null;
    findings: string[];
    error: string | null;
  }>;
  noise_included: boolean;
  warnings: string[];
  limits: {
    max_upload_bytes: number;
    max_pixels: number;
    max_png_chunks: number;
    max_jpeg_segments: number;
    max_lsb_bytes: number;
    max_signature_matches: number;
    max_carved_bytes: number;
    max_candidates: number;
    max_candidate_bytes: number;
    max_analysis_seconds: number;
  };
}

export function analyzeStegoImage(
  file: File,
  showAll = false,
  deepScan = false,
  signal?: AbortSignal,
): Promise<StegoAnalysisResponse> {
  const body = new FormData();
  body.append('file', file, file.name);
  body.append('show_all', String(showAll));
  body.append('deep_scan', String(deepScan));
  return apiRequest<StegoAnalysisResponse>('/stego/analyze', {
    method: 'POST',
    body,
    signal,
  });
}
