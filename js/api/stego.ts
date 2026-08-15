import { apiRequest } from './client.ts';
import type { EntropyResult, Hashes } from './forensics.ts';

export interface StegoAnalysisResponse {
  analysis_id: string;
  artifact_id: string;
  analyzer: string;
  category: 'steganography';
  original_filename: string;
  size: number;
  hashes: Hashes;
  image: {
    format: 'PNG' | 'JPEG';
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
    source: 'image' | 'exif' | 'png-text' | 'container';
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
  warnings: string[];
  limits: {
    max_upload_bytes: number;
    max_pixels: number;
    max_png_chunks: number;
    max_jpeg_segments: number;
    max_lsb_bytes: number;
    max_signature_matches: number;
    max_carved_bytes: number;
  };
}

export function analyzeStegoImage(
  file: File,
  signal?: AbortSignal,
): Promise<StegoAnalysisResponse> {
  const body = new FormData();
  body.append('file', file, file.name);
  return apiRequest<StegoAnalysisResponse>('/stego/analyze', {
    method: 'POST',
    body,
    signal,
  });
}
