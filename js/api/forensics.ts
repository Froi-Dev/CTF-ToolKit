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
): Promise<ForensicsTriageResponse> {
  const body = new FormData();
  body.append('file', file, file.name);
  return apiRequest<ForensicsTriageResponse>('/forensics/triage', {
    method: 'POST',
    body,
    signal,
  });
}
