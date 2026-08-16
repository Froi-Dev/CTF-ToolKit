import { apiRequest } from './client.ts';

export type ReverseSeverity = 'critical' | 'high' | 'medium' | 'low' | 'info';

export interface ReverseAnalysisResponse {
  analysis_id: string;
  artifact_id: string;
  analyzer: 'reverse_static';
  category: 'reversing';
  file: {
    name: string; size: number; hashes: { md5: string; sha256: string };
    detected_type: string; format: string; architecture: string | null;
    bits: number | null; endian: 'little' | 'big' | null; operating_system: string | null;
    compiler: string | null; entry_point: number | null; stripped: boolean | null;
    packed: boolean | null; extension_matches: boolean; extension_reason: string;
  };
  protections: Array<{ name: string; status: 'enabled' | 'disabled' | 'partial' | 'unknown'; value: string; significance: string; evidence: string }>;
  sections: Array<{ name: string; virtual_address: number; file_offset: number; size: number; permissions: string; entropy: number; suspicious: boolean; reason: string | null }>;
  strings: Array<{ offset: number; value: string; encoding: string; category: string; importance: ReverseSeverity; reason: string }>;
  strings_truncated: boolean;
  imports: Array<{ name: string; library: string | null; category: string; importance: ReverseSeverity; reason: string }>;
  exports: string[];
  functions: Array<{ name: string; address: number | null; likely_role: string; evidence: string[]; confidence: number }>;
  disassembly: Array<{ address: number; bytes: string; instruction: string; function: string | null }>;
  validation_leads: Array<{ kind: string; evidence: string; interpretation: string; next_step: string; confidence: number }>;
  transformations: string[];
  findings: Array<{ severity: ReverseSeverity; title: string; confidence: number; evidence: string; why_it_matters: string; recommendation: string; location: string | null }>;
  flags: Array<{ value: string; matched_pattern: string; source: string; offset: number; confidence: number; context: string; state: 'candidate' }>;
  likely_flag_locations: string[];
  recovered_values: Record<string, string>;
  dynamic_recommendations: Array<{ breakpoint: string; why: string; inspect: string; command: string | null }>;
  solving_path: string[];
  tools: Record<string, boolean>;
  warnings: string[];
  summary: string;
  limits: { max_upload_bytes: number; max_strings: number; max_disassembly_lines: number };
}

export function analyzeReverseArtifact(
  file: File,
  options: { customFlagPrefix?: string; signal?: AbortSignal } = {},
): Promise<ReverseAnalysisResponse> {
  const body = new FormData();
  body.append('file', file, file.name);
  if (options.customFlagPrefix?.trim()) body.append('custom_flag_prefix', options.customFlagPrefix.trim());
  return apiRequest<ReverseAnalysisResponse>('/reversing/analyze', { method: 'POST', body, signal: options.signal });
}
