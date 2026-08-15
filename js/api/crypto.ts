import { apiRequest } from './client.ts';

export interface TransformationStep {
  transform: string;
  parameter: string | null;
}

export interface EncodingDetection {
  name: string;
  confidence: number;
  evidence: string;
}

export interface FlagCandidate {
  value: string;
  matched_pattern: string;
  source: 'request.input';
  offset: number;
  confidence: number;
  context: string;
  chain: TransformationStep[];
  state: 'candidate';
}

export interface DecodingCandidate {
  output: string;
  output_format: 'utf-8' | 'hex';
  output_bytes: number;
  output_truncated: boolean;
  chain: TransformationStep[];
  score: number;
  score_breakdown: {
    printable: number;
    utf8: number;
    language: number;
    structure: number;
    flag_bonus: number;
    entropy: number;
    depth_penalty: number;
    syntax_bonus: number;
  };
  flags: FlagCandidate[];
}

export interface DecodeResponse {
  analyzer: string;
  category: 'crypto';
  detected_encodings: EncodingDetection[];
  results: DecodingCandidate[];
  flags: FlagCandidate[];
  search: {
    explored_states: number;
    elapsed_ms: number;
    max_depth_reached: number;
    truncated: boolean;
  };
}

export function decodeCrypto(input: string, signal?: AbortSignal): Promise<DecodeResponse> {
  return apiRequest<DecodeResponse>('/crypto/decode', {
    method: 'POST',
    body: JSON.stringify({ input, max_depth: 4, max_results: 10 }),
    signal,
  });
}
