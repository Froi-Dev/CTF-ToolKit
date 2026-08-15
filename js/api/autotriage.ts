import { apiRequest } from './client.ts';
import type { ForensicsTriageResponse } from './forensics.ts';
import type { NetworkAnalysisResponse } from './network.ts';
import type { StegoAnalysisResponse } from './stego.ts';

export type AutoTriageStatus = 'completed' | 'skipped' | 'unavailable' | 'failed';

export interface AutoTriageResponse {
  analysis_id: string;
  artifact_id: string;
  analyzer: 'auto_triage';
  category: 'auto-triage';
  original_filename: string;
  size: number;
  detected_type: string;
  mime_type: string;
  duration_ms: number;
  analyzer_runs: Array<{
    analyzer: string;
    category: 'forensics' | 'steganography' | 'network';
    status: AutoTriageStatus;
    duration_ms: number;
    message: string;
  }>;
  capabilities: Array<{
    key: string;
    label: string;
    analyzer: string;
    status: AutoTriageStatus;
    result_count: number;
    message: string;
  }>;
  forensics: ForensicsTriageResponse;
  steganography: StegoAnalysisResponse | null;
  network: NetworkAnalysisResponse | null;
  warnings: string[];
}

export function autoTriageFile(file: File, signal?: AbortSignal): Promise<AutoTriageResponse> {
  const body = new FormData();
  body.append('file', file, file.name);
  return apiRequest<AutoTriageResponse>('/auto-triage/analyze', {
    method: 'POST',
    body,
    signal,
  });
}

