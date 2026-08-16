import { apiRequest } from './client.ts';

export type TargetScope = 'ctf' | 'lab' | 'owned';
export type FindingSeverity = 'critical' | 'high' | 'medium' | 'low' | 'info';

export interface HeaderRecord { name: string; value: string }
export interface EndpointRecord {
  url: string; path: string; method: string; parameters: string[]; sources: string[];
  priority: number; reason: string;
}
export interface WebFlagCandidate {
  value: string; pattern: string; source: string; location: string; context: string;
  confidence: number; source_type: string; url: string; authenticated: boolean; state: 'candidate';
}
export interface NotableFinding {
  id: string; score: number; severity: FindingSeverity; title: string; evidence: string[];
  location: string; why_it_matters: string; suggested_investigation: string;
  confidence: number; sources: string[]; url: string; source_type: string;
  context: string; authenticated: boolean;
}
export interface AttackSurfaceRecord {
  parameter: string; endpoint: string; method: string;
  location: 'query' | 'form' | 'javascript' | 'path'; input_type: string | null;
  potential_category: string;
}
export interface RawEvidenceRecord {
  kind: string; url: string; status_code: number | null; headers: HeaderRecord[];
  body_preview: string; truncated: boolean; authenticated: boolean;
}

export interface WebAnalysisResponse {
  analysis_id: string;
  analyzer: string;
  category: 'web';
  target_scope: TargetScope;
  exchange: {
    url: string; method: string; status_code: number; reason_phrase: string; elapsed_ms: number;
    request_headers: HeaderRecord[]; response_headers: HeaderRecord[]; content_type: string | null;
    body_bytes: number; body_truncated: boolean; redirect_chain: string[];
  };
  target_summary: {
    url: string; final_url: string; server: string | null; technologies: string[];
    pages_analyzed: number; endpoints_discovered: number; javascript_files_analyzed: number;
  };
  flag_status: 'found' | 'possible_lead' | 'not_found';
  flags: WebFlagCandidate[];
  notable_findings: NotableFinding[];
  endpoints: EndpointRecord[];
  attack_surface: AttackSurfaceRecord[];
  forms: Array<{
    page_url: string; action: string; method: string; enctype: string | null;
    fields: Array<{ name: string; input_type: string; value: string | null }>;
  }>;
  pages: Array<{ url: string; status_code: number; content_type: string | null; depth: number; source: string; parent_url: string | null }>;
  recon_tree: Array<{ url: string; parent_url: string | null; source: string; depth: number }>;
  raw_evidence: RawEvidenceRecord[];
  warnings: string[];
  documents: Array<{ kind: string; url: string; status_code: number | null; content_type: string | null; size: number; truncated: boolean; error: string | null }>;
  technologies: Array<{ name: string; version: string | null; evidence: string[]; confidence: number }>;
  cookies: Array<{ name: string; value: string; source: string; url: string; authenticated: boolean; issues: string[] }>;
  limits: Record<string, number>;
}

export interface WebAnalysisInput {
  url: string;
  target_scope: TargetScope;
  authorization_confirmed: true;
  method: 'GET';
  headers: Record<string, string>;
  cookies: Record<string, string>;
  fetch_robots: boolean;
  fetch_sitemap: boolean;
  fetch_javascript: boolean;
  source_map_discovery: boolean;
  crawl_same_origin: boolean;
  directory_discovery: boolean;
  api_discovery: boolean;
  sensitive_file_checks: boolean;
  follow_redirects: boolean;
  scan_depth: number;
  max_pages: number;
  authenticated_url: string | null;
  timeout_ms: number;
  compare_without_auth: boolean;
}

export function analyzeWebTarget(input: WebAnalysisInput, signal?: AbortSignal): Promise<WebAnalysisResponse> {
  return apiRequest<WebAnalysisResponse>('/web/analyze', {
    method: 'POST',
    body: JSON.stringify(input),
    signal,
  });
}
