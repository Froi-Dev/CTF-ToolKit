import { apiRequest } from './client.ts';

export type TargetScope = 'ctf' | 'lab' | 'owned';

export interface HeaderRecord { name: string; value: string }
export interface HeaderAssessment { name: string; value: string | null; source: 'request' | 'response'; status: 'present' | 'missing' | 'informational' | 'warning'; note: string }
export interface CookieRecord { name: string; value: string; source: 'request' | 'response'; domain: string | null; path: string | null; secure: boolean; http_only: boolean; same_site: string | null; expires: string | null; issues: string[] }
export interface DiscoveryDocument { kind: 'robots' | 'sitemap' | 'javascript' | 'source-map'; url: string; status_code: number | null; content_type: string | null; size: number; truncated: boolean; error: string | null }
export interface EndpointRecord { url: string; path: string; method: string; parameters: string[]; sources: string[] }
export interface ParameterRecord { name: string; locations: Array<'query' | 'form' | 'javascript' | 'path'>; sources: string[] }
export interface TechnologyRecord { name: string; version: string | null; evidence: string[]; confidence: number }
export interface JwtRecord { source: string; token_preview: string; algorithm: string | null; token_type: string | null; header: Record<string, unknown>; payload: Record<string, unknown>; signature_present: boolean; expires_at: string | null; expired: boolean | null; issues: string[]; signature_verified: false }

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
  headers: HeaderAssessment[];
  cookies: CookieRecord[];
  documents: DiscoveryDocument[];
  robots_rules: string[];
  sitemap_urls: string[];
  comments: Array<{ source: string; line: number; text: string }>;
  scripts: Array<{ url: string | null; inline: boolean; status_code: number | null; size: number; source_maps: string[] }>;
  endpoints: EndpointRecord[];
  parameters: ParameterRecord[];
  technologies: TechnologyRecord[];
  authentication: {
    request_authorization_scheme: string | null;
    response_challenges: string[];
    login_forms: Array<{ action: string; method: string; username_fields: string[]; password_fields: string[] }>;
    session_cookie_names: string[];
    observations: string[];
  };
  jwts: JwtRecord[];
  comparison: {
    performed: boolean; baseline_status: number | null; comparison_status: number | null;
    baseline_bytes: number | null; comparison_bytes: number | null; body_similarity: number | null;
    differing_headers: string[]; authentication_effect: string | null; error: string | null;
  };
  warnings: string[];
  limits: Record<string, number>;
}

export interface WebAnalysisInput {
  url: string;
  target_scope: TargetScope;
  authorization_confirmed: true;
  method: 'GET' | 'HEAD';
  headers: Record<string, string>;
  cookies: Record<string, string>;
  fetch_robots: boolean;
  fetch_sitemap: boolean;
  fetch_javascript: boolean;
  compare_without_auth: boolean;
}

export function analyzeWebTarget(input: WebAnalysisInput, signal?: AbortSignal): Promise<WebAnalysisResponse> {
  return apiRequest<WebAnalysisResponse>('/web/analyze', {
    method: 'POST',
    body: JSON.stringify(input),
    signal,
  });
}

// ---------------------------------------------------------------------------
// Active Recon types
// ---------------------------------------------------------------------------

export interface FormInput { name: string; input_type: string; value: string | null }
export interface CrawledForm { action: string; method: string; inputs: FormInput[] }
export interface CrawledPage {
  url: string; status_code: number; content_type: string | null; title: string | null;
  size: number; depth: number; links: string[]; forms: CrawledForm[]; parameters: string[]; elapsed_ms: number;
}
export interface CrawlResult {
  pages: CrawledPage[]; total_pages: number; max_depth_reached: number;
  total_forms: number; total_links: number; elapsed_ms: number;
}

export interface DirBustEntry {
  path: string; url: string; status_code: number; content_type: string | null;
  size: number; redirect_url: string | null; elapsed_ms: number;
}
export interface DirBustResult {
  entries: DirBustEntry[]; total_tested: number; total_found: number;
  wordlist_used: string; extensions_used: string[]; elapsed_ms: number;
}

export interface ParamFuzzEntry {
  parameter: string; url: string; canary: string; reflected: boolean;
  reflection_context: string | null; response_status: number; response_size: number;
  baseline_similarity: number;
}
export interface ParamFuzzResult {
  entries: ParamFuzzEntry[]; total_tested: number; total_reflected: number; elapsed_ms: number;
}

export interface ConsoleEntry { level: string; text: string; timestamp: string | null }
export interface NetworkEntry { method: string; url: string; status_code: number | null; content_type: string | null; size: number; elapsed_ms: number }
export interface StorageEntry { storage_type: 'cookie' | 'localStorage' | 'sessionStorage'; key: string; value: string }
export interface BrowserCapture {
  url: string; final_url: string; title: string | null; dom_snapshot: string | null;
  console_log: ConsoleEntry[]; network_log: NetworkEntry[]; storage: StorageEntry[];
  screenshot_base64: string | null; errors: string[]; elapsed_ms: number;
}

export interface XssFinding {
  finding_type: 'reflected' | 'dom'; severity: 'high' | 'medium' | 'low' | 'info';
  parameter: string; url: string; canary: string; injection_context: string | null;
  evidence: string; dom_sink: string | null; suggestion: string;
}
export interface XssScanResult {
  findings: XssFinding[]; parameters_tested: number; total_reflected: number;
  total_dom: number; elapsed_ms: number;
}

export interface FlagMatch { pattern: string; value: string; source: string; url: string; context: string }
export interface FlagResult { matches: FlagMatch[]; patterns_used: string[] }

export interface ActiveReconResponse {
  scan_id: string; target_url: string; target_scope: TargetScope;
  status: 'completed' | 'failed' | 'stopped';
  crawl: CrawlResult | null; dirbust: DirBustResult | null;
  param_fuzz: ParamFuzzResult | null; browser: BrowserCapture | null;
  xss: XssScanResult | null; flags: FlagResult | null;
  warnings: string[]; elapsed_ms: number;
  started_at: string | null; completed_at: string | null;
}

export interface ActiveReconInput {
  url: string;
  target_scope: TargetScope;
  authorization_confirmed: true;
  active_testing_confirmed: true;
  enable_crawl: boolean;
  crawl_depth: number;
  crawl_max_pages: number;
  enable_dirbust: boolean;
  dirbust_wordlist: 'common' | 'medium' | 'small';
  dirbust_extensions: string[];
  dirbust_concurrency: number;
  dirbust_status_filter: number[];
  enable_param_fuzz: boolean;
  enable_browser: boolean;
  browser_timeout_ms: number;
  enable_xss: boolean;
  flag_patterns: string[];
  headers: Record<string, string>;
  cookies: Record<string, string>;
  timeout_ms: number;
  rate_limit_rps: number;
}

export function startActiveRecon(input: ActiveReconInput, signal?: AbortSignal): Promise<ActiveReconResponse> {
  return apiRequest<ActiveReconResponse>('/web/active-recon', {
    method: 'POST',
    body: JSON.stringify(input),
    signal,
  });
}

export function crawlTarget(input: {
  url: string; target_scope: TargetScope; authorization_confirmed: true; active_testing_confirmed: true;
  depth?: number; max_pages?: number; headers?: Record<string, string>; cookies?: Record<string, string>; timeout_ms?: number;
}, signal?: AbortSignal): Promise<CrawlResult> {
  return apiRequest<CrawlResult>('/web/crawl', {
    method: 'POST',
    body: JSON.stringify(input),
    signal,
  });
}

export function dirBustTarget(input: {
  url: string; target_scope: TargetScope; authorization_confirmed: true; active_testing_confirmed: true;
  wordlist?: string; extensions?: string[]; concurrency?: number; status_filter?: number[];
  headers?: Record<string, string>; cookies?: Record<string, string>; timeout_ms?: number; rate_limit_rps?: number;
}, signal?: AbortSignal): Promise<DirBustResult> {
  return apiRequest<DirBustResult>('/web/dirbust', {
    method: 'POST',
    body: JSON.stringify(input),
    signal,
  });
}

export function xssScanTarget(input: {
  url: string; target_scope: TargetScope; authorization_confirmed: true; active_testing_confirmed: true;
  headers?: Record<string, string>; cookies?: Record<string, string>; timeout_ms?: number; browser_timeout_ms?: number;
}, signal?: AbortSignal): Promise<XssScanResult> {
  return apiRequest<XssScanResult>('/web/xss-scan', {
    method: 'POST',
    body: JSON.stringify(input),
    signal,
  });
}

export function browserRender(input: {
  url: string; target_scope: TargetScope; authorization_confirmed: true;
  headers?: Record<string, string>; cookies?: Record<string, string>; timeout_ms?: number; flag_patterns?: string[];
}, signal?: AbortSignal): Promise<BrowserCapture> {
  return apiRequest<BrowserCapture>('/web/browser-render', {
    method: 'POST',
    body: JSON.stringify(input),
    signal,
  });
}
