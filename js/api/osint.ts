import { apiRequest } from './client.ts';

export type OsintTargetType = 'auto' | 'domain' | 'ip' | 'username' | 'url';

export interface OsintProviderRun {
  name: string;
  status: 'success' | 'no_data' | 'unavailable' | 'error';
  source: string;
  record_count: number;
  duration_ms: number;
  error: string | null;
}

export interface OsintEntity {
  id: string;
  entity_type: 'domain' | 'ip' | 'username' | 'account' | 'asn' | 'organization' | 'certificate' | 'url';
  value: string;
  attributes: Record<string, unknown>;
  sources: string[];
}

export interface OsintRelationship {
  source_id: string;
  target_id: string;
  relationship: string;
  confidence: number;
  sources: string[];
}

export interface OsintInvestigationResponse {
  analysis_id: string;
  analyzer: string;
  category: 'osint';
  target: string;
  normalized_target: string;
  target_type: Exclude<OsintTargetType, 'auto'>;
  generated_at: string;
  providers: OsintProviderRun[];
  dns_records: Array<{ name: string; record_type: string; value: string; ttl: number | null; priority: number | null }>;
  whois: null | {
    server: string; registrar: string | null; organization: string | null; country: string | null;
    created_at: string | null; updated_at: string | null; expires_at: string | null;
    nameservers: string[]; statuses: string[];
  };
  rdap: Array<{ query: string; object_class: string | null; handle: string | null; name: string | null; country: string | null; registry: string | null; statuses: string[]; nameservers: string[]; events: Record<string, string> }>;
  ip_metadata: Array<{ address: string; reverse_dns: string | null; prefix: string | null; asns: number[]; registry: string | null; name: string | null; country: string | null }>;
  certificates: Array<{ certificate_id: string; common_name: string | null; dns_names: string[]; issuer: string | null; not_before: string | null; not_after: string | null }>;
  username_profiles: Array<{ platform: string; username: string; exists: boolean | null; profile_url: string; display_name: string | null; bio: string | null; attributes: Record<string, unknown> }>;
  web_metadata: null | { url: string; final_url: string; status_code: number; title: string | null; description: string | null; author: string | null; canonical_url: string | null; open_graph: Record<string, string>; json_ld_types: string[]; links: string[] };
  search_queries: Array<{ label: string; query: string; google_url: string }>;
  search_results: Array<{ title: string; url: string; snippet: string | null; display_link: string | null }>;
  entities: OsintEntity[];
  relationships: OsintRelationship[];
  warnings: string[];
}

export function investigateOsintTarget(
  target: string,
  targetType: OsintTargetType,
  includeSearchResults: boolean,
  signal?: AbortSignal,
): Promise<OsintInvestigationResponse> {
  return apiRequest<OsintInvestigationResponse>('/osint/investigate', {
    method: 'POST',
    body: JSON.stringify({
      target,
      target_type: targetType,
      include_search_results: includeSearchResults,
    }),
    signal,
  });
}
