export interface SymmetricFinding { title: string; severity: 'critical' | 'high' | 'medium' | 'low' | 'info'; confidence: number; description: string; }
export interface SymmetricAnalyzeResponse { analyzer: 'symmetric_analyzer'; category: 'crypto'; findings: SymmetricFinding[]; block_size_detected: number | null; }

export interface StreamFinding { title: string; severity: 'critical' | 'high' | 'medium' | 'low' | 'info'; confidence: number; description: string; }
export interface StreamAnalyzeResponse { analyzer: 'stream_analyzer'; category: 'crypto'; findings: StreamFinding[]; estimated_xor_key_lengths: number[]; recovered_keystream: string | null; }

export interface HashFinding { title: string; severity: 'critical' | 'high' | 'medium' | 'low' | 'info'; confidence: number; description: string; }
export interface HashAnalyzeResponse { analyzer: 'hash_analyzer'; category: 'crypto'; findings: HashFinding[]; cracked_plaintext: string | null; algorithm: string | null; }

export interface CustomFinding { title: string; severity: 'critical' | 'high' | 'medium' | 'low' | 'info'; confidence: number; description: string; }
export interface CustomAnalyzeResponse { analyzer: 'custom_analyzer'; category: 'crypto'; findings: CustomFinding[]; extracted_constants: Record<string, string>; proposed_solver: string | null; }

export function analyzeSymmetric(ciphertext: string, signal?: AbortSignal): Promise<SymmetricAnalyzeResponse> {
  return import('./client.ts').then(m => m.apiRequest<SymmetricAnalyzeResponse>('/crypto/analyze/symmetric', { method: 'POST', body: JSON.stringify({ ciphertext }), signal }));
}
export function analyzeStream(ciphertexts: string[], cribs: string[] = [], signal?: AbortSignal): Promise<StreamAnalyzeResponse> {
  return import('./client.ts').then(m => m.apiRequest<StreamAnalyzeResponse>('/crypto/analyze/stream', { method: 'POST', body: JSON.stringify({ ciphertexts, cribs }), signal }));
}
export function analyzeHash(hash_str: string, signal?: AbortSignal): Promise<HashAnalyzeResponse> {
  return import('./client.ts').then(m => m.apiRequest<HashAnalyzeResponse>('/crypto/analyze/hash', { method: 'POST', body: JSON.stringify({ hash_str }), signal }));
}
export function analyzeCustom(source_code: string, signal?: AbortSignal): Promise<CustomAnalyzeResponse> {
  return import('./client.ts').then(m => m.apiRequest<CustomAnalyzeResponse>('/crypto/analyze/custom', { method: 'POST', body: JSON.stringify({ source_code }), signal }));
}
