import { apiRequest } from './client.ts';

export interface TransformationStep { transform: string; parameter: string | null; }
export interface EncodingDetection { name: string; confidence: number; evidence: string; }
export interface ArtifactDetection {
  kind: string; label: string; mime: string; confidence: number;
  details: Record<string, string | number | boolean>; send_to_decryptor: boolean;
}
export interface ByteAnalysis { length: number; entropy: number; printable: number; utf8: boolean; magic: string | null; }
export interface FlagCandidate {
  value: string; matched_pattern: string; source: 'request.input' | 'decryptor.plaintext';
  offset: number; confidence: number; context: string; chain: TransformationStep[]; state: 'candidate';
}
export interface DecodingCandidate {
  output: string; output_format: 'utf-8' | 'hex'; output_base64: string; output_bytes: number;
  output_truncated: boolean; chain: TransformationStep[]; score: number;
  score_breakdown: {
    printable: number; utf8: number; language: number; structure: number; flag_bonus: number;
    entropy: number; depth_penalty: number; syntax_bonus: number;
  };
  flags: FlagCandidate[]; artifacts: ArtifactDetection[]; analysis: ByteAnalysis;
}
export interface DecodeResponse {
  analyzer: string; category: 'crypto'; detected_encodings: EncodingDetection[];
  results: DecodingCandidate[]; flags: FlagCandidate[];
  search: { explored_states: number; elapsed_ms: number; max_depth_reached: number; truncated: boolean; };
}

export type RecipeOperationName = 'base64' | 'base32' | 'base16' | 'base58' | 'base85' | 'ascii85'
  | 'hex' | 'binary' | 'octal' | 'decimal-ascii' | 'url' | 'html-entities'
  | 'unicode-escapes' | 'escaped-bytes' | 'rot13' | 'rot47' | 'caesar' | 'morse' | 'ascii' | 'utf-8'
  | 'utf-16' | 'xor' | 'gunzip';
export interface RecipeOperation { operation: RecipeOperationName; parameter: string | null; enabled: boolean; }
export interface RecipeIntermediate {
  index: number; operation: RecipeOperationName; parameter: string | null; output: string;
  output_format: 'utf-8' | 'hex'; output_base64: string; output_bytes: number;
  artifacts: ArtifactDetection[]; analysis: ByteAnalysis; flags: FlagCandidate[];
}
export interface RecipeResponse { analyzer: 'decoder_recipe'; category: 'crypto'; steps: RecipeIntermediate[]; result: RecipeIntermediate; }

export type ValueEncoding = 'auto' | 'text' | 'hex' | 'base64';
export type RsaPadding = 'pkcs1v15' | 'oaep-sha1' | 'oaep-sha256' | 'raw';
export interface CryptoMaterial { value: string; encoding: ValueEncoding; }
export interface RsaKeyInfo { key_type: 'private' | 'public'; format: 'PEM' | 'DER'; modulus_bits: number; public_exponent: number; }
export interface CryptoFinding { title: string; severity: 'critical' | 'high' | 'medium' | 'low' | 'info'; confidence: number; description: string; }
export interface CryptoAnalyzeResponse {
  analyzer: 'crypto_material_analyzer'; category: 'crypto'; key: RsaKeyInfo;
  key_artifacts: ArtifactDetection[]; ciphertext_artifacts: ArtifactDetection[];
  ciphertext_bytes: number | null; compatible: boolean | null;
  findings: CryptoFinding[]; recommended_actions: string[];
}
export interface RsaDecryptResponse {
  analyzer: 'rsa_decryptor'; category: 'crypto'; status: 'success'; key: RsaKeyInfo;
  padding: RsaPadding; ciphertext_bytes: number; plaintext: string; plaintext_format: 'utf-8' | 'hex';
  plaintext_base64: string; artifacts: ArtifactDetection[]; flags: FlagCandidate[];
}

export type OpenSslCipher = 'auto' | 'des-cbc' | 'des-ede3-cbc' | 'aes-128-cbc' | 'aes-192-cbc' | 'aes-256-cbc';
export type OpenSslKdf = 'auto' | 'evp-bytes-to-key' | 'pbkdf2';
export type OpenSslDigest = 'auto' | 'md5' | 'sha256';
export type PasswordEncoding = 'utf-8' | 'ascii' | 'hex' | 'base64';
export interface OpenSslAnalyzeResponse {
  analyzer: 'openssl_enc_analyzer'; category: 'crypto'; detected: boolean;
  format: 'openssl-enc' | 'raw'; header: 'Salted__' | null; salt_hex: string | null;
  total_bytes: number; encrypted_payload_bytes: number; structure_valid: boolean;
  password_supplied: boolean; password_status: 'provided' | 'not-supplied';
  status: 'ready-for-decryption' | 'password-required' | 'invalid-payload'; message: string;
}
export interface OpenSslDecryptCandidate {
  rank: number; cipher: Exclude<OpenSslCipher, 'auto'>; cipher_label: string;
  kdf: Exclude<OpenSslKdf, 'auto'>; digest: Exclude<OpenSslDigest, 'auto'>;
  iterations: number | null; key_hex: string; iv_hex: string; padding_valid: true;
  printable_percentage: number; utf8_valid: boolean; file_magic: string | null;
  confidence: 'LOW' | 'MEDIUM' | 'HIGH' | 'VERY HIGH'; score: number;
  plaintext: string; plaintext_format: 'utf-8' | 'hex'; plaintext_base64: string;
  artifacts: ArtifactDetection[]; flags: FlagCandidate[]; equivalent_command: string | null;
}
export interface OpenSslDecryptResponse {
  analyzer: 'openssl_enc_decryptor'; category: 'crypto'; status: 'success' | 'rejected';
  payload: OpenSslAnalyzeResponse; attempted_variants: number;
  candidates: OpenSslDecryptCandidate[]; rejection_reason: string | null; possible_causes: string[];
}

export function decodeCrypto(input: string, signal?: AbortSignal): Promise<DecodeResponse> {
  return apiRequest<DecodeResponse>('/crypto/decode', {
    method: 'POST', body: JSON.stringify({ input, max_depth: 5, max_results: 14 }), signal,
  });
}

export function runRecipe(input: string, operations: RecipeOperation[], signal?: AbortSignal): Promise<RecipeResponse> {
  return apiRequest<RecipeResponse>('/crypto/recipes/run', {
    method: 'POST', body: JSON.stringify({ input, operations }), signal,
  });
}

export function analyzeCrypto(
  key: CryptoMaterial, ciphertext: CryptoMaterial | null, signal?: AbortSignal,
): Promise<CryptoAnalyzeResponse> {
  return apiRequest<CryptoAnalyzeResponse>('/crypto/decrypt/analyze', {
    method: 'POST', body: JSON.stringify({ key, ciphertext }), signal,
  });
}

export function decryptRsa(
  privateKey: CryptoMaterial, ciphertext: CryptoMaterial, rsaPadding: RsaPadding, signal?: AbortSignal,
): Promise<RsaDecryptResponse> {
  return apiRequest<RsaDecryptResponse>('/crypto/decrypt/rsa', {
    method: 'POST', body: JSON.stringify({ private_key: privateKey, ciphertext, padding: rsaPadding }), signal,
  });
}

export function analyzeOpenSsl(
  encrypted: CryptoMaterial, password: string | null, signal?: AbortSignal,
): Promise<OpenSslAnalyzeResponse> {
  return apiRequest<OpenSslAnalyzeResponse>('/crypto/decrypt/openssl/analyze', {
    method: 'POST', body: JSON.stringify({ encrypted, password: password || null }), signal,
  });
}

export function decryptOpenSsl(
  request: {
    encrypted: CryptoMaterial; password: string; password_encoding: PasswordEncoding;
    cipher: OpenSslCipher; kdf: OpenSslKdf; digest: OpenSslDigest; iterations: number;
  },
  signal?: AbortSignal,
): Promise<OpenSslDecryptResponse> {
  return apiRequest<OpenSslDecryptResponse>('/crypto/decrypt/openssl', {
    method: 'POST', body: JSON.stringify(request), signal,
  });
}
