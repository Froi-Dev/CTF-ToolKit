import { apiRequest } from './client.ts';

export type AudioSeverity = 'critical' | 'high' | 'medium' | 'low' | 'info';

export interface AudioArtifact {
  artifact_id: string;
  filename: string;
  kind: 'spectrogram' | 'channel' | 'difference-channel' | 'reversed' | 'slowed' | 'sped-up' | 'lsb-extraction' | 'embedded-file' | 'waveform-image';
  mime_type: string;
  description: string;
  size: number;
  sha256: string;
  content_base64: string | null;
  truncated: boolean;
}

export interface AudioAnalysisResponse {
  analysis_id: string;
  analyzer: 'audio_forensics';
  category: 'forensics';
  file: {
    name: string; size: number; hashes: { md5: string; sha256: string };
    detected_type: string; mime_type: string; extension: string | null; extension_matches: boolean;
    container: string; codec: string; encoding: string; duration_seconds: number | null;
    sample_rate: number | null; bit_rate: number | null; bit_depth: number | null;
    channels: number | null; channel_layout: string | null;
  };
  metadata: Record<string, string>;
  strings: string[];
  riff_chunks: Array<{ chunk_id: string; offset: number; size: number; known: boolean; preview: string | null; malformed: boolean }>;
  waveform: null | { peak: number; rms: number; dc_offset: number; clipping_ratio: number; silence_ratio: number; zero_crossing_rate: number; analyzed_samples: number };
  channels: Array<{ channel: string; rms: number; peak: number; dc_offset: number; entropy: number; high_frequency_ratio: number }>;
  channel_correlation: number | null;
  spectrogram: null | { fft_size: number; hop_size: number; dynamic_range_db: number; maximum_frequency_hz: number; duration_seconds: number; frequency_band_energy: Record<string, number>; artifact_id: string | null };
  tones: {
    dtmf_sequence: string;
    dtmf_events: Array<{ symbol: string; start_seconds: number; end_seconds: number; confidence: number }>;
    morse_symbols: string | null; morse_text: string | null; morse_confidence: number | null;
    carrier_hz: number | null; ultrasonic_peak_hz: number | null; ultrasonic_energy_ratio: number;
  };
  lsb_candidates: Array<{ channel: string; bit_plane: number; bit_order: string; printable_ratio: number; entropy: number; recognized_type: string | null; preview: string | null; artifact_id: string | null }>;
  sstv: null | { detected: boolean; mode: string | null; confidence: number; header_offset_seconds: number | null };
  embedded_files: Array<{ offset: number; detected_type: string; size: number; artifact_id: string | null }>;
  flags: Array<{ value: string; confidence: number; source: string; extraction_method: string; offset: number | null; channel: string | null; bit_plane: number | null; state: 'candidate'; context: string | null }>;
  findings: Array<{ severity: AudioSeverity; title: string; confidence: number; description: string; location: string | null; method: string; recommendation: string | null; evidence: Record<string, unknown> }>;
  artifacts: AudioArtifact[];
  tools: Record<string, boolean>;
  errors: string[];
  recommendations: string[];
  summary: string;
  evidence_integrity: string;
  limits: Record<string, number>;
}

export interface RawPcmParameters {
  sampleRate: number;
  bitDepth: number;
  endianness: 'little' | 'big';
  channels: number;
  signed: boolean;
}

export function analyzeAudio(
  file: File,
  options: { raw?: RawPcmParameters; customFlagPrefix?: string; signal?: AbortSignal } = {},
): Promise<AudioAnalysisResponse> {
  const body = new FormData();
  body.append('file', file, file.name);
  if (options.raw) {
    body.append('raw_sample_rate', String(options.raw.sampleRate));
    body.append('raw_bit_depth', String(options.raw.bitDepth));
    body.append('raw_endianness', options.raw.endianness);
    body.append('raw_channels', String(options.raw.channels));
    body.append('raw_signed', String(options.raw.signed));
  }
  if (options.customFlagPrefix?.trim()) body.append('custom_flag_prefix', options.customFlagPrefix.trim());
  return apiRequest<AudioAnalysisResponse>('/forensics/audio/analyze', {
    method: 'POST', body, signal: options.signal,
  });
}

