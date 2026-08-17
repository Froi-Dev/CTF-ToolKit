from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, Field


Severity = Literal["critical", "high", "medium", "low", "info"]


class AudioHashes(BaseModel):
    md5: str
    sha256: str


class AudioFileSummary(BaseModel):
    name: str
    size: int = Field(ge=0)
    hashes: AudioHashes
    detected_type: str
    mime_type: str
    extension: str | None
    extension_matches: bool
    container: str
    codec: str
    encoding: str
    duration_seconds: float | None = Field(default=None, ge=0)
    sample_rate: int | None = Field(default=None, ge=1)
    bit_rate: int | None = Field(default=None, ge=0)
    bit_depth: int | None = Field(default=None, ge=1)
    channels: int | None = Field(default=None, ge=1)
    channel_layout: str | None = None


class AudioFinding(BaseModel):
    severity: Severity
    title: str
    confidence: float = Field(ge=0.0, le=1.0)
    description: str
    location: str | None = None
    method: str
    recommendation: str | None = None
    evidence: dict[str, Any] = Field(default_factory=dict)


class AudioFlagCandidate(BaseModel):
    value: str
    confidence: float = Field(ge=0.0, le=1.0)
    source: str
    extraction_method: str
    offset: int | None = Field(default=None, ge=0)
    channel: str | None = None
    bit_plane: int | None = Field(default=None, ge=0, le=7)
    state: Literal["candidate"] = "candidate"
    context: str | None = None


class AudioArtifact(BaseModel):
    artifact_id: str
    filename: str
    kind: Literal[
        "spectrogram",
        "channel",
        "difference-channel",
        "reversed",
        "slowed",
        "sped-up",
        "lsb-extraction",
        "embedded-file",
        "waveform-image",
    ]
    mime_type: str
    description: str
    size: int = Field(ge=0)
    sha256: str
    content_base64: str | None = None
    truncated: bool = False


class RiffChunk(BaseModel):
    chunk_id: str
    offset: int = Field(ge=0)
    size: int = Field(ge=0)
    known: bool
    preview: str | None = None
    malformed: bool = False


class WaveformMetrics(BaseModel):
    peak: float = Field(ge=0.0)
    rms: float = Field(ge=0.0)
    dc_offset: float
    clipping_ratio: float = Field(ge=0.0, le=1.0)
    silence_ratio: float = Field(ge=0.0, le=1.0)
    zero_crossing_rate: float = Field(ge=0.0, le=1.0)
    analyzed_samples: int = Field(ge=0)


class ChannelMetrics(BaseModel):
    channel: str
    rms: float = Field(ge=0.0)
    peak: float = Field(ge=0.0)
    dc_offset: float
    entropy: float = Field(ge=0.0, le=8.0)
    high_frequency_ratio: float = Field(ge=0.0, le=1.0)


class DtmfEvent(BaseModel):
    symbol: str
    start_seconds: float = Field(ge=0)
    end_seconds: float = Field(ge=0)
    confidence: float = Field(ge=0.0, le=1.0)


class ToneAnalysis(BaseModel):
    dtmf_sequence: str = ""
    dtmf_events: list[DtmfEvent] = Field(default_factory=list)
    morse_symbols: str | None = None
    morse_text: str | None = None
    morse_confidence: float | None = Field(default=None, ge=0.0, le=1.0)
    carrier_hz: float | None = Field(default=None, ge=0)
    ultrasonic_peak_hz: float | None = Field(default=None, ge=0)
    ultrasonic_energy_ratio: float = Field(default=0.0, ge=0.0, le=1.0)


class SpectrogramReport(BaseModel):
    fft_size: int = Field(ge=2)
    hop_size: int = Field(ge=1)
    dynamic_range_db: float = Field(gt=0)
    maximum_frequency_hz: float = Field(ge=0)
    duration_seconds: float = Field(ge=0)
    frequency_band_energy: dict[str, float] = Field(default_factory=dict)
    artifact_id: str | None = None


class LsbCandidate(BaseModel):
    channel: str
    bit_plane: int = Field(ge=0, le=7)
    bit_order: Literal["msb-first", "lsb-first"]
    printable_ratio: float = Field(ge=0.0, le=1.0)
    entropy: float = Field(ge=0.0, le=8.0)
    recognized_type: str | None = None
    preview: str | None = None
    artifact_id: str | None = None


class EmbeddedAudioFile(BaseModel):
    offset: int = Field(ge=0)
    detected_type: str
    size: int = Field(ge=0)
    artifact_id: str | None = None


class SstvDetection(BaseModel):
    detected: bool = False
    mode: str | None = None
    confidence: float = Field(default=0.0, ge=0.0, le=1.0)
    header_offset_seconds: float | None = Field(default=None, ge=0)


class AudioLimits(BaseModel):
    max_upload_bytes: int
    max_decoded_seconds: float
    max_analysis_samples: int
    max_generated_artifact_bytes: int
    max_lsb_bit_plane: int


class AudioAnalysisResponse(BaseModel):
    analysis_id: str
    analyzer: Literal["audio_forensics"] = "audio_forensics"
    category: Literal["forensics"] = "forensics"
    file: AudioFileSummary
    metadata: dict[str, str] = Field(default_factory=dict)
    strings: list[str] = Field(default_factory=list)
    riff_chunks: list[RiffChunk] = Field(default_factory=list)
    waveform: WaveformMetrics | None = None
    channels: list[ChannelMetrics] = Field(default_factory=list)
    channel_correlation: float | None = Field(default=None, ge=-1.0, le=1.0)
    spectrogram: SpectrogramReport | None = None
    tones: ToneAnalysis = Field(default_factory=ToneAnalysis)
    sstv: SstvDetection | None = None
    lsb_candidates: list[LsbCandidate] = Field(default_factory=list)
    embedded_files: list[EmbeddedAudioFile] = Field(default_factory=list)
    flags: list[AudioFlagCandidate] = Field(default_factory=list)
    findings: list[AudioFinding] = Field(default_factory=list)
    artifacts: list[AudioArtifact] = Field(default_factory=list)
    tools: dict[str, bool] = Field(default_factory=dict)
    errors: list[str] = Field(default_factory=list)
    recommendations: list[str] = Field(default_factory=list)
    summary: str
    evidence_integrity: str = (
        "Original evidence preserved. All analysis was performed against working copies."
    )
    limits: AudioLimits
