from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field

from app.schemas.forensics import EntropyResult, Hashes


class ImageMetadataEntry(BaseModel):
    key: str
    value: str | int | float | bool
    source: Literal["image", "exif", "xmp", "png-text", "icc", "container"]


class ImageSummary(BaseModel):
    format: str
    mode: str
    width: int = Field(ge=1)
    height: int = Field(ge=1)
    frames: int = Field(ge=1)
    animated: bool
    has_alpha: bool


class PngChunk(BaseModel):
    index: int = Field(ge=0)
    chunk_type: str
    offset: int = Field(ge=0)
    data_length: int = Field(ge=0)
    critical: bool
    crc_expected: str
    crc_actual: str
    crc_valid: bool
    known: bool = True
    suspicious: bool = False
    explanation: str | None = None
    text_preview: str | None = None


class JpegSegment(BaseModel):
    index: int = Field(ge=0)
    marker: str
    name: str
    offset: int = Field(ge=0)
    segment_length: int = Field(ge=0)


class TrailingBytes(BaseModel):
    present: bool
    offset: int = Field(ge=0)
    size: int = Field(ge=0)
    detected_type: str | None = None
    preview_hex: str


class ChannelInspection(BaseModel):
    channel: str
    minimum: int = Field(ge=0, le=255)
    maximum: int = Field(ge=0, le=255)
    mean: float = Field(ge=0.0, le=255.0)
    standard_deviation: float = Field(ge=0.0)
    entropy: float = Field(ge=0.0, le=8.0)
    lsb_zeros: int = Field(ge=0)
    lsb_ones: int = Field(ge=0)
    lsb_one_ratio: float = Field(ge=0.0, le=1.0)


class BitPlaneResult(BaseModel):
    channel: str
    bit: int = Field(ge=0, le=7)
    zeros: int = Field(ge=0)
    ones: int = Field(ge=0)
    one_ratio: float = Field(ge=0.0, le=1.0)
    entropy: float = Field(ge=0.0, le=1.0)
    biased: bool


class LsbSignature(BaseModel):
    detected_type: str
    mime_type: str
    offset: int = Field(ge=0)


class StegoFlagCandidate(BaseModel):
    value: str
    matched_pattern: str
    source: str
    offset: int = Field(ge=0)
    confidence: float = Field(ge=0.0, le=1.0)
    context: str
    state: Literal["candidate"] = "candidate"


class LsbAnalysis(BaseModel):
    stream: str
    channel_order: str
    bits_per_sample: Literal[1] = 1
    available_bits: int = Field(ge=0)
    extracted_bytes: int = Field(ge=0)
    truncated: bool
    printable_ratio: float = Field(ge=0.0, le=1.0)
    entropy: EntropyResult
    preview_ascii: str
    preview_hex: str
    signatures: list[LsbSignature]
    flags: list[StegoFlagCandidate]
    suspicious: bool


class EntropyAnalysis(BaseModel):
    file: EntropyResult
    pixel_data: EntropyResult
    channels: dict[str, EntropyResult]


class SignatureCandidate(BaseModel):
    detected_type: str
    mime_type: str
    offset: int = Field(ge=0)
    source: Literal["embedded-signature", "trailing-bytes"]
    estimated_size: int | None = Field(default=None, ge=0)
    carved_artifact_id: str | None = None


class CarvedArtifact(BaseModel):
    artifact_id: str
    parent_artifact_id: str
    source_offset: int = Field(ge=0)
    source: Literal["embedded-signature", "trailing-bytes"]
    detected_type: str
    mime_type: str
    size: int = Field(ge=0)
    hashes: Hashes
    entropy: EntropyResult
    retained: Literal[False] = False


class StegoLimits(BaseModel):
    max_upload_bytes: int = Field(ge=1)
    max_pixels: int = Field(ge=1)
    max_png_chunks: int = Field(ge=1)
    max_jpeg_segments: int = Field(ge=1)
    max_lsb_bytes: int = Field(ge=1)
    max_signature_matches: int = Field(ge=1)
    max_carved_bytes: int = Field(ge=1)
    max_candidates: int = Field(default=64, ge=1)
    max_candidate_bytes: int = Field(default=1, ge=1)
    max_analysis_seconds: float = Field(default=1.0, gt=0)


class ExtractionMethod(BaseModel):
    notation: str
    bits_per_channel: int = Field(ge=1, le=4)
    channels: str
    bit_plane: int | None = Field(default=None, ge=0, le=7)
    bit_order: Literal["lsb", "msb"]
    byte_bit_order: Literal["msb-first", "lsb-first"]
    traversal: Literal["xy", "yx", "reverse-xy", "reverse-yx"]


class AnalysisChainStep(BaseModel):
    operation: str
    detail: str


class CandidateSignature(BaseModel):
    detected_type: str
    mime_type: str
    offset: int = Field(ge=0)


class CandidateEncoding(BaseModel):
    name: str
    confidence: float = Field(ge=0.0, le=1.0)
    evidence: str


class StegoFinding(BaseModel):
    finding_id: str
    title: str
    source: Literal[
        "pixel_steganography", "metadata", "png_structure", "trailing_data",
        "embedded_file", "qr_barcode", "external_tool",
    ]
    severity: Literal["critical", "high", "medium", "low", "noise"]
    confidence: float = Field(ge=0.0, le=1.0)
    score: int = Field(ge=0, le=100)
    detected_type: str
    explanation: str
    method: ExtractionMethod | None = None
    offset: int = Field(default=0, ge=0)
    length: int = Field(ge=0)
    entropy: float = Field(ge=0.0, le=8.0)
    printable_ratio: float = Field(ge=0.0, le=1.0)
    utf8_valid: bool
    null_ratio: float = Field(ge=0.0, le=1.0)
    preview_text: str
    preview_hex: str
    data_base64: str
    data_truncated: bool
    signatures: list[CandidateSignature] = Field(default_factory=list)
    encodings: list[CandidateEncoding] = Field(default_factory=list)
    flags: list[StegoFlagCandidate] = Field(default_factory=list)
    analysis_chain: list[AnalysisChainStep] = Field(default_factory=list)
    equivalent_methods: list[str] = Field(default_factory=list)


class BitPlaneVisual(BaseModel):
    channel: str
    bit: int = Field(ge=0, le=7)
    label: str
    width: int = Field(ge=1)
    height: int = Field(ge=1)
    png_base64: str
    one_ratio: float = Field(ge=0.0, le=1.0)
    qr_payloads: list[str] = Field(default_factory=list)


class BarcodeDetection(BaseModel):
    symbology: str
    payload: str
    source: str
    method: ExtractionMethod | None = None


class PixelScanSummary(BaseModel):
    mode: Literal["quick", "deep"]
    candidates_evaluated: int = Field(ge=0)
    unique_streams: int = Field(ge=0)
    retained_findings: int = Field(ge=0)
    noise_hidden: int = Field(ge=0)
    elapsed_ms: int = Field(ge=0)
    truncated: bool
    stages: list[str]


class ExternalValidation(BaseModel):
    tool: str
    available: bool
    executed: bool
    duration_ms: int | None = Field(default=None, ge=0)
    findings: list[str] = Field(default_factory=list)
    error: str | None = None


class StegoAnalysisResponse(BaseModel):
    analysis_id: str
    artifact_id: str
    analyzer: str
    category: Literal["steganography"] = "steganography"
    original_filename: str
    size: int = Field(ge=0)
    hashes: Hashes
    image: ImageSummary
    metadata: list[ImageMetadataEntry]
    png_chunks: list[PngChunk]
    png_chunks_truncated: bool
    jpeg_segments: list[JpegSegment]
    jpeg_segments_truncated: bool
    trailing_bytes: TrailingBytes
    channels: list[ChannelInspection]
    bit_planes: list[BitPlaneResult]
    lsb: list[LsbAnalysis]
    entropy: EntropyAnalysis
    signatures: list[SignatureCandidate]
    carved_artifacts: list[CarvedArtifact]
    flags: list[StegoFlagCandidate]
    findings: list[StegoFinding] = Field(default_factory=list)
    bit_plane_visuals: list[BitPlaneVisual] = Field(default_factory=list)
    barcodes: list[BarcodeDetection] = Field(default_factory=list)
    pixel_scan: PixelScanSummary | None = None
    external_validation: list[ExternalValidation] = Field(default_factory=list)
    noise_included: bool = False
    warnings: list[str]
    limits: StegoLimits
