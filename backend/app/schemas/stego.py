from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field

from app.schemas.forensics import EntropyResult, Hashes


class ImageMetadataEntry(BaseModel):
    key: str
    value: str | int | float | bool
    source: Literal["image", "exif", "png-text", "container"]


class ImageSummary(BaseModel):
    format: Literal["PNG", "JPEG"]
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
    warnings: list[str]
    limits: StegoLimits
