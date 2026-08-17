from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, Field


class Hashes(BaseModel):
    md5: str
    sha1: str
    sha256: str


class MagicByteDetection(BaseModel):
    detected_type: str
    mime_type: str
    description: str
    signature: str | None = None
    confidence: float = Field(ge=0.0, le=1.0)


class MetadataEntry(BaseModel):
    key: str
    value: str | int | float | bool


Severity = Literal["critical", "high", "medium", "low", "info"]


class ForensicFinding(BaseModel):
    finding_id: str
    severity: Severity
    title: str
    reason: str
    analyzer: Literal["metadata", "qr_barcode", "file"]
    section: str
    field: str | None = None
    value: str | None = None


class DeepMetadataEntry(BaseModel):
    group: str
    tag: str
    key: str
    category: str
    value: Any
    display_value: str
    importance: Severity = "info"


class DecodeStep(BaseModel):
    transform: str
    parameter: str | None = None
    output: str


class DecodedMetadataValue(BaseModel):
    field: str
    original: str
    detected_encoding: str
    confidence: float = Field(ge=0.0, le=1.0)
    chain: list[DecodeStep]
    decoded: str
    flags: list[str] = Field(default_factory=list)


class MetadataTimelineEvent(BaseModel):
    field: str
    timestamp: str
    normalized_timestamp: str | None = None
    description: str


class GPSMetadata(BaseModel):
    latitude: float
    longitude: float
    altitude: float | None = None
    timestamp: str | None = None
    direction: str | None = None
    location: str | None = None


class EmbeddedMetadataObject(BaseModel):
    tag: str
    kind: str
    description: str
    byte_size: int | None = Field(default=None, ge=0)
    mime_type: str | None = None
    data_base64: str | None = None


class MetadataAnalysis(BaseModel):
    tool_available: bool
    tool: str = "ExifTool"
    tool_version: str | None = None
    summary: str
    categories: dict[str, list[DeepMetadataEntry]] = Field(default_factory=dict)
    notable: list[ForensicFinding] = Field(default_factory=list)
    decoded: list[DecodedMetadataValue] = Field(default_factory=list)
    timeline: list[MetadataTimelineEvent] = Field(default_factory=list)
    timestamp_anomalies: list[str] = Field(default_factory=list)
    gps: GPSMetadata | None = None
    embedded_objects: list[EmbeddedMetadataObject] = Field(default_factory=list)
    all_metadata: list[DeepMetadataEntry] = Field(default_factory=list)
    raw_exiftool: str = ""
    warnings: list[str] = Field(default_factory=list)


class BoundingBox(BaseModel):
    x: int = Field(ge=0)
    y: int = Field(ge=0)
    width: int = Field(ge=0)
    height: int = Field(ge=0)


class RecoveryStep(BaseModel):
    operation: str
    tool: str
    parameters: dict[str, str | int | float | bool] = Field(default_factory=dict)


class QRDecodeResult(BaseModel):
    detected_encodings: list[str] = Field(default_factory=list)
    chain: list[DecodeStep] = Field(default_factory=list)
    decoded: str | None = None
    flags: list[str] = Field(default_factory=list)


class CodeFinding(BaseModel):
    finding_id: str
    symbology: str
    decoded_value: str
    source: str
    page: int | None = Field(default=None, ge=1)
    frame: int | None = Field(default=None, ge=0)
    timestamp_seconds: float | None = Field(default=None, ge=0)
    bounding_box: BoundingBox | None = None
    decoder: str
    confidence: Literal["high", "medium", "low"]
    recovery_method: str
    provenance: list[RecoveryStep]
    secondary_analysis: QRDecodeResult | None = None


class RecoveryAttempt(BaseModel):
    source: str
    variant: str
    decoder: str
    success: bool
    detail: str


class RecoveryVariant(BaseModel):
    variant_id: str
    label: str
    source: str
    width: int = Field(ge=1)
    height: int = Field(ge=1)
    mime_type: Literal["image/png"] = "image/png"
    image_base64: str
    transformations: list[RecoveryStep]
    best_candidate: bool = False


class QRStructure(BaseModel):
    source: str
    finder_patterns: int | None = Field(default=None, ge=0)
    estimated_version: int | None = Field(default=None, ge=1, le=40)
    estimated_modules: str | None = None
    orientation_degrees: float | None = None
    decode_failed: bool = True


class QRBarcodeAnalysis(BaseModel):
    findings: list[CodeFinding] = Field(default_factory=list)
    attempts: list[RecoveryAttempt] = Field(default_factory=list)
    variants: list[RecoveryVariant] = Field(default_factory=list)
    structures: list[QRStructure] = Field(default_factory=list)
    decoders_available: list[str] = Field(default_factory=list)
    decoders_unavailable: list[str] = Field(default_factory=list)
    scanned_sources: list[str] = Field(default_factory=list)
    warnings: list[str] = Field(default_factory=list)


class StringOccurrence(BaseModel):
    offset: int = Field(ge=0)
    value: str
    encoding: Literal["ascii", "utf-16le", "utf-16be"]


class EntropyResult(BaseModel):
    bits_per_byte: float = Field(ge=0.0, le=8.0)
    classification: Literal["very-low", "low", "normal", "high", "very-high"]
    sample_size: int = Field(ge=0)


class SignatureMatch(BaseModel):
    name: str
    mime_type: str
    offset: int = Field(ge=0)
    signature: str
    is_embedded: bool


class ExtensionAssessment(BaseModel):
    provided_extension: str | None
    expected_extensions: list[str]
    mismatch: bool
    reason: str


class EmbeddedFile(BaseModel):
    name: str
    detected_type: str
    mime_type: str
    offset: int = Field(ge=0)
    estimated_size: int | None = Field(default=None, ge=0)
    extracted_artifact_id: str | None = None


class ArchiveMember(BaseModel):
    path: str
    size: int = Field(ge=0)
    compressed_size: int | None = Field(default=None, ge=0)
    kind: Literal["file", "directory", "symlink", "other"]
    encrypted: bool = False
    extractable: bool
    skipped_reason: str | None = None
    extracted_artifact_id: str | None = None


class ArchiveDiscovery(BaseModel):
    format: str
    member_count: int = Field(ge=0)
    total_uncompressed_size: int = Field(ge=0)
    members_truncated: bool
    members: list[ArchiveMember]


class FlagCandidate(BaseModel):
    value: str
    matched_pattern: str
    source: str
    offset: int = Field(ge=0)
    confidence: float = Field(ge=0.0, le=1.0)
    context: str
    state: Literal["candidate"] = "candidate"


class ExtractedArtifact(BaseModel):
    artifact_id: str
    parent_artifact_id: str
    source_path: str
    extraction_method: Literal["archive-member", "embedded-carve"]
    size: int = Field(ge=0)
    detected_type: str
    mime_type: str
    hashes: Hashes
    entropy: EntropyResult
    retained: Literal[False] = False


class TriageLimits(BaseModel):
    max_upload_bytes: int = Field(ge=1)
    max_strings: int = Field(ge=1)
    max_archive_members: int = Field(ge=1)
    max_extracted_bytes: int = Field(ge=1)
    max_compression_ratio: float = Field(ge=1.0)


class ForensicsTriageResponse(BaseModel):
    analysis_id: str
    artifact_id: str
    analyzer: str
    category: Literal["forensics"] = "forensics"
    original_filename: str
    size: int = Field(ge=0)
    magic: MagicByteDetection
    hashes: Hashes
    metadata: list[MetadataEntry]
    metadata_analysis: MetadataAnalysis
    qr_barcode: QRBarcodeAnalysis
    notable_findings: list[ForensicFinding] = Field(default_factory=list)
    strings: list[StringOccurrence]
    strings_truncated: bool
    entropy: EntropyResult
    signatures: list[SignatureMatch]
    extension: ExtensionAssessment
    embedded_files: list[EmbeddedFile]
    archives: list[ArchiveDiscovery]
    flags: list[FlagCandidate]
    extracted_artifacts: list[ExtractedArtifact]
    warnings: list[str]
    limits: TriageLimits
