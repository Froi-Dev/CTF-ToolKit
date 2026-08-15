from __future__ import annotations

from typing import Literal

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
