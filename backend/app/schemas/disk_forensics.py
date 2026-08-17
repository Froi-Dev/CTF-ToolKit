from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field

from app.schemas.forensics import EntropyResult, Hashes


# ---------------------------------------------------------------------------
# Image-level
# ---------------------------------------------------------------------------

class DiskImageInfo(BaseModel):
    filename: str
    size: int = Field(ge=0)
    detected_image_type: str
    mime_type: str
    sector_size: int = Field(ge=1)
    total_sectors: int = Field(ge=0)
    hashes: Hashes


class PartitionTableInfo(BaseModel):
    type: Literal[
        "mbr", "gpt", "apm", "bsd", "hybrid", "protective-mbr",
        "raw-filesystem", "none", "unknown",
    ]
    description: str


# ---------------------------------------------------------------------------
# Partitions & regions
# ---------------------------------------------------------------------------

class PartitionEntry(BaseModel):
    number: int = Field(ge=0)
    slot: str
    start_sector: int = Field(ge=0)
    end_sector: int = Field(ge=0)
    sector_count: int = Field(ge=0)
    byte_offset: int = Field(ge=0)
    size_bytes: int = Field(ge=0)
    size_display: str
    partition_type_id: str
    partition_type_name: str
    filesystem: str | None = None
    bootable: bool = False
    status: Literal["allocated", "deleted", "extended"] = "allocated"


class UnallocatedRegion(BaseModel):
    start_sector: int = Field(ge=0)
    end_sector: int = Field(ge=0)
    sector_count: int = Field(ge=0)
    byte_offset: int = Field(ge=0)
    size_bytes: int = Field(ge=0)
    size_display: str
    location: Literal["before-partitions", "between-partitions", "after-partitions", "partition-gap"]
    suspicious: bool = False
    reason: str | None = None


# ---------------------------------------------------------------------------
# Filesystem
# ---------------------------------------------------------------------------

class FilesystemInfo(BaseModel):
    partition_number: int = Field(ge=0)
    filesystem_type: str
    volume_label: str | None = None
    volume_uuid: str | None = None
    block_size: int | None = None
    cluster_size: int | None = None
    total_blocks: int | None = None
    free_blocks: int | None = None
    root_inode: int | None = None
    inode_count: int | None = None
    last_mounted: str | None = None
    last_mount_time: str | None = None
    last_write_time: str | None = None
    creation_time: str | None = None
    journal: bool | None = None
    dirty: bool | None = None
    details: dict[str, str | int | bool | None] = Field(default_factory=dict)


# ---------------------------------------------------------------------------
# Files
# ---------------------------------------------------------------------------

class FileEntry(BaseModel):
    id: str
    path: str
    name: str
    is_directory: bool = False
    inode: int | None = None
    size: int = Field(default=0, ge=0)
    size_display: str = ""
    status: Literal[
        "allocated", "deleted", "recovered", "orphaned",
        "metadata-only", "corrupted", "carved", "slack-derived",
        "unallocated-derived",
    ] = "allocated"
    permissions: str | None = None
    uid: int | None = None
    gid: int | None = None
    access_time: str | None = None
    modification_time: str | None = None
    change_time: str | None = None
    creation_time: str | None = None
    partition_number: int = Field(default=0, ge=0)
    data_offset: int | None = None
    interesting: bool = False
    interest_reasons: list[str] = Field(default_factory=list)
    children: list[FileEntry] = Field(default_factory=list)


# ---------------------------------------------------------------------------
# Recovery
# ---------------------------------------------------------------------------

class RecoveredFile(BaseModel):
    file_entry: FileEntry
    recovery_status: Literal["full", "partial", "failed"]
    preview_text: str | None = None
    preview_hex: str | None = None
    magic_type: str | None = None
    magic_bytes: str | None = None
    content_size: int = Field(default=0, ge=0)


# ---------------------------------------------------------------------------
# Carving
# ---------------------------------------------------------------------------

class CarvedFile(BaseModel):
    id: str
    file_type: str
    mime_type: str
    disk_offset: int = Field(ge=0)
    disk_offset_hex: str
    size: int = Field(ge=0)
    size_display: str
    source_region: str
    signature_hex: str
    preview_hex: str | None = None
    entropy: EntropyResult | None = None


# ---------------------------------------------------------------------------
# Type mismatches
# ---------------------------------------------------------------------------

class TypeMismatch(BaseModel):
    file_path: str
    extension: str
    actual_type: str
    magic_bytes_hex: str
    partition_number: int = Field(default=0, ge=0)


# ---------------------------------------------------------------------------
# String findings
# ---------------------------------------------------------------------------

class StringFinding(BaseModel):
    value: str
    offset: int = Field(ge=0)
    offset_hex: str
    source: str
    encoding: Literal["ascii", "utf-16le", "utf-16be"]
    category: Literal[
        "flag", "credential", "url", "key", "encoded", "interesting", "general",
    ] = "general"
    partition_number: int | None = None


class EncodedStringFinding(BaseModel):
    original: str
    decoded: str
    encoding_type: Literal["base64", "base32", "hex", "url"]
    confidence: float = Field(ge=0.0, le=1.0)
    source: str
    offset: int = Field(ge=0)


# ---------------------------------------------------------------------------
# Flags
# ---------------------------------------------------------------------------

class DiskFlagCandidate(BaseModel):
    value: str
    source: str
    partition: str
    evidence_type: str
    confidence: float = Field(ge=0.0, le=1.0)
    context: str
    disk_offset: int | None = None
    disk_offset_hex: str | None = None


# ---------------------------------------------------------------------------
# Notable findings
# ---------------------------------------------------------------------------

class NotableFinding(BaseModel):
    id: str
    severity: Literal["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
    confidence: float = Field(ge=0.0, le=1.0)
    category: str
    title: str
    description: str
    evidence: str
    partition: str | None = None
    filesystem: str | None = None
    file_path: str | None = None
    inode_or_record: int | None = None
    sector: int | None = None
    absolute_offset: int | None = None
    absolute_offset_hex: str | None = None
    recommended_action: str
    equivalent_command: str | None = None


# ---------------------------------------------------------------------------
# Evidence Graph
# ---------------------------------------------------------------------------

class EvidenceNode(BaseModel):
    id: str
    node_type: str
    label: str
    attributes: dict[str, str | int | float | bool | None] = Field(default_factory=dict)
    confidence: float = Field(default=1.0, ge=0.0, le=1.0)


class EvidenceEdge(BaseModel):
    source_id: str
    target_id: str
    relation: str


# ---------------------------------------------------------------------------
# Timeline
# ---------------------------------------------------------------------------

class TimelineEvent(BaseModel):
    timestamp: str
    event_type: Literal["created", "modified", "accessed", "changed", "deleted"]
    file_path: str
    partition_number: int = Field(default=0, ge=0)
    inode: int | None = None
    details: str | None = None


# ---------------------------------------------------------------------------
# Top-level response
# ---------------------------------------------------------------------------

class DiskAnalysisLimits(BaseModel):
    max_upload_bytes: int = Field(ge=1)
    max_carved_files: int = Field(ge=1)
    max_strings: int = Field(ge=1)
    max_file_entries: int = Field(ge=1)


class DiskForensicsResponse(BaseModel):
    analysis_id: str
    analyzer: str
    category: Literal["disk-forensics"] = "disk-forensics"
    image: DiskImageInfo
    partition_table: PartitionTableInfo
    partitions: list[PartitionEntry]
    unallocated_regions: list[UnallocatedRegion]
    filesystems: list[FilesystemInfo]
    files: list[FileEntry]
    deleted_files: list[FileEntry]
    recovered_files: list[RecoveredFile]
    carved_files: list[CarvedFile]
    type_mismatches: list[TypeMismatch]
    embedded_objects: list[dict[str, str | int | None]]
    strings: list[StringFinding]
    encoded_strings: list[EncodedStringFinding]
    flag_candidates: list[DiskFlagCandidate]
    notable_findings: list[NotableFinding]
    timeline: list[TimelineEvent]
    evidence_nodes: list[EvidenceNode] = Field(default_factory=list)
    evidence_edges: list[EvidenceEdge] = Field(default_factory=list)
    warnings: list[str]
    errors: list[str]
    limits: DiskAnalysisLimits
