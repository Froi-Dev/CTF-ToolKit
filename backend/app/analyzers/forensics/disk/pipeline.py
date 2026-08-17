"""Main orchestrator for disk image forensics."""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from pathlib import Path

from app.core.analyzers import BaseAnalyzer
from app.schemas.disk_forensics import (
    DiskForensicsResponse,
    DiskImageInfo,
    DiskAnalysisLimits,
)
from app.schemas.forensics import Hashes
from app.analyzers.forensics.disk.image_detect import detect_image, compute_hashes
from app.analyzers.forensics.disk.partition_table import detect_partition_table, find_unallocated
from app.analyzers.forensics.disk.filesystem import detect_filesystem
from app.analyzers.forensics.disk.file_enum import enumerate_files
from app.analyzers.forensics.disk.recovery import recover_deleted_files
from app.analyzers.forensics.disk.unallocated import analyze_unallocated
from app.analyzers.forensics.disk.carving import carve_files
from app.analyzers.forensics.disk.strings_scan import scan_strings
from app.analyzers.forensics.disk.scoring import generate_notable_findings
from app.analyzers.forensics.disk.graph import EvidenceGraph
from app.analyzers.forensics.disk.reasoning_engine import ForensicReasoningEngine


@dataclass(frozen=True, slots=True)
class DiskPolicy:
    max_upload_bytes: int = 512 * 1024 * 1024  # 512 MiB
    max_carved_files: int = 64
    max_strings: int = 1000
    max_file_entries: int = 50000


@dataclass(frozen=True, slots=True)
class DiskAnalysisInput:
    path: Path
    original_filename: str
    artifact_id: str


class DiskImageAnalyzer(BaseAnalyzer[DiskAnalysisInput, DiskForensicsResponse]):
    name = "disk_forensics"
    category = "disk-forensics"

    def __init__(self, policy: DiskPolicy | None = None) -> None:
        self.policy = policy or DiskPolicy()

    def supports(self, value: object) -> bool:
        return isinstance(value, DiskAnalysisInput) and value.path.is_file()

    def analyze(self, value: DiskAnalysisInput) -> DiskForensicsResponse:
        if not self.supports(value):
            raise TypeError("DiskImageAnalyzer requires a regular file input")

        size = value.path.stat().st_size
        warnings: list[str] = []
        errors: list[str] = []

        # 1. Detect image format
        detection = detect_image(value.path)
        md5_hash, sha1_hash, sha256_hash = compute_hashes(value.path)
        
        image_info = DiskImageInfo(
            filename=value.original_filename,
            size=size,
            detected_image_type=detection.image_type,
            mime_type=detection.mime_type,
            sector_size=detection.sector_size,
            total_sectors=size // detection.sector_size if detection.sector_size else 0,
            hashes=Hashes(md5=md5_hash, sha1=sha1_hash, sha256=sha256_hash),
        )

        # 2. Partition Table Parsing
        ptable = detect_partition_table(value.path, detection.sector_size)
        warnings.extend(ptable.warnings)

        # Map partitions to schemas
        from app.schemas.disk_forensics import PartitionEntry, PartitionTableInfo, UnallocatedRegion
        partitions: list[PartitionEntry] = []
        for p in ptable.partitions:
            partitions.append(PartitionEntry(
                number=p.number,
                slot=p.slot,
                start_sector=p.start_sector,
                end_sector=p.end_sector,
                sector_count=p.sector_count,
                byte_offset=p.start_sector * detection.sector_size,
                size_bytes=p.sector_count * detection.sector_size,
                size_display=_format_size(p.sector_count * detection.sector_size),
                partition_type_id=p.type_id,
                partition_type_name=p.type_name,
                bootable=p.bootable,
                status=p.status,  # type: ignore[arg-type]
            ))

        # 3. Find Unallocated Regions
        unallocated_raw = find_unallocated(ptable.partitions, image_info.total_sectors, detection.sector_size)
        unalloc_regions: list[UnallocatedRegion] = []
        for u in unallocated_raw:
            unalloc_regions.append(UnallocatedRegion(
                start_sector=u.start_sector,
                end_sector=u.end_sector,
                sector_count=u.sector_count,
                byte_offset=u.start_sector * detection.sector_size,
                size_bytes=u.sector_count * detection.sector_size,
                size_display=_format_size(u.sector_count * detection.sector_size),
                location=u.location,  # type: ignore[arg-type]
                suspicious=u.suspicious,
                reason=u.reason,
            ))

        # 4. Filesystem Detection
        filesystems = []
        for p in partitions:
            if p.status == "extended":
                continue
            fs = detect_filesystem(value.path, p.byte_offset)
            if fs:
                p.filesystem = fs.fs_type
                from app.schemas.disk_forensics import FilesystemInfo
                filesystems.append(FilesystemInfo(
                    partition_number=p.number,
                    filesystem_type=fs.fs_type,
                    volume_label=fs.volume_label,
                    volume_uuid=fs.volume_uuid,
                    block_size=fs.block_size,
                    cluster_size=fs.cluster_size,
                    total_blocks=fs.total_blocks,
                    free_blocks=fs.free_blocks,
                    root_inode=fs.root_inode,
                    inode_count=fs.inode_count,
                    last_mounted=fs.last_mounted,
                    last_mount_time=fs.last_mount_time,
                    last_write_time=fs.last_write_time,
                    creation_time=fs.creation_time,
                    journal=fs.journal,
                    dirty=fs.dirty,
                    details=fs.details,
                ))

        # Initialize Evidence Graph and Reasoning Engine
        graph = EvidenceGraph()
        reasoning_engine = ForensicReasoningEngine(graph)
        notable_findings = []

        graph.add_node("Disk", image_info.filename, {"size": image_info.size})

        # 5. File Enumeration & Recovery & 6. Carving & Strings
        files = []
        deleted_files = []
        recovered_files = []
        carved_files = []
        type_mismatches = []
        embedded_objects = []
        timeline = []

        # Stage A: Raw Strings
        strings, encoded_strings, flag_candidates = scan_strings(value.path, [])
        for flag in flag_candidates:
            node = graph.add_node("FlagCandidate", flag.value, {"confidence": flag.confidence})
            notable_findings.extend(reasoning_engine.evaluate_node(node))

        # Stage B & C: Filesystems, Enumeration, Recovery
        for p in partitions:
            if not p.filesystem:
                continue
            
            p_node = graph.add_node("Partition", f"Partition {p.number} ({p.filesystem})", {"offset": p.byte_offset})
            
            p_files = enumerate_files(value.path, p.byte_offset, p.filesystem, None, detection.sector_size)
            files.extend(p_files)
            
            p_deleted = [f for f in p_files if f.status == "deleted"]
            deleted_files.extend(p_deleted)
            
            if p_deleted:
                p_recovered = recover_deleted_files(value.path, p.byte_offset, p.filesystem, p_deleted, detection.sector_size)
                recovered_files.extend(p_recovered)
                for rec in p_recovered:
                    r_node = graph.add_node("RecoveredFile", rec.file_entry.name, {"size": rec.content_size, "status": rec.recovery_status})
                    graph.add_edge(p_node.id, r_node.id, "contains")
                    notable_findings.extend(reasoning_engine.evaluate_node(r_node))

        notable_findings.extend(generate_notable_findings(files, flag_candidates, carved_files))

        return DiskForensicsResponse(
            analysis_id=str(uuid.uuid4()),
            analyzer=self.name,
            image=image_info,
            partition_table=PartitionTableInfo(type=ptable.table_type, description=ptable.description),  # type: ignore[arg-type]
            partitions=partitions,
            unallocated_regions=unalloc_regions,
            filesystems=filesystems,
            files=files,
            deleted_files=deleted_files,
            recovered_files=recovered_files,
            carved_files=carved_files,
            type_mismatches=type_mismatches,
            embedded_objects=embedded_objects,
            strings=strings,
            encoded_strings=encoded_strings,
            flag_candidates=flag_candidates,
            notable_findings=notable_findings,
            timeline=timeline,
            evidence_nodes=graph.get_nodes(),
            evidence_edges=graph.get_edges(),
            warnings=warnings,
            errors=errors,
            limits=DiskAnalysisLimits(
                max_upload_bytes=self.policy.max_upload_bytes,
                max_carved_files=self.policy.max_carved_files,
                max_strings=self.policy.max_strings,
                max_file_entries=self.policy.max_file_entries,
            ),
        )


def _format_size(size_bytes: int) -> str:
    """Human-readable size."""
    if size_bytes < 1024:
        return f"{size_bytes} B"
    if size_bytes < 1024 ** 2:
        return f"{size_bytes / 1024:.1f} KiB"
    if size_bytes < 1024 ** 3:
        return f"{size_bytes / 1024 ** 2:.1f} MiB"
    return f"{size_bytes / 1024 ** 3:.2f} GiB"
