from __future__ import annotations

import gzip
import stat
import tarfile
import zipfile
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from uuid import uuid4

from app.schemas.forensics import ArchiveDiscovery, ArchiveMember


@dataclass(frozen=True, slots=True)
class ArchivePolicy:
    max_members: int
    max_extracted_bytes: int
    max_compression_ratio: float


@dataclass(frozen=True, slots=True)
class ExtractedPath:
    artifact_id: str
    source_path: str
    method: str
    path: Path


def _member_parts(name: str) -> tuple[str, ...] | None:
    if "\x00" in name:
        return None
    normalized = name.replace("\\", "/")
    candidate = PurePosixPath(normalized)
    if candidate.is_absolute() or any(part in {"", ".", ".."} for part in candidate.parts):
        return None
    if candidate.parts and ":" in candidate.parts[0]:
        return None
    return candidate.parts


def _destination(root: Path, name: str, used: set[Path]) -> Path | None:
    parts = _member_parts(name)
    if not parts:
        return None
    destination = root.joinpath(*parts).resolve()
    root_resolved = root.resolve()
    if destination == root_resolved or root_resolved not in destination.parents:
        return None
    if destination in used:
        return None
    used.add(destination)
    return destination


def _copy_bounded(source: object, destination: Path, remaining: int) -> int:
    destination.parent.mkdir(parents=True, exist_ok=True)
    written = 0
    try:
        with destination.open("xb") as output:
            while True:
                chunk = source.read(min(64 * 1024, remaining - written + 1))  # type: ignore[attr-defined]
                if not chunk:
                    break
                written += len(chunk)
                if written > remaining:
                    raise ValueError("expanded data limit exceeded")
                output.write(chunk)
    except Exception:
        destination.unlink(missing_ok=True)
        raise
    return written


def _zip_kind(info: zipfile.ZipInfo) -> str:
    mode = info.external_attr >> 16
    if info.is_dir():
        return "directory"
    if stat.S_ISLNK(mode):
        return "symlink"
    return "file"


def inspect_zip(
    path: Path, extraction_root: Path, policy: ArchivePolicy
) -> tuple[ArchiveDiscovery, list[ExtractedPath], list[str]]:
    extracted: list[ExtractedPath] = []
    warnings: list[str] = []
    member_results: list[ArchiveMember] = []
    used: set[Path] = set()
    expanded = 0

    with zipfile.ZipFile(path) as archive:
        entries = archive.infolist()
        total_size = sum(max(0, entry.file_size) for entry in entries)
        for info in entries[: policy.max_members]:
            kind = _zip_kind(info)
            encrypted = bool(info.flag_bits & 0x1)
            reason: str | None = None
            destination: Path | None = None
            if kind == "symlink":
                reason = "symlink entries are not extracted"
            elif encrypted:
                reason = "encrypted entry requires an analyst-provided password"
            elif info.file_size > policy.max_extracted_bytes - expanded:
                reason = "expanded data limit exceeded"
            elif info.file_size / max(1, info.compress_size) > policy.max_compression_ratio:
                reason = "compression ratio limit exceeded"
            elif kind in {"file", "directory"}:
                destination = _destination(extraction_root, info.filename, used)
                if destination is None:
                    reason = "unsafe or colliding member path"

            artifact_id: str | None = None
            if reason is None and kind == "file" and destination is not None:
                try:
                    with archive.open(info, "r") as source:
                        actual = _copy_bounded(
                            source, destination, policy.max_extracted_bytes - expanded
                        )
                    expanded += actual
                    artifact_id = str(uuid4())
                    extracted.append(
                        ExtractedPath(artifact_id, info.filename, "archive-member", destination)
                    )
                except (RuntimeError, ValueError, OSError, zipfile.BadZipFile) as exc:
                    reason = f"entry extraction failed: {type(exc).__name__}"
            elif reason is None and kind == "directory":
                # Directory creation is unnecessary; file parents are created lazily.
                pass

            member_results.append(
                ArchiveMember(
                    path=info.filename,
                    size=max(0, info.file_size),
                    compressed_size=max(0, info.compress_size),
                    kind=kind,
                    encrypted=encrypted,
                    extractable=reason is None and kind in {"file", "directory"},
                    skipped_reason=reason,
                    extracted_artifact_id=artifact_id,
                )
            )

        if len(entries) > policy.max_members:
            warnings.append(
                f"ZIP has {len(entries)} members; only the first {policy.max_members} were inspected."
            )

    return (
        ArchiveDiscovery(
            format="zip",
            member_count=len(entries),
            total_uncompressed_size=total_size,
            members_truncated=len(entries) > policy.max_members,
            members=member_results,
        ),
        extracted,
        warnings,
    )


def _tar_kind(member: tarfile.TarInfo) -> str:
    if member.isfile():
        return "file"
    if member.isdir():
        return "directory"
    if member.issym() or member.islnk():
        return "symlink"
    return "other"


def inspect_tar(
    path: Path, extraction_root: Path, policy: ArchivePolicy
) -> tuple[ArchiveDiscovery, list[ExtractedPath], list[str]]:
    extracted: list[ExtractedPath] = []
    warnings: list[str] = []
    member_results: list[ArchiveMember] = []
    used: set[Path] = set()
    expanded = 0

    with tarfile.open(path, mode="r:*") as archive:
        entries = archive.getmembers()
        total_size = sum(max(0, entry.size) for entry in entries if entry.isfile())
        ratio_exceeded = (
            total_size / max(1, path.stat().st_size) > policy.max_compression_ratio
        )
        for member in entries[: policy.max_members]:
            kind = _tar_kind(member)
            reason: str | None = None
            destination: Path | None = None
            if kind == "symlink":
                reason = "link entries are not extracted"
            elif kind == "other":
                reason = "special entries are not extracted"
            elif kind == "file" and ratio_exceeded:
                reason = "archive compression ratio limit exceeded"
            elif member.size > policy.max_extracted_bytes - expanded:
                reason = "expanded data limit exceeded"
            elif kind in {"file", "directory"}:
                destination = _destination(extraction_root, member.name, used)
                if destination is None:
                    reason = "unsafe or colliding member path"

            artifact_id: str | None = None
            if reason is None and kind == "file" and destination is not None:
                source = archive.extractfile(member)
                if source is None:
                    reason = "member content is unavailable"
                else:
                    try:
                        with source:
                            actual = _copy_bounded(
                                source, destination, policy.max_extracted_bytes - expanded
                            )
                        expanded += actual
                        artifact_id = str(uuid4())
                        extracted.append(
                            ExtractedPath(artifact_id, member.name, "archive-member", destination)
                        )
                    except (ValueError, OSError, tarfile.TarError) as exc:
                        reason = f"entry extraction failed: {type(exc).__name__}"

            member_results.append(
                ArchiveMember(
                    path=member.name,
                    size=max(0, member.size),
                    compressed_size=None,
                    kind=kind,
                    extractable=reason is None and kind in {"file", "directory"},
                    skipped_reason=reason,
                    extracted_artifact_id=artifact_id,
                )
            )

        if len(entries) > policy.max_members:
            warnings.append(
                f"TAR has {len(entries)} members; only the first {policy.max_members} were inspected."
            )

    return (
        ArchiveDiscovery(
            format="tar",
            member_count=len(entries),
            total_uncompressed_size=total_size,
            members_truncated=len(entries) > policy.max_members,
            members=member_results,
        ),
        extracted,
        warnings,
    )


def inspect_gzip(
    path: Path, extraction_root: Path, policy: ArchivePolicy, original_name: str
) -> tuple[ArchiveDiscovery, list[ExtractedPath], list[str]]:
    output_name = Path(original_name).stem or "gzip-content"
    destination = _destination(extraction_root, output_name, set())
    if destination is None:
        destination = extraction_root / "gzip-content"
    reason: str | None = None
    artifact_id: str | None = None
    extracted: list[ExtractedPath] = []
    size = 0
    try:
        with gzip.open(path, "rb") as source:
            size = _copy_bounded(source, destination, policy.max_extracted_bytes)
        if size / max(1, path.stat().st_size) > policy.max_compression_ratio:
            destination.unlink(missing_ok=True)
            reason = "compression ratio limit exceeded"
        else:
            artifact_id = str(uuid4())
            extracted.append(
                ExtractedPath(artifact_id, output_name, "archive-member", destination)
            )
    except (gzip.BadGzipFile, EOFError, ValueError, OSError) as exc:
        reason = f"gzip extraction failed: {type(exc).__name__}"

    member = ArchiveMember(
        path=output_name,
        size=size,
        compressed_size=path.stat().st_size,
        kind="file",
        extractable=reason is None,
        skipped_reason=reason,
        extracted_artifact_id=artifact_id,
    )
    return (
        ArchiveDiscovery(
            format="gzip",
            member_count=1,
            total_uncompressed_size=size,
            members_truncated=False,
            members=[member],
        ),
        extracted,
        [],
    )
