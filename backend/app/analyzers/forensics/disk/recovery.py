"""Deleted file recovery from filesystem metadata."""

from __future__ import annotations

from pathlib import Path
from typing import BinaryIO

from app.schemas.disk_forensics import RecoveredFile, FileEntry


import subprocess
import logging

logger = logging.getLogger(__name__)

def recover_deleted_files(
    path: Path, partition_offset: int, fs_type: str, deleted_files: list[FileEntry], sector_size: int = 512
) -> list[RecoveredFile]:
    """Attempt to recover deleted file contents using Sleuth Kit's icat."""
    recovered: list[RecoveredFile] = []
    sector_offset = partition_offset // sector_size

    for entry in deleted_files:
        if not entry.inode or entry.is_directory:
            continue
            
        cmd = ["icat", "-o", str(sector_offset), str(path), str(entry.inode)]
        try:
            result = subprocess.run(cmd, capture_output=True, check=False)
            if result.returncode == 0 and result.stdout:
                # We have some recovered bytes
                content = result.stdout
                preview_hex = content[:32].hex() if len(content) > 0 else None
                preview_text = None
                try:
                    preview_text = content[:100].decode("utf-8", errors="ignore")
                except:
                    pass

                rec = RecoveredFile(
                    file_entry=entry,
                    recovery_status="full" if len(content) == entry.size or entry.size == 0 else "partial",
                    preview_text=preview_text,
                    preview_hex=preview_hex,
                    content_size=len(content)
                )
                recovered.append(rec)
        except Exception as e:
            logger.error(f"icat failed for inode {entry.inode}: {e}")
            
    return recovered
