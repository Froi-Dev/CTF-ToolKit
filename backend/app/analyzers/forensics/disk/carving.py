"""File carving from raw disk regions."""

from __future__ import annotations

from pathlib import Path

from app.schemas.disk_forensics import CarvedFile


def carve_files(
    path: Path, regions: list[tuple[int, int, str]], max_carved: int = 64
) -> list[CarvedFile]:
    """Scan raw regions for file signatures and carve them out."""
    carved: list[CarvedFile] = []
    
    # In a full implementation, this scans the provided regions (start_offset, end_offset, name)
    # for signatures from SIGNATURES, finds end markers, and extracts the files.
    
    return carved
