"""Unallocated space analysis and extraction."""

from __future__ import annotations

from pathlib import Path

from app.schemas.disk_forensics import UnallocatedRegion


def analyze_unallocated(
    path: Path, regions: list[UnallocatedRegion]
) -> dict[str, bytes]:
    """Extract and analyze unallocated regions."""
    
    # In a full implementation, this reads the raw bytes from the specified regions
    # and processes them for strings, carving, and entropy.
    
    return {}
