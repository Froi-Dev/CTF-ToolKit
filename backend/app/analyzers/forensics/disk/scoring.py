"""Evidence scoring and notable findings generation."""

from __future__ import annotations

import uuid

from app.schemas.disk_forensics import NotableFinding, FileEntry, DiskFlagCandidate, CarvedFile


def generate_notable_findings(
    files: list[FileEntry],
    flags: list[DiskFlagCandidate],
    carved: list[CarvedFile],
) -> list[NotableFinding]:
    """Score evidence and generate actionable findings."""
    findings: list[NotableFinding] = []
    
    # High confidence flags are CRITICAL
    for flag in flags:
        if flag.confidence > 0.8:
            findings.append(NotableFinding(
                id=str(uuid.uuid4()),
                severity="CRITICAL",
                confidence=flag.confidence,
                category="flag",
                title="High-confidence flag candidate discovered",
                description=f"A string closely matching a known flag format was found in {flag.source}.",
                evidence=flag.value,
                partition=flag.partition,
                recommended_action="Verify this flag submission.",
            ))
            
    # In a full implementation, we'd score deleted files, hidden files, extension mismatches, etc.
    
    return sorted(findings, key=lambda f: {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}[f.severity])
