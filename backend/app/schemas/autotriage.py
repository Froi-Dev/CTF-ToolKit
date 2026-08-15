from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field

from app.schemas.forensics import ForensicsTriageResponse
from app.schemas.network import NetworkAnalysisResponse
from app.schemas.stego import StegoAnalysisResponse


TriageStatus = Literal["completed", "skipped", "unavailable", "failed"]


class AnalyzerRun(BaseModel):
    analyzer: str
    category: Literal["forensics", "steganography", "network"]
    status: TriageStatus
    duration_ms: int = Field(ge=0)
    message: str


class CapabilityStatus(BaseModel):
    key: Literal[
        "file_identification",
        "hashes",
        "metadata",
        "strings",
        "entropy",
        "signatures",
        "archives",
        "embedded_files",
        "flag_detection",
        "image_structure",
        "lsb",
        "network_protocols",
    ]
    label: str
    analyzer: str
    status: TriageStatus
    result_count: int = Field(ge=0)
    message: str


class AutoTriageResponse(BaseModel):
    analysis_id: str
    artifact_id: str
    analyzer: Literal["auto_triage"] = "auto_triage"
    category: Literal["auto-triage"] = "auto-triage"
    original_filename: str
    size: int = Field(ge=0)
    detected_type: str
    mime_type: str
    duration_ms: int = Field(ge=0)
    analyzer_runs: list[AnalyzerRun]
    capabilities: list[CapabilityStatus]
    forensics: ForensicsTriageResponse
    steganography: StegoAnalysisResponse | None = None
    network: NetworkAnalysisResponse | None = None
    warnings: list[str]

