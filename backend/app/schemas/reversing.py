from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field


Severity = Literal["critical", "high", "medium", "low", "info"]


class ReverseHashes(BaseModel):
    md5: str
    sha256: str


class ReverseFileInfo(BaseModel):
    name: str
    size: int = Field(ge=0)
    hashes: ReverseHashes
    detected_type: str
    format: str
    architecture: str | None = None
    bits: int | None = None
    endian: Literal["little", "big"] | None = None
    operating_system: str | None = None
    compiler: str | None = None
    entry_point: int | None = Field(default=None, ge=0)
    stripped: bool | None = None
    packed: bool | None = None
    extension_matches: bool
    extension_reason: str


class ReverseProtection(BaseModel):
    name: str
    status: Literal["enabled", "disabled", "partial", "unknown"]
    value: str
    significance: str
    evidence: str


class ReverseSection(BaseModel):
    name: str
    virtual_address: int = Field(ge=0)
    file_offset: int = Field(ge=0)
    size: int = Field(ge=0)
    permissions: str
    entropy: float = Field(ge=0.0, le=8.0)
    suspicious: bool = False
    reason: str | None = None


class ReverseString(BaseModel):
    offset: int = Field(ge=0)
    value: str
    encoding: Literal["ascii", "utf-16le", "utf-16be"]
    category: str
    importance: Severity
    reason: str


class ReverseImport(BaseModel):
    name: str
    library: str | None = None
    category: str
    importance: Severity
    reason: str


class ReverseFunction(BaseModel):
    name: str
    address: int | None = Field(default=None, ge=0)
    likely_role: str
    evidence: list[str]
    confidence: float = Field(ge=0.0, le=1.0)


class DisassemblyLine(BaseModel):
    address: int = Field(ge=0)
    bytes: str
    instruction: str
    function: str | None = None


class ReverseFinding(BaseModel):
    severity: Severity
    title: str
    confidence: float = Field(ge=0.0, le=1.0)
    evidence: str
    why_it_matters: str
    recommendation: str
    location: str | None = None


class ReverseFlagCandidate(BaseModel):
    value: str
    matched_pattern: str
    source: str
    offset: int = Field(ge=0)
    confidence: float = Field(ge=0.0, le=1.0)
    context: str
    state: Literal["candidate"] = "candidate"


class ValidationLead(BaseModel):
    kind: str
    evidence: str
    interpretation: str
    next_step: str
    confidence: float = Field(ge=0.0, le=1.0)


class DynamicRecommendation(BaseModel):
    breakpoint: str
    why: str
    inspect: str
    command: str | None = None


class ReverseLimits(BaseModel):
    max_upload_bytes: int = Field(ge=1)
    max_strings: int = Field(ge=1)
    max_disassembly_lines: int = Field(ge=1)


class ReverseAnalysisResponse(BaseModel):
    analysis_id: str
    artifact_id: str
    analyzer: Literal["reverse_static"] = "reverse_static"
    category: Literal["reversing"] = "reversing"
    file: ReverseFileInfo
    protections: list[ReverseProtection]
    sections: list[ReverseSection]
    strings: list[ReverseString]
    strings_truncated: bool
    imports: list[ReverseImport]
    exports: list[str]
    functions: list[ReverseFunction]
    disassembly: list[DisassemblyLine]
    validation_leads: list[ValidationLead]
    transformations: list[str]
    findings: list[ReverseFinding]
    flags: list[ReverseFlagCandidate]
    likely_flag_locations: list[str]
    recovered_values: dict[str, str]
    dynamic_recommendations: list[DynamicRecommendation]
    solving_path: list[str]
    tools: dict[str, bool]
    warnings: list[str]
    summary: str
    limits: ReverseLimits
