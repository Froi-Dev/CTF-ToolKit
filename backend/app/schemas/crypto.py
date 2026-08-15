from __future__ import annotations

from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field, StringConstraints, field_validator

DEFAULT_FLAG_PREFIXES = ["flag", "CTF", "picoCTF", "HTB", "H4G"]


class DecodeRequest(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=False)

    input: Annotated[str, StringConstraints(min_length=1, max_length=32_768)]
    max_depth: int = Field(default=4, ge=1, le=6)
    max_results: int = Field(default=10, ge=1, le=50)
    beam_width: int = Field(default=24, ge=4, le=64)
    timeout_ms: int = Field(default=2_000, ge=100, le=5_000)
    xor_keys: list[str] = Field(default_factory=list, max_length=16)
    flag_prefixes: list[str] = Field(
        default_factory=lambda: DEFAULT_FLAG_PREFIXES.copy(),
        min_length=1,
        max_length=20,
    )

    @field_validator("flag_prefixes")
    @classmethod
    def validate_flag_prefixes(cls, values: list[str]) -> list[str]:
        for value in values:
            if not (1 <= len(value) <= 32) or not all(
                character.isalnum() or character == "_" for character in value
            ):
                raise ValueError("flag prefixes must contain only letters, numbers, or underscores")
        return list(dict.fromkeys(values))

    @field_validator("xor_keys")
    @classmethod
    def validate_xor_keys(cls, values: list[str]) -> list[str]:
        for value in values:
            if not value or len(value) > 128:
                raise ValueError("XOR keys must contain between 1 and 128 characters")
        return list(dict.fromkeys(values))


class EncodingDetection(BaseModel):
    name: str
    confidence: float = Field(ge=0.0, le=1.0)
    evidence: str


class ScoreBreakdown(BaseModel):
    printable: float = Field(ge=0.0, le=1.0)
    utf8: float = Field(ge=0.0, le=1.0)
    language: float = Field(ge=0.0, le=1.0)
    structure: float = Field(ge=0.0, le=1.0)
    flag_bonus: float = Field(ge=0.0, le=1.0)
    entropy: float = Field(ge=0.0)
    depth_penalty: float = Field(ge=0.0, le=1.0)
    syntax_bonus: float = Field(ge=0.0, le=1.0)


class TransformationStep(BaseModel):
    transform: str
    parameter: str | None = None


class FlagCandidate(BaseModel):
    value: str
    matched_pattern: str
    source: Literal["request.input"] = "request.input"
    offset: int = Field(ge=0)
    confidence: float = Field(ge=0.0, le=1.0)
    context: str
    chain: list[TransformationStep] = Field(default_factory=list)
    state: Literal["candidate"] = "candidate"


class DecodingCandidate(BaseModel):
    output: str
    output_format: Literal["utf-8", "hex"]
    output_bytes: int = Field(ge=0)
    output_truncated: bool
    chain: list[TransformationStep]
    score: float = Field(ge=0.0, le=1.0)
    score_breakdown: ScoreBreakdown
    flags: list[FlagCandidate]


class SearchMetadata(BaseModel):
    explored_states: int = Field(ge=0)
    elapsed_ms: int = Field(ge=0)
    max_depth_reached: int = Field(ge=0)
    truncated: bool


class DecodeResponse(BaseModel):
    analyzer: str
    category: Literal["crypto"] = "crypto"
    detected_encodings: list[EncodingDetection]
    results: list[DecodingCandidate]
    flags: list[FlagCandidate]
    search: SearchMetadata
