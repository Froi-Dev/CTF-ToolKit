from __future__ import annotations

from typing import Literal
from pydantic import BaseModel, Field


CryptoCategory = Literal[
    "ENCODING",
    "CIPHER",
    "HASH",
    "SYMMETRIC ENCRYPTION",
    "PUBLIC-KEY CRYPTOGRAPHY",
    "XOR / STREAM CIPHER",
    "CUSTOM ALGORITHM",
    "CRYPTOGRAPHIC KEY",
    "CERTIFICATE",
    "COMPRESSED DATA",
    "SERIALIZED DATA",
    "UNKNOWN",
]


class CryptoTriageResult(BaseModel):
    crypto_type: CryptoCategory
    likely_algorithm: str
    confidence: Literal["LOW", "MEDIUM", "HIGH", "CONFIRMED"]
    evidence: list[str]
    recommended_engine: str | None
    recommended_next_action: str | None


class CryptoTriageResponse(BaseModel):
    analyzer: Literal["crypto_triage"] = "crypto_triage"
    category: Literal["crypto"] = "crypto"
    results: list[CryptoTriageResult]
    warnings: list[str]
