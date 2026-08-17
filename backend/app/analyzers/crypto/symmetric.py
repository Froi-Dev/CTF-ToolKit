from __future__ import annotations

from app.core.analyzers import BaseAnalyzer
from pydantic import BaseModel, Field
from typing import Literal

class SymmetricAnalyzeInput(BaseModel):
    ciphertext: bytes

class SymmetricFinding(BaseModel):
    title: str
    severity: Literal["critical", "high", "medium", "low", "info"]
    confidence: float
    description: str

class SymmetricAnalyzeResponse(BaseModel):
    analyzer: Literal["symmetric_analyzer"] = "symmetric_analyzer"
    category: Literal["crypto"] = "crypto"
    findings: list[SymmetricFinding]
    block_size_detected: int | None

class SymmetricAnalyzer(BaseAnalyzer[SymmetricAnalyzeInput, SymmetricAnalyzeResponse]):
    name = "symmetric_analyzer"
    category = "crypto"

    def supports(self, value: object) -> bool:
        return isinstance(value, SymmetricAnalyzeInput)

    def analyze(self, value: SymmetricAnalyzeInput) -> SymmetricAnalyzeResponse:
        findings = []
        data = value.ciphertext
        length = len(data)

        if length == 0:
            return SymmetricAnalyzeResponse(findings=[], block_size_detected=None)

        block_size = None
        if length % 16 == 0:
            block_size = 16
        elif length % 8 == 0:
            block_size = 8

        if block_size:
            blocks = [data[i:i+block_size] for i in range(0, length, block_size)]
            unique_blocks = set(blocks)
            
            if len(blocks) > 4 and len(unique_blocks) < len(blocks) * 0.8:
                findings.append(SymmetricFinding(
                    title="ECB Mode Pattern Leakage",
                    severity="high",
                    confidence=0.9,
                    description=f"Found {len(blocks) - len(unique_blocks)} repeating {block_size}-byte blocks. This strongly suggests ECB mode which leaks plaintext patterns."
                ))
                
            if blocks.count(b'\x00' * block_size) > 0:
                findings.append(SymmetricFinding(
                    title="Zero Block Detected",
                    severity="medium",
                    confidence=0.8,
                    description="A completely null block was found. This could indicate a zero IV, null padding, or ECB encryption of null bytes."
                ))

        if block_size is None:
            findings.append(SymmetricFinding(
                title="Non-Block-Aligned Length",
                severity="low",
                confidence=0.9,
                description=f"Ciphertext length ({length} bytes) is not a multiple of 8 or 16. This suggests a stream cipher (e.g., ChaCha20, RC4) or CTR/GCM mode."
            ))

        return SymmetricAnalyzeResponse(
            findings=findings,
            block_size_detected=block_size
        )
