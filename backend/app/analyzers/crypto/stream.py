from __future__ import annotations

from typing import Literal
from pydantic import BaseModel
from app.core.analyzers import BaseAnalyzer

class StreamAnalyzeInput(BaseModel):
    ciphertexts: list[bytes]
    cribs: list[bytes] = []

class StreamFinding(BaseModel):
    title: str
    severity: Literal["critical", "high", "medium", "low", "info"]
    confidence: float
    description: str

class StreamAnalyzeResponse(BaseModel):
    analyzer: Literal["stream_analyzer"] = "stream_analyzer"
    category: Literal["crypto"] = "crypto"
    findings: list[StreamFinding]
    estimated_xor_key_lengths: list[int]
    recovered_keystream: bytes | None

def _hamming_distance(b1: bytes, b2: bytes) -> int:
    return sum(bin(x ^ y).count('1') for x, y in zip(b1, b2))

class StreamAnalyzer(BaseAnalyzer[StreamAnalyzeInput, StreamAnalyzeResponse]):
    name = "stream_analyzer"
    category = "crypto"

    def supports(self, value: object) -> bool:
        return isinstance(value, StreamAnalyzeInput)

    def analyze(self, value: StreamAnalyzeInput) -> StreamAnalyzeResponse:
        findings = []
        key_lengths = []
        recovered_keystream = None

        if not value.ciphertexts:
            return StreamAnalyzeResponse(findings=[], estimated_xor_key_lengths=[], recovered_keystream=None)

        if len(value.ciphertexts) > 1:
            findings.append(StreamFinding(
                title="Multiple Ciphertexts Supplied",
                severity="info",
                confidence=1.0,
                description="Checking for keystream reuse (Many-Time Pad attack)."
            ))
            # Check if any two ciphertexts have the same length and are identical (exact reuse)
            # Or if we can crib drag
            if len(value.cribs) > 0:
                c1 = value.ciphertexts[0]
                crib = value.cribs[0]
                if len(c1) >= len(crib):
                    # Known Plaintext XOR to recover keystream
                    keystream_part = bytes(c ^ p for c, p in zip(c1[:len(crib)], crib))
                    recovered_keystream = keystream_part
                    findings.append(StreamFinding(
                        title="Keystream Recovered via Crib",
                        severity="high",
                        confidence=0.95,
                        description=f"Recovered {len(keystream_part)} bytes of keystream using the provided crib."
                    ))

        # Single ciphertext repeating key XOR analysis
        c = value.ciphertexts[0]
        if len(c) >= 10:
            distances = []
            for keysize in range(2, min(40, len(c) // 2)):
                blocks = [c[i:i+keysize] for i in range(0, len(c), keysize)][:4]
                if len(blocks) >= 2:
                    dist = sum(_hamming_distance(blocks[i], blocks[i+1]) for i in range(len(blocks)-1))
                    normalized = dist / (keysize * (len(blocks)-1))
                    distances.append((normalized, keysize))
            
            distances.sort(key=lambda x: x[0])
            key_lengths = [k for _, k in distances[:3]]
            if key_lengths:
                findings.append(StreamFinding(
                    title="Repeating-Key XOR Detected",
                    severity="medium",
                    confidence=0.8,
                    description=f"Hamming distance analysis suggests repeating XOR key lengths: {key_lengths}"
                ))

        return StreamAnalyzeResponse(
            findings=findings,
            estimated_xor_key_lengths=key_lengths,
            recovered_keystream=recovered_keystream
        )
