from __future__ import annotations

import hashlib
import bcrypt
from typing import Literal
from pydantic import BaseModel
from app.core.analyzers import BaseAnalyzer

COMMON_PASSWORDS = [
    b"password", b"123456", b"12345678", b"1234", b"qwerty",
    b"admin", b"root", b"picoCTF", b"flag", b"crypto", b"letmein",
    b"password123", b"test", b"guest"
]

class HashAnalyzeInput(BaseModel):
    hash_str: str

class HashFinding(BaseModel):
    title: str
    severity: Literal["critical", "high", "medium", "low", "info"]
    confidence: float
    description: str

class HashAnalyzeResponse(BaseModel):
    analyzer: Literal["hash_analyzer"] = "hash_analyzer"
    category: Literal["crypto"] = "crypto"
    findings: list[HashFinding]
    cracked_plaintext: str | None
    algorithm: str | None

class HashAnalyzer(BaseAnalyzer[HashAnalyzeInput, HashAnalyzeResponse]):
    name = "hash_analyzer"
    category = "crypto"

    def supports(self, value: object) -> bool:
        return isinstance(value, HashAnalyzeInput)

    def analyze(self, value: HashAnalyzeInput) -> HashAnalyzeResponse:
        findings = []
        cracked = None
        algo = None

        h = value.hash_str.strip()
        h_bytes = h.encode('ascii', errors='ignore')
        
        if h_bytes.startswith(b"$2"):
            algo = "bcrypt"
            # attempt crack
            for pw in COMMON_PASSWORDS:
                try:
                    if bcrypt.checkpw(pw, h_bytes):
                        cracked = pw.decode('ascii')
                        break
                except ValueError:
                    pass
        elif len(h) == 32:
            algo = "MD5"
            h = h.lower()
            for pw in COMMON_PASSWORDS:
                if hashlib.md5(pw).hexdigest() == h:
                    cracked = pw.decode('ascii')
                    break
        elif len(h) == 40:
            algo = "SHA-1"
            h = h.lower()
            for pw in COMMON_PASSWORDS:
                if hashlib.sha1(pw).hexdigest() == h:
                    cracked = pw.decode('ascii')
                    break
        elif len(h) == 64:
            algo = "SHA-256"
            h = h.lower()
            for pw in COMMON_PASSWORDS:
                if hashlib.sha256(pw).hexdigest() == h:
                    cracked = pw.decode('ascii')
                    break
        elif len(h) == 128:
            algo = "SHA-512"
            h = h.lower()
            for pw in COMMON_PASSWORDS:
                if hashlib.sha512(pw).hexdigest() == h:
                    cracked = pw.decode('ascii')
                    break
                    
        if algo:
            findings.append(HashFinding(
                title=f"Hash Identified: {algo}",
                severity="info",
                confidence=0.9,
                description=f"The hash matches the length/format of {algo}."
            ))
            
        if cracked:
            findings.append(HashFinding(
                title="Hash Cracked!",
                severity="critical",
                confidence=1.0,
                description=f"The hash was successfully cracked using dictionary attack. Plaintext: {cracked}"
            ))

        return HashAnalyzeResponse(
            findings=findings,
            cracked_plaintext=cracked,
            algorithm=algo
        )
