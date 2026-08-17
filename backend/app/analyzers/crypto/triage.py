from __future__ import annotations

import re
from pathlib import Path

from app.core.analyzers import BaseAnalyzer
from app.schemas.crypto_triage import (
    CryptoTriageInput,
    CryptoTriageResponse,
    CryptoTriageResult,
)
from app.analyzers.crypto.transforms import (
    decode_base64,
    decode_hex,
)

_PEM_RE = re.compile(rb"-----BEGIN (.*?)-----")


class CryptoTriageAnalyzer(BaseAnalyzer[CryptoTriageInput, CryptoTriageResponse]):
    name = "crypto_triage"
    category = "crypto"

    def supports(self, value: object) -> bool:
        return isinstance(value, CryptoTriageInput)

    def analyze(self, value: CryptoTriageInput) -> CryptoTriageResponse:
        results: list[CryptoTriageResult] = []
        warnings: list[str] = []

        path = Path(value.path)
        try:
            # We only read up to 1MB for triage
            with path.open("rb") as f:
                data = f.read(1024 * 1024)
        except OSError as exc:
            warnings.append(f"Failed to read file for crypto triage: {exc}")
            return CryptoTriageResponse(results=[], warnings=warnings)

        if not data:
            return CryptoTriageResponse(results=[], warnings=warnings)

        compact_text = data.replace(b"\n", b"").replace(b"\r", b"")
        hex_decoded = decode_hex(data)
        b64_decoded = decode_base64(data)

        # 1. Check for OpenSSL
        if data.startswith(b"Salted__"):
            results.append(
                CryptoTriageResult(
                    crypto_type="SYMMETRIC ENCRYPTION",
                    likely_algorithm="OpenSSL Salted Cipher",
                    confidence="CONFIRMED",
                    evidence=["Input starts with raw 'Salted__' magic bytes."],
                    recommended_engine="openssl_enc_decryptor",
                    recommended_next_action="Attempt OpenSSL decryption with provided or derived passwords.",
                )
            )
        elif b64_decoded and b64_decoded.startswith(b"Salted__"):
            results.append(
                CryptoTriageResult(
                    crypto_type="SYMMETRIC ENCRYPTION",
                    likely_algorithm="OpenSSL Salted Cipher (Base64)",
                    confidence="CONFIRMED",
                    evidence=["Base64 decoded bytes contain 'Salted__' magic bytes."],
                    recommended_engine="openssl_enc_decryptor",
                    recommended_next_action="Decode Base64 and attempt OpenSSL decryption.",
                )
            )

        # 2. Check for PEM Keys / Certificates
        pem_match = _PEM_RE.search(data)
        if pem_match:
            header = pem_match.group(1).decode("ascii", errors="ignore")
            crypto_type = "CERTIFICATE" if "CERTIFICATE" in header else "CRYPTOGRAPHIC KEY"
            results.append(
                CryptoTriageResult(
                    crypto_type=crypto_type,
                    likely_algorithm=header,
                    confidence="CONFIRMED",
                    evidence=[f"Found PEM header: -----BEGIN {header}-----"],
                    recommended_engine="crypto_material_analyzer",
                    recommended_next_action="Parse with RSA or X.509 analyzer.",
                )
            )

        # 3. Check for Hashes
        if hex_decoded and len(hex_decoded) in {16, 20, 28, 32, 48, 64}:
            # e.g., MD5 is 16 bytes (32 hex chars), SHA1 is 20, SHA256 is 32
            algo_map = {
                16: "MD5 / NTLM / MD4",
                20: "SHA-1",
                28: "SHA-224 / SHA-3",
                32: "SHA-256 / SHA-3",
                48: "SHA-384",
                64: "SHA-512",
            }
            results.append(
                CryptoTriageResult(
                    crypto_type="HASH",
                    likely_algorithm=algo_map[len(hex_decoded)],
                    confidence="MEDIUM",
                    evidence=[f"Length is exactly {len(compact_text)} hex characters ({len(hex_decoded)} bytes)."],
                    recommended_engine="hash_analyzer",
                    recommended_next_action="Attempt dictionary/wordlist attack or lookup in rainbow tables.",
                )
            )
        
        # 4. Check for bcrypt / common hashes
        if data.startswith(b"$2y$") or data.startswith(b"$2a$") or data.startswith(b"$2b$"):
            results.append(
                CryptoTriageResult(
                    crypto_type="HASH",
                    likely_algorithm="bcrypt",
                    confidence="HIGH",
                    evidence=["Starts with bcrypt hash identifier."],
                    recommended_engine="hash_analyzer",
                    recommended_next_action="Attempt dictionary attack.",
                )
            )

        # 5. Check for Basic Encodings
        if not results:
            if b64_decoded and not b64_decoded.startswith(b"Salted__"):
                results.append(
                    CryptoTriageResult(
                        crypto_type="ENCODING",
                        likely_algorithm="Base64",
                        confidence="HIGH",
                        evidence=["Valid Base64 alphabet and padding."],
                        recommended_engine="recursive_decoder",
                        recommended_next_action="Attempt recursive decoding.",
                    )
                )
            elif hex_decoded and len(hex_decoded) not in {16, 20, 28, 32, 48, 64}:
                results.append(
                    CryptoTriageResult(
                        crypto_type="ENCODING",
                        likely_algorithm="Hexadecimal",
                        confidence="HIGH",
                        evidence=["Valid even-length hexadecimal sequence."],
                        recommended_engine="recursive_decoder",
                        recommended_next_action="Attempt recursive decoding.",
                    )
                )

        if not results:
            results.append(
                CryptoTriageResult(
                    crypto_type="UNKNOWN",
                    likely_algorithm="Unknown",
                    confidence="LOW",
                    evidence=["No obvious magic bytes, known lengths, or encodings detected."],
                    recommended_engine="recursive_decoder",
                    recommended_next_action="Run generic recursive decoding to search for nested flags.",
                )
            )

        return CryptoTriageResponse(results=results, warnings=warnings)
