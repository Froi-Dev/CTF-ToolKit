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


class ArtifactDetection(BaseModel):
    kind: str
    label: str
    mime: str
    confidence: float = Field(ge=0.0, le=1.0)
    details: dict[str, str | int | bool] = Field(default_factory=dict)
    send_to_decryptor: bool = False


class ByteAnalysis(BaseModel):
    length: int = Field(ge=0)
    entropy: float = Field(ge=0.0, le=8.0)
    printable: float = Field(ge=0.0, le=1.0)
    utf8: bool
    magic: str | None = None


class FlagCandidate(BaseModel):
    value: str
    matched_pattern: str
    source: Literal["request.input", "decryptor.plaintext"] = "request.input"
    offset: int = Field(ge=0)
    confidence: float = Field(ge=0.0, le=1.0)
    context: str
    chain: list[TransformationStep] = Field(default_factory=list)
    state: Literal["candidate"] = "candidate"


class DecodingCandidate(BaseModel):
    output: str
    output_format: Literal["utf-8", "hex"]
    output_base64: str
    output_bytes: int = Field(ge=0)
    output_truncated: bool
    chain: list[TransformationStep]
    score: float = Field(ge=0.0, le=1.0)
    score_breakdown: ScoreBreakdown
    flags: list[FlagCandidate]
    artifacts: list[ArtifactDetection] = Field(default_factory=list)
    analysis: ByteAnalysis


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


RecipeOperationName = Literal[
    "base64",
    "base32",
    "base16",
    "base58",
    "base85",
    "ascii85",
    "hex",
    "binary",
    "octal",
    "decimal-ascii",
    "url",
    "html-entities",
    "unicode-escapes",
    "escaped-bytes",
    "rot13",
    "rot47",
    "caesar",
    "morse",
    "ascii",
    "utf-8",
    "utf-16",
    "xor",
    "gunzip",
]


class RecipeOperation(BaseModel):
    operation: RecipeOperationName
    parameter: str | None = Field(default=None, max_length=256)
    enabled: bool = True


class RecipeRequest(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=False)

    input: Annotated[str, StringConstraints(min_length=1, max_length=65_536)]
    input_encoding: Literal["text", "hex", "base64"] = "text"
    operations: list[RecipeOperation] = Field(min_length=1, max_length=32)
    flag_prefixes: list[str] = Field(
        default_factory=lambda: DEFAULT_FLAG_PREFIXES.copy(), min_length=1, max_length=20
    )


class RecipeIntermediate(BaseModel):
    index: int = Field(ge=0)
    operation: RecipeOperationName
    parameter: str | None = None
    output: str
    output_format: Literal["utf-8", "hex"]
    output_base64: str
    output_bytes: int = Field(ge=0)
    artifacts: list[ArtifactDetection]
    analysis: ByteAnalysis
    flags: list[FlagCandidate]


class RecipeResponse(BaseModel):
    analyzer: Literal["decoder_recipe"] = "decoder_recipe"
    category: Literal["crypto"] = "crypto"
    steps: list[RecipeIntermediate]
    result: RecipeIntermediate


ValueEncoding = Literal["auto", "text", "hex", "base64"]
RsaPadding = Literal["pkcs1v15", "oaep-sha1", "oaep-sha256", "raw"]
OpenSslCipher = Literal[
    "auto",
    "des-cbc",
    "des-ede3-cbc",
    "aes-128-cbc",
    "aes-192-cbc",
    "aes-256-cbc",
]
OpenSslKdf = Literal["auto", "evp-bytes-to-key", "pbkdf2"]
OpenSslDigest = Literal["auto", "md5", "sha256"]
PasswordEncoding = Literal["utf-8", "ascii", "hex", "base64"]
ResolvedOpenSslCipher = Literal[
    "des-cbc", "des-ede3-cbc", "aes-128-cbc", "aes-192-cbc", "aes-256-cbc"
]
ResolvedOpenSslKdf = Literal["evp-bytes-to-key", "pbkdf2"]
ResolvedOpenSslDigest = Literal["md5", "sha256"]


class CryptoMaterial(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=False)

    value: Annotated[str, StringConstraints(min_length=1, max_length=131_072)]
    encoding: ValueEncoding = "auto"


class OpenSslEncryptedMaterial(BaseModel):
    """Bounded textual transport for a binary OpenSSL payload."""

    model_config = ConfigDict(str_strip_whitespace=False)

    value: Annotated[str, StringConstraints(min_length=1, max_length=3_000_000)]
    encoding: ValueEncoding = "auto"


class OpenSslAnalyzeRequest(BaseModel):
    encrypted: OpenSslEncryptedMaterial
    password: str | None = Field(default=None, min_length=1, max_length=4_096)


class OpenSslAnalyzeResponse(BaseModel):
    analyzer: Literal["openssl_enc_analyzer"] = "openssl_enc_analyzer"
    category: Literal["crypto"] = "crypto"
    detected: bool
    format: Literal["openssl-enc", "raw"]
    header: Literal["Salted__"] | None = None
    salt_hex: str | None = None
    total_bytes: int = Field(ge=0)
    encrypted_payload_bytes: int = Field(ge=0)
    structure_valid: bool
    password_supplied: bool
    password_status: Literal["provided", "not-supplied"]
    status: Literal["ready-for-decryption", "password-required", "invalid-payload"]
    message: str


class OpenSslDecryptRequest(BaseModel):
    encrypted: OpenSslEncryptedMaterial
    password: Annotated[str, StringConstraints(min_length=1, max_length=4_096)]
    password_encoding: PasswordEncoding = "utf-8"
    cipher: OpenSslCipher = "auto"
    kdf: OpenSslKdf = "auto"
    digest: OpenSslDigest = "auto"
    iterations: int = Field(default=10_000, ge=1, le=10_000_000)
    flag_prefixes: list[str] = Field(
        default_factory=lambda: DEFAULT_FLAG_PREFIXES.copy(), min_length=1, max_length=20
    )

    @field_validator("flag_prefixes")
    @classmethod
    def validate_openssl_flag_prefixes(cls, values: list[str]) -> list[str]:
        return DecodeRequest.validate_flag_prefixes(values)


class OpenSslDecryptCandidate(BaseModel):
    rank: int = Field(ge=1)
    cipher: ResolvedOpenSslCipher
    cipher_label: str
    kdf: ResolvedOpenSslKdf
    digest: ResolvedOpenSslDigest
    iterations: int | None = Field(default=None, ge=1)
    key_hex: str
    iv_hex: str
    padding_valid: Literal[True] = True
    printable_percentage: float = Field(ge=0.0, le=100.0)
    utf8_valid: bool
    file_magic: str | None = None
    confidence: Literal["LOW", "MEDIUM", "HIGH", "VERY HIGH"]
    score: float = Field(ge=0.0, le=1.0)
    plaintext: str
    plaintext_format: Literal["utf-8", "hex"]
    plaintext_base64: str
    artifacts: list[ArtifactDetection]
    flags: list[FlagCandidate]
    equivalent_command: str | None = None


class OpenSslDecryptResponse(BaseModel):
    analyzer: Literal["openssl_enc_decryptor"] = "openssl_enc_decryptor"
    category: Literal["crypto"] = "crypto"
    status: Literal["success", "rejected"]
    payload: OpenSslAnalyzeResponse
    attempted_variants: int = Field(ge=0)
    candidates: list[OpenSslDecryptCandidate]
    rejection_reason: str | None = None
    possible_causes: list[str] = Field(default_factory=list)


class CryptoFinding(BaseModel):
    title: str
    severity: Literal["critical", "high", "medium", "low", "info"]
    confidence: float = Field(ge=0.0, le=1.0)
    description: str


class RsaKeyInfo(BaseModel):
    key_type: Literal["private", "public"]
    format: Literal["PEM", "DER"]
    modulus_bits: int = Field(gt=0)
    public_exponent: int = Field(gt=0)


class CryptoAnalyzeRequest(BaseModel):
    key: CryptoMaterial
    ciphertext: CryptoMaterial | None = None


class CryptoAnalyzeResponse(BaseModel):
    analyzer: Literal["crypto_material_analyzer"] = "crypto_material_analyzer"
    category: Literal["crypto"] = "crypto"
    key: RsaKeyInfo
    key_artifacts: list[ArtifactDetection]
    ciphertext_artifacts: list[ArtifactDetection]
    ciphertext_bytes: int | None = Field(default=None, ge=0)
    compatible: bool | None = None
    findings: list[CryptoFinding]
    recommended_actions: list[str]


class RsaDecryptRequest(BaseModel):
    private_key: CryptoMaterial
    ciphertext: CryptoMaterial
    padding: RsaPadding = "pkcs1v15"
    password: str | None = Field(default=None, max_length=256)
    label: str | None = Field(default=None, max_length=256)
    flag_prefixes: list[str] = Field(
        default_factory=lambda: DEFAULT_FLAG_PREFIXES.copy(), min_length=1, max_length=20
    )


class RsaDecryptResponse(BaseModel):
    analyzer: Literal["rsa_decryptor"] = "rsa_decryptor"
    category: Literal["crypto"] = "crypto"
    status: Literal["success"] = "success"
    key: RsaKeyInfo
    padding: RsaPadding
    ciphertext_bytes: int = Field(ge=0)
    plaintext: str
    plaintext_format: Literal["utf-8", "hex"]
    plaintext_base64: str
    artifacts: list[ArtifactDetection]
    flags: list[FlagCandidate]
