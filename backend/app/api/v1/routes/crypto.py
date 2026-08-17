from fastapi import APIRouter

from app.schemas.crypto import (
    CryptoAnalyzeRequest,
    CryptoAnalyzeResponse,
    DecodeRequest,
    DecodeResponse,
    OpenSslAnalyzeRequest,
    OpenSslAnalyzeResponse,
    OpenSslDecryptRequest,
    OpenSslDecryptResponse,
    RecipeRequest,
    RecipeResponse,
    RsaDecryptRequest,
    RsaDecryptResponse,
)
from app.services.crypto import CryptoDecodeService, CryptoDecryptService
from app.analyzers.crypto.symmetric import SymmetricAnalyzeInput, SymmetricAnalyzeResponse
from app.analyzers.crypto.stream import StreamAnalyzeInput, StreamAnalyzeResponse
from app.analyzers.crypto.hash import HashAnalyzeInput, HashAnalyzeResponse
from app.analyzers.crypto.custom import CustomAnalyzeInput, CustomAnalyzeResponse

router = APIRouter()
service = CryptoDecodeService()
decrypt_service = CryptoDecryptService()


@router.post("/decode", response_model=DecodeResponse)
async def decode(request: DecodeRequest) -> DecodeResponse:
    """Discover and rank bounded recursive decoding chains."""
    return await service.decode(request)


@router.post("/recipes/run", response_model=RecipeResponse)
async def run_decoder_recipe(request: RecipeRequest) -> RecipeResponse:
    """Run a deterministic decoder recipe and retain every intermediate result."""
    return await service.recipe(request)


@router.post("/decrypt/analyze", response_model=CryptoAnalyzeResponse)
async def analyze_crypto_material(request: CryptoAnalyzeRequest) -> CryptoAnalyzeResponse:
    """Parse RSA material and report evidence-backed compatibility and weaknesses."""
    return await decrypt_service.analyze(request)


@router.post("/decrypt/rsa", response_model=RsaDecryptResponse)
async def rsa_decrypt(request: RsaDecryptRequest) -> RsaDecryptResponse:
    """Decrypt one bounded RSA block with an explicitly selected padding mode."""
    return await decrypt_service.rsa_decrypt(request)


@router.post("/decrypt/openssl/analyze", response_model=OpenSslAnalyzeResponse)
async def analyze_openssl_payload(request: OpenSslAnalyzeRequest) -> OpenSslAnalyzeResponse:
    """Recognize an OpenSSL enc container without requiring its password."""
    return await decrypt_service.openssl_analyze(request)


@router.post("/decrypt/openssl", response_model=OpenSslDecryptResponse)
async def openssl_decrypt(request: OpenSslDecryptRequest) -> OpenSslDecryptResponse:
    """Try a bounded OpenSSL-compatible CBC key-derivation matrix."""
    return await decrypt_service.openssl_decrypt(request)


@router.post("/analyze/symmetric", response_model=SymmetricAnalyzeResponse)
async def analyze_symmetric(request: SymmetricAnalyzeInput) -> SymmetricAnalyzeResponse:
    """Analyze raw ciphertext for symmetric encryption weaknesses."""
    return await decrypt_service.symmetric_analyze(request)


@router.post("/analyze/stream", response_model=StreamAnalyzeResponse)
async def analyze_stream(request: StreamAnalyzeInput) -> StreamAnalyzeResponse:
    """Analyze ciphertexts for stream cipher and repeating XOR vulnerabilities."""
    return await decrypt_service.stream_analyze(request)


@router.post("/analyze/hash", response_model=HashAnalyzeResponse)
async def analyze_hash(request: HashAnalyzeInput) -> HashAnalyzeResponse:
    """Identify hashes and attempt basic dictionary recovery."""
    return await decrypt_service.hash_analyze(request)


@router.post("/analyze/custom", response_model=CustomAnalyzeResponse)
async def analyze_custom(request: CustomAnalyzeInput) -> CustomAnalyzeResponse:
    """Parse custom Python encryption source code using static analysis."""
    return await decrypt_service.custom_analyze(request)
