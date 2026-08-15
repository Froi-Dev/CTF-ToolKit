from fastapi import APIRouter

from app.schemas.crypto import (
    CryptoAnalyzeRequest,
    CryptoAnalyzeResponse,
    DecodeRequest,
    DecodeResponse,
    RecipeRequest,
    RecipeResponse,
    RsaDecryptRequest,
    RsaDecryptResponse,
)
from app.services.crypto import CryptoDecodeService, CryptoDecryptService

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
