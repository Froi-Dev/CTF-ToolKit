from fastapi import APIRouter

from app.schemas.crypto import DecodeRequest, DecodeResponse
from app.services.crypto import CryptoDecodeService

router = APIRouter()
service = CryptoDecodeService()


@router.post("/decode", response_model=DecodeResponse)
async def decode(request: DecodeRequest) -> DecodeResponse:
    """Discover and rank bounded recursive decoding chains."""
    return await service.decode(request)

