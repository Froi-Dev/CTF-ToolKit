from typing import Annotated

from fastapi import APIRouter, File, UploadFile

from app.schemas.stego import StegoAnalysisResponse
from app.services.stego import StegoAnalysisService

router = APIRouter()
service = StegoAnalysisService()


@router.post("/analyze", response_model=StegoAnalysisResponse)
async def analyze_image(
    file: Annotated[
        UploadFile,
        File(description="A PNG or JPEG image to inspect for steganographic indicators."),
    ],
) -> StegoAnalysisResponse:
    """Run bounded static steganography analysis on one uploaded image."""
    return await service.analyze(file)
