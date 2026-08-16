from typing import Annotated

from fastapi import APIRouter, File, Form, UploadFile

from app.schemas.stego import StegoAnalysisResponse
from app.services.stego import StegoAnalysisService

router = APIRouter()
service = StegoAnalysisService()


@router.post("/analyze", response_model=StegoAnalysisResponse)
async def analyze_image(
    file: Annotated[
        UploadFile,
        File(description="A PNG, BMP, GIF, TIFF, lossless WebP, or JPEG image."),
    ],
    show_all: Annotated[
        bool,
        Form(description="Include a small, bounded set of low-value/noise candidates."),
    ] = False,
    deep_scan: Annotated[
        bool,
        Form(description="Run the slower exhaustive traversal and bit-order search."),
    ] = False,
) -> StegoAnalysisResponse:
    """Run bounded static steganography analysis on one uploaded image."""
    return await service.analyze(file, show_all=show_all, deep_scan=deep_scan)
