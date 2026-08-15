from typing import Annotated

from fastapi import APIRouter, File, UploadFile

from app.schemas.network import NetworkAnalysisResponse
from app.services.network import NetworkAnalysisService

router = APIRouter()
service = NetworkAnalysisService()


@router.post("/analyze", response_model=NetworkAnalysisResponse)
async def analyze_capture(
    file: Annotated[
        UploadFile,
        File(description="A PCAP or PCAPNG artifact to decode with TShark."),
    ],
) -> NetworkAnalysisResponse:
    """Decode and inspect one bounded offline packet capture."""
    return await service.analyze(file)
