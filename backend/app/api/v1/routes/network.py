from typing import Annotated

from fastapi import APIRouter, File, Form, HTTPException, UploadFile

from app.schemas.network import NetworkAnalysisProgress, NetworkAnalysisResponse
from app.services.network import NetworkAnalysisService

router = APIRouter()
service = NetworkAnalysisService()


@router.post("/analyze", response_model=NetworkAnalysisResponse)
async def analyze_capture(
    file: Annotated[
        UploadFile,
        File(description="A PCAP or PCAPNG artifact to decode with TShark."),
    ],
    custom_flag_prefix: Annotated[
        str | None,
        Form(
            description="Optional literal flag prefix, with or without the opening brace.",
            max_length=65,
        ),
    ] = None,
    progress_id: Annotated[
        str | None,
        Form(description="Optional UUID used to poll honest analysis stage progress.", max_length=36),
    ] = None,
) -> NetworkAnalysisResponse:
    """Decode and inspect one bounded offline packet capture."""
    return await service.analyze(file, custom_flag_prefix, progress_id)


@router.get("/progress/{progress_id}", response_model=NetworkAnalysisProgress)
def analysis_progress(progress_id: str) -> NetworkAnalysisProgress:
    progress = service.get_progress(progress_id)
    if progress is None:
        raise HTTPException(status_code=404, detail="Analysis progress was not found.")
    return progress
