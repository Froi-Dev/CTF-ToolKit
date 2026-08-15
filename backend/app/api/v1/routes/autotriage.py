from typing import Annotated

from fastapi import APIRouter, File, UploadFile

from app.schemas.autotriage import AutoTriageResponse
from app.services.autotriage import AutoTriageService

router = APIRouter()
service = AutoTriageService()


@router.post("/analyze", response_model=AutoTriageResponse)
async def analyze_artifact(
    file: Annotated[
        UploadFile,
        File(description="A hostile artifact to classify and inspect without executing it."),
    ],
) -> AutoTriageResponse:
    """Select and run the applicable bounded static analyzers for one artifact."""
    return await service.analyze(file)

