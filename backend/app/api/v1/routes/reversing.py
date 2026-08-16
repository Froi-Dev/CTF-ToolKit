from typing import Annotated

from fastapi import APIRouter, File, Form, UploadFile

from app.schemas.reversing import ReverseAnalysisResponse
from app.services.reversing import ReverseAnalysisService

router = APIRouter()
service = ReverseAnalysisService()


@router.post("/analyze", response_model=ReverseAnalysisResponse)
async def analyze_artifact(
    file: Annotated[
        UploadFile,
        File(description="A hostile executable, bytecode, or script artifact to inspect statically."),
    ],
    custom_flag_prefix: Annotated[str | None, Form(max_length=32)] = None,
) -> ReverseAnalysisResponse:
    """Run bounded static reverse-engineering triage without executing the artifact."""
    return await service.analyze(file, custom_flag_prefix=custom_flag_prefix)
