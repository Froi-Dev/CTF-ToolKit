from typing import Annotated

from fastapi import APIRouter, File, UploadFile

from app.schemas.forensics import ForensicsTriageResponse
from app.services.forensics import ForensicsTriageService

router = APIRouter()
service = ForensicsTriageService()


@router.post("/triage", response_model=ForensicsTriageResponse)
async def triage_file(
    file: Annotated[
        UploadFile,
        File(description="A hostile artifact to inspect without executing it."),
    ],
) -> ForensicsTriageResponse:
    """Run bounded static file and forensics triage on one uploaded artifact."""
    return await service.triage(file)
