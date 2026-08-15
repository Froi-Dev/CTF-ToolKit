from fastapi import APIRouter

from app.schemas.osint import OsintInvestigationRequest, OsintInvestigationResponse
from app.services.osint import OsintService

router = APIRouter()
service = OsintService()


@router.post("/investigate", response_model=OsintInvestigationResponse)
async def investigate(request: OsintInvestigationRequest) -> OsintInvestigationResponse:
    """Collect bounded passive intelligence from public registration and profile sources."""
    return await service.investigate(request)
