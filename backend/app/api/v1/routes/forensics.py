from typing import Annotated

from fastapi import APIRouter, File, Form, UploadFile

from app.schemas.audio import AudioAnalysisResponse
from app.schemas.forensics import ForensicsTriageResponse
from app.schemas.disk_forensics import DiskForensicsResponse
from app.services.audio import AudioAnalysisService
from app.services.forensics import ForensicsTriageService
from app.services.disk_forensics import DiskForensicsService

router = APIRouter()
service = ForensicsTriageService()
audio_service = AudioAnalysisService()
disk_service = DiskForensicsService()


@router.post("/triage", response_model=ForensicsTriageResponse)
async def triage_file(
    file: Annotated[
        UploadFile,
        File(description="A hostile artifact to inspect without executing it."),
    ],
) -> ForensicsTriageResponse:
    """Run bounded static file and forensics triage on one uploaded artifact."""
    return await service.triage(file)


@router.post("/audio/analyze", response_model=AudioAnalysisResponse)
async def analyze_audio(
    file: Annotated[
        UploadFile,
        File(description="Hostile audio evidence to inspect without executing embedded content."),
    ],
    raw_sample_rate: Annotated[int | None, Form(ge=1, le=768_000)] = None,
    raw_bit_depth: Annotated[int | None, Form()] = None,
    raw_endianness: Annotated[str | None, Form()] = None,
    raw_channels: Annotated[int | None, Form(ge=1, le=32)] = None,
    raw_signed: Annotated[bool | None, Form()] = None,
    custom_flag_prefix: Annotated[str | None, Form(max_length=32)] = None,
) -> AudioAnalysisResponse:
    """Run bounded audio-forensics triage and return a unified evidence report."""
    return await audio_service.analyze(
        file,
        raw_sample_rate=raw_sample_rate,
        raw_bit_depth=raw_bit_depth,
        raw_endianness=raw_endianness,
        raw_channels=raw_channels,
        raw_signed=raw_signed,
        custom_flag_prefix=custom_flag_prefix,
    )


@router.post("/disk/analyze", response_model=DiskForensicsResponse)
async def analyze_disk(
    file: Annotated[
        UploadFile,
        File(description="A disk image or filesystem image to analyze statically."),
    ],
) -> DiskForensicsResponse:
    """Analyze a disk image for partitions, filesystems, and forensic evidence."""
    return await disk_service.analyze_disk(file)
