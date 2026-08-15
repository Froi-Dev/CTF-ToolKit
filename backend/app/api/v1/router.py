from fastapi import APIRouter

from app.api.v1.routes.autotriage import router as autotriage_router
from app.api.v1.routes.crypto import router as crypto_router
from app.api.v1.routes.forensics import router as forensics_router
from app.api.v1.routes.network import router as network_router
from app.api.v1.routes.osint import router as osint_router
from app.api.v1.routes.stego import router as stego_router
from app.api.v1.routes.web import router as web_router

api_router = APIRouter()
api_router.include_router(autotriage_router, prefix="/auto-triage", tags=["auto-triage"])
api_router.include_router(crypto_router, prefix="/crypto", tags=["cryptography"])
api_router.include_router(forensics_router, prefix="/forensics", tags=["forensics"])
api_router.include_router(network_router, prefix="/network", tags=["network"])
api_router.include_router(osint_router, prefix="/osint", tags=["osint"])
api_router.include_router(stego_router, prefix="/stego", tags=["steganography"])
api_router.include_router(web_router, prefix="/web", tags=["web-analysis"])


@api_router.get("/health", tags=["system"])
async def health() -> dict[str, str]:
    return {"status": "ok"}
