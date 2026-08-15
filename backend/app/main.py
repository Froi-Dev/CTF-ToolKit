from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from app.api.v1.router import api_router
from app.core.errors import (
    ArtifactTooLargeError,
    DecoderInputError,
    InvalidArtifactError,
    InvalidOsintTargetError,
    ToolExecutionError,
    ToolNotAvailableError,
    UnsafeWebTargetError,
    WebRequestError,
)

app = FastAPI(title="CTFKit API", version="0.1.0")
app.add_middleware(
    CORSMiddleware,
    allow_origin_regex=r"^https?://(?:localhost|127\.0\.0\.1)(?::\d+)?$",
    allow_credentials=False,
    allow_methods=["GET", "POST"],
    allow_headers=["Content-Type"],
)
app.include_router(api_router, prefix="/api/v1")


@app.exception_handler(RequestValidationError)
async def validation_error_handler(
    request: Request, exc: RequestValidationError
) -> JSONResponse:
    del request
    fields = [
        {
            key: value
            for key, value in error.items()
            if key not in {"ctx", "input", "url"}
        }
        for error in exc.errors()
    ]
    return JSONResponse(
        status_code=422,
        content={
            "error": {
                "code": "VALIDATION_ERROR",
                "message": "The request payload is invalid.",
                "details": {"fields": fields},
            }
        },
    )


@app.exception_handler(DecoderInputError)
async def decoder_input_error_handler(
    request: Request, exc: DecoderInputError
) -> JSONResponse:
    del request
    return JSONResponse(
        status_code=400,
        content={
            "error": {
                "code": "INVALID_DECODER_OPTION",
                "message": str(exc),
                "details": {},
            }
        },
    )


@app.exception_handler(ArtifactTooLargeError)
async def artifact_too_large_handler(
    request: Request, exc: ArtifactTooLargeError
) -> JSONResponse:
    del request
    return JSONResponse(
        status_code=413,
        content={
            "error": {
                "code": "ARTIFACT_TOO_LARGE",
                "message": str(exc),
                "details": {"max_bytes": exc.maximum_bytes},
            }
        },
    )


@app.exception_handler(InvalidArtifactError)
async def invalid_artifact_handler(
    request: Request, exc: InvalidArtifactError
) -> JSONResponse:
    del request
    return JSONResponse(
        status_code=400,
        content={
            "error": {
                "code": "INVALID_ARTIFACT",
                "message": str(exc),
                "details": {},
            }
        },
    )


@app.exception_handler(ToolNotAvailableError)
async def tool_not_available_handler(
    request: Request, exc: ToolNotAvailableError
) -> JSONResponse:
    del request
    return JSONResponse(
        status_code=503,
        content={
            "error": {
                "code": "TOOL_NOT_AVAILABLE",
                "message": str(exc),
                "details": {"tool": exc.tool},
            }
        },
    )


@app.exception_handler(ToolExecutionError)
async def tool_execution_error_handler(
    request: Request, exc: ToolExecutionError
) -> JSONResponse:
    del request
    return JSONResponse(
        status_code=504 if exc.timed_out else 502,
        content={
            "error": {
                "code": "TOOL_TIMEOUT" if exc.timed_out else "TOOL_EXECUTION_FAILED",
                "message": str(exc),
                "details": {"tool": exc.tool},
            }
        },
    )


@app.exception_handler(UnsafeWebTargetError)
async def unsafe_web_target_handler(
    request: Request, exc: UnsafeWebTargetError
) -> JSONResponse:
    del request
    return JSONResponse(
        status_code=400,
        content={
            "error": {
                "code": "UNSAFE_WEB_TARGET",
                "message": str(exc),
                "details": {},
            }
        },
    )


@app.exception_handler(WebRequestError)
async def web_request_error_handler(
    request: Request, exc: WebRequestError
) -> JSONResponse:
    del request
    return JSONResponse(
        status_code=504 if exc.timed_out else 502,
        content={
            "error": {
                "code": "WEB_REQUEST_TIMEOUT" if exc.timed_out else "WEB_REQUEST_FAILED",
                "message": str(exc),
                "details": {},
            }
        },
    )


@app.exception_handler(InvalidOsintTargetError)
async def invalid_osint_target_handler(
    request: Request, exc: InvalidOsintTargetError
) -> JSONResponse:
    del request
    return JSONResponse(
        status_code=400,
        content={
            "error": {
                "code": "INVALID_OSINT_TARGET",
                "message": str(exc),
                "details": {},
            }
        },
    )
