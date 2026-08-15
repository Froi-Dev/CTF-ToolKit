from fastapi import APIRouter

from app.schemas.active_recon import (
    ActiveReconRequest,
    ActiveReconResponse,
    BrowserCapture,
    BrowserRenderRequest,
    CrawlRequest,
    CrawlResult,
    DirBustRequest,
    DirBustResult,
    ScanProgress,
    XssScanRequest,
    XssScanResult,
)
from app.schemas.web import WebAnalysisRequest, WebAnalysisResponse
from app.services import active_recon as recon_service
from app.services import browser_engine
from app.services.web import WebAnalysisService
from app.services.xss_analyzer import run_xss_scan

router = APIRouter()
service = WebAnalysisService()


@router.post("/analyze", response_model=WebAnalysisResponse)
async def analyze_web_target(request: WebAnalysisRequest) -> WebAnalysisResponse:
    """Passively inspect one explicitly authorized CTF, lab, or owned Web target."""
    return await service.analyze(request)


@router.post("/active-recon", response_model=ActiveReconResponse)
async def active_recon(request: ActiveReconRequest) -> ActiveReconResponse:
    """Launch a full active recon scan with crawl, dir bust, param fuzz, browser, and XSS."""
    return await recon_service.run_active_recon(
        str(request.url),
        target_scope=request.target_scope,
        enable_crawl=request.enable_crawl,
        crawl_depth=request.crawl_depth,
        crawl_max_pages=request.crawl_max_pages,
        enable_dirbust=request.enable_dirbust,
        dirbust_wordlist=request.dirbust_wordlist,
        dirbust_extensions=request.dirbust_extensions,
        dirbust_concurrency=request.dirbust_concurrency,
        dirbust_status_filter=request.dirbust_status_filter,
        rate_limit_rps=request.rate_limit_rps,
        enable_param_fuzz=request.enable_param_fuzz,
        enable_browser=request.enable_browser,
        browser_timeout_ms=request.browser_timeout_ms,
        enable_xss=request.enable_xss,
        flag_patterns=request.flag_patterns,
        headers=request.headers,
        cookies=request.cookies,
        timeout_ms=request.timeout_ms,
    )


@router.post("/crawl", response_model=CrawlResult)
async def crawl_target(request: CrawlRequest) -> CrawlResult:
    """Standalone same-origin recursive crawl."""
    return await recon_service.crawl(
        str(request.url),
        depth=request.depth,
        max_pages=request.max_pages,
        headers=request.headers,
        cookies=request.cookies,
        timeout_ms=request.timeout_ms,
    )


@router.post("/dirbust", response_model=DirBustResult)
async def dirbust_target(request: DirBustRequest) -> DirBustResult:
    """Standalone rate-limited directory and file discovery."""
    return await recon_service.dirbust(
        str(request.url),
        wordlist=request.wordlist,
        extensions=request.extensions,
        concurrency=request.concurrency,
        status_filter=request.status_filter,
        rate_limit_rps=request.rate_limit_rps,
        headers=request.headers,
        cookies=request.cookies,
        timeout_ms=request.timeout_ms,
    )


@router.post("/xss-scan", response_model=XssScanResult)
async def xss_scan(request: XssScanRequest) -> XssScanResult:
    """Standalone XSS analysis — discovers parameters then tests for reflected and DOM XSS."""
    # First crawl to discover parameters
    crawl_result = await recon_service.crawl(
        str(request.url), depth=1, max_pages=5,
        headers=request.headers, cookies=request.cookies,
        timeout_ms=request.timeout_ms,
    )
    parameters = list(dict.fromkeys(
        param for page in crawl_result.pages for param in page.parameters
    ))
    if not parameters:
        return XssScanResult(parameters_tested=0)

    return await run_xss_scan(
        str(request.url), parameters,
        headers=request.headers, cookies=request.cookies,
        timeout_ms=request.timeout_ms,
        browser_timeout_ms=request.browser_timeout_ms,
        enable_dom=browser_engine.is_available(),
    )


@router.post("/browser-render", response_model=BrowserCapture)
async def browser_render(request: BrowserRenderRequest) -> BrowserCapture:
    """Single-page browser render with full evidence capture."""
    from app.services.flag_detector import FlagDetector, _TextSource

    capture = await browser_engine.render_page(
        str(request.url),
        headers=request.headers,
        cookies=request.cookies,
        timeout_ms=request.timeout_ms,
    )

    return capture


@router.get("/active-recon/{scan_id}/status", response_model=ScanProgress | None)
async def get_scan_status(scan_id: str) -> ScanProgress | dict[str, str]:
    """Poll progress of a running active recon scan."""
    progress = recon_service.get_scan_progress(scan_id)
    if progress is None:
        return {"error": "Scan not found"}
    return progress


@router.get("/active-recon/{scan_id}/results", response_model=ActiveReconResponse | None)
async def get_scan_results(scan_id: str) -> ActiveReconResponse | dict[str, str]:
    """Get final results of a completed active recon scan."""
    result = recon_service.get_scan_result(scan_id)
    if result is None:
        return {"error": "Scan not found or not yet completed"}
    return result
