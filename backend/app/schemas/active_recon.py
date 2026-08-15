"""Schemas for the Active Web CTF recon subsystem."""

from __future__ import annotations

from datetime import datetime
from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field, HttpUrl, StringConstraints, field_validator, model_validator


BoundedText = Annotated[str, StringConstraints(max_length=16_384)]


# ---------------------------------------------------------------------------
# Request models
# ---------------------------------------------------------------------------

class ActiveReconRequest(BaseModel):
    """Top-level request to launch a full active-recon scan."""

    model_config = ConfigDict(str_strip_whitespace=True)

    url: HttpUrl
    target_scope: Literal["ctf", "lab", "owned"]
    authorization_confirmed: bool
    active_testing_confirmed: bool

    # Crawl settings
    enable_crawl: bool = True
    crawl_depth: int = Field(default=3, ge=1, le=10)
    crawl_max_pages: int = Field(default=50, ge=1, le=500)

    # Dir bust settings
    enable_dirbust: bool = True
    dirbust_wordlist: Literal["common", "medium", "small"] = "small"
    dirbust_extensions: list[str] = Field(default_factory=lambda: [".php", ".html", ".txt", ".bak", ".old", ".js"])
    dirbust_concurrency: int = Field(default=10, ge=1, le=50)
    dirbust_status_filter: list[int] = Field(default_factory=lambda: [200, 201, 204, 301, 302, 307, 401, 403])

    # Parameter fuzzing settings
    enable_param_fuzz: bool = True

    # Browser / DOM settings
    enable_browser: bool = True
    browser_timeout_ms: int = Field(default=15_000, ge=3_000, le=60_000)

    # XSS settings
    enable_xss: bool = True

    # Flag detection
    flag_patterns: list[str] = Field(
        default_factory=lambda: [
            r"CTF\{[^}]+\}",
            r"FLAG\{[^}]+\}",
            r"flag\{[^}]+\}",
            r"THM\{[^}]+\}",
            r"DICT\{[^}]+\}",
            r"H4G\{[^}]+\}",
        ]
    )

    # General
    headers: dict[str, BoundedText] = Field(default_factory=dict)
    cookies: dict[str, BoundedText] = Field(default_factory=dict)
    timeout_ms: int = Field(default=8_000, ge=1_000, le=30_000)
    rate_limit_rps: float = Field(default=10.0, ge=1.0, le=100.0)

    @model_validator(mode="after")
    def require_confirmations(self) -> "ActiveReconRequest":
        if not self.authorization_confirmed:
            raise ValueError("authorization_confirmed must be true for active web recon")
        if not self.active_testing_confirmed:
            raise ValueError("active_testing_confirmed must be true — active testing modifies request patterns sent to the target")
        return self

    @field_validator("headers")
    @classmethod
    def validate_headers(cls, values: dict[str, str]) -> dict[str, str]:
        if len(values) > 32:
            raise ValueError("at most 32 request headers are allowed")
        forbidden = {"host", "content-length", "transfer-encoding", "connection", "proxy-authorization"}
        for name, value in values.items():
            if not name.strip() or name.strip().lower() in forbidden:
                raise ValueError(f"request header {name!r} is not allowed")
            if any(c in name + value for c in "\r\n\0"):
                raise ValueError("request headers cannot contain control-line characters")
        return values

    @field_validator("cookies")
    @classmethod
    def validate_cookies(cls, values: dict[str, str]) -> dict[str, str]:
        if len(values) > 32:
            raise ValueError("at most 32 cookies are allowed")
        for name, value in values.items():
            if not name.strip() or any(c in name + value for c in "\r\n\0;"):
                raise ValueError("cookie names and values must be valid single-line values")
        return values

    @field_validator("dirbust_extensions")
    @classmethod
    def validate_extensions(cls, values: list[str]) -> list[str]:
        if len(values) > 20:
            raise ValueError("at most 20 extensions are allowed")
        return [ext if ext.startswith(".") else f".{ext}" for ext in values]

    @field_validator("flag_patterns")
    @classmethod
    def validate_patterns(cls, values: list[str]) -> list[str]:
        if len(values) > 20:
            raise ValueError("at most 20 flag patterns are allowed")
        return values


# ---------------------------------------------------------------------------
# Standalone request models for individual operations
# ---------------------------------------------------------------------------

class CrawlRequest(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True)
    url: HttpUrl
    target_scope: Literal["ctf", "lab", "owned"]
    authorization_confirmed: bool
    active_testing_confirmed: bool
    depth: int = Field(default=3, ge=1, le=10)
    max_pages: int = Field(default=50, ge=1, le=500)
    headers: dict[str, BoundedText] = Field(default_factory=dict)
    cookies: dict[str, BoundedText] = Field(default_factory=dict)
    timeout_ms: int = Field(default=8_000, ge=1_000, le=30_000)

    @model_validator(mode="after")
    def require_confirmations(self) -> "CrawlRequest":
        if not self.authorization_confirmed or not self.active_testing_confirmed:
            raise ValueError("both authorization_confirmed and active_testing_confirmed must be true")
        return self


class DirBustRequest(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True)
    url: HttpUrl
    target_scope: Literal["ctf", "lab", "owned"]
    authorization_confirmed: bool
    active_testing_confirmed: bool
    wordlist: Literal["common", "medium", "small"] = "small"
    extensions: list[str] = Field(default_factory=lambda: [".php", ".html", ".txt", ".bak"])
    concurrency: int = Field(default=10, ge=1, le=50)
    status_filter: list[int] = Field(default_factory=lambda: [200, 201, 204, 301, 302, 307, 401, 403])
    headers: dict[str, BoundedText] = Field(default_factory=dict)
    cookies: dict[str, BoundedText] = Field(default_factory=dict)
    timeout_ms: int = Field(default=8_000, ge=1_000, le=30_000)
    rate_limit_rps: float = Field(default=10.0, ge=1.0, le=100.0)

    @model_validator(mode="after")
    def require_confirmations(self) -> "DirBustRequest":
        if not self.authorization_confirmed or not self.active_testing_confirmed:
            raise ValueError("both authorization_confirmed and active_testing_confirmed must be true")
        return self


class XssScanRequest(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True)
    url: HttpUrl
    target_scope: Literal["ctf", "lab", "owned"]
    authorization_confirmed: bool
    active_testing_confirmed: bool
    headers: dict[str, BoundedText] = Field(default_factory=dict)
    cookies: dict[str, BoundedText] = Field(default_factory=dict)
    browser_timeout_ms: int = Field(default=15_000, ge=3_000, le=60_000)
    timeout_ms: int = Field(default=8_000, ge=1_000, le=30_000)

    @model_validator(mode="after")
    def require_confirmations(self) -> "XssScanRequest":
        if not self.authorization_confirmed or not self.active_testing_confirmed:
            raise ValueError("both authorization_confirmed and active_testing_confirmed must be true")
        return self


class BrowserRenderRequest(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True)
    url: HttpUrl
    target_scope: Literal["ctf", "lab", "owned"]
    authorization_confirmed: bool
    headers: dict[str, BoundedText] = Field(default_factory=dict)
    cookies: dict[str, BoundedText] = Field(default_factory=dict)
    timeout_ms: int = Field(default=15_000, ge=3_000, le=60_000)
    flag_patterns: list[str] = Field(
        default_factory=lambda: [r"CTF\{[^}]+\}", r"FLAG\{[^}]+\}", r"flag\{[^}]+\}", r"THM\{[^}]+\}", r"DICT\{[^}]+\}"]
    )

    @model_validator(mode="after")
    def require_authorization(self) -> "BrowserRenderRequest":
        if not self.authorization_confirmed:
            raise ValueError("authorization_confirmed must be true")
        return self


# ---------------------------------------------------------------------------
# Result / response models
# ---------------------------------------------------------------------------

class CrawledPage(BaseModel):
    url: str
    status_code: int
    content_type: str | None = None
    title: str | None = None
    size: int = Field(default=0, ge=0)
    depth: int = Field(ge=0)
    links: list[str] = Field(default_factory=list)
    forms: list[CrawledForm] = Field(default_factory=list)
    parameters: list[str] = Field(default_factory=list)
    elapsed_ms: int = Field(default=0, ge=0)


class CrawledForm(BaseModel):
    action: str
    method: str
    inputs: list[FormInput] = Field(default_factory=list)


class FormInput(BaseModel):
    name: str
    input_type: str
    value: str | None = None


class CrawlResult(BaseModel):
    pages: list[CrawledPage] = Field(default_factory=list)
    total_pages: int = 0
    max_depth_reached: int = 0
    total_forms: int = 0
    total_links: int = 0
    elapsed_ms: int = Field(default=0, ge=0)


class DirBustEntry(BaseModel):
    path: str
    url: str
    status_code: int
    content_type: str | None = None
    size: int = Field(default=0, ge=0)
    redirect_url: str | None = None
    elapsed_ms: int = Field(default=0, ge=0)


class DirBustResult(BaseModel):
    entries: list[DirBustEntry] = Field(default_factory=list)
    total_tested: int = 0
    total_found: int = 0
    wordlist_used: str = ""
    extensions_used: list[str] = Field(default_factory=list)
    elapsed_ms: int = Field(default=0, ge=0)


class ParamFuzzEntry(BaseModel):
    parameter: str
    url: str
    canary: str
    reflected: bool = False
    reflection_context: str | None = None  # html_body, html_attr, script, comment, url
    response_status: int = 0
    response_size: int = 0
    baseline_similarity: float = Field(default=1.0, ge=0.0, le=1.0)


class ParamFuzzResult(BaseModel):
    entries: list[ParamFuzzEntry] = Field(default_factory=list)
    total_tested: int = 0
    total_reflected: int = 0
    elapsed_ms: int = Field(default=0, ge=0)


class ConsoleEntry(BaseModel):
    level: Literal["log", "info", "warn", "error", "debug"] = "log"
    text: str
    timestamp: str | None = None


class NetworkEntry(BaseModel):
    method: str
    url: str
    status_code: int | None = None
    content_type: str | None = None
    size: int = Field(default=0, ge=0)
    elapsed_ms: int = Field(default=0, ge=0)


class StorageEntry(BaseModel):
    storage_type: Literal["cookie", "localStorage", "sessionStorage"]
    key: str
    value: str


class BrowserCapture(BaseModel):
    url: str
    final_url: str
    title: str | None = None
    dom_snapshot: str | None = None
    console_log: list[ConsoleEntry] = Field(default_factory=list)
    network_log: list[NetworkEntry] = Field(default_factory=list)
    storage: list[StorageEntry] = Field(default_factory=list)
    screenshot_base64: str | None = None
    errors: list[str] = Field(default_factory=list)
    elapsed_ms: int = Field(default=0, ge=0)


class XssFinding(BaseModel):
    finding_type: Literal["reflected", "dom"]
    severity: Literal["high", "medium", "low", "info"]
    parameter: str
    url: str
    canary: str
    injection_context: str | None = None  # html_body, html_attr, script, comment, url, dom_sink
    evidence: str = ""
    dom_sink: str | None = None  # innerHTML, document.write, eval, etc.
    suggestion: str = ""


class XssScanResult(BaseModel):
    findings: list[XssFinding] = Field(default_factory=list)
    parameters_tested: int = 0
    total_reflected: int = 0
    total_dom: int = 0
    elapsed_ms: int = Field(default=0, ge=0)


class FlagMatch(BaseModel):
    pattern: str
    value: str
    source: str  # response_body, dom, console, cookie, localStorage, sessionStorage, script, header
    url: str = ""
    context: str = ""


class FlagResult(BaseModel):
    matches: list[FlagMatch] = Field(default_factory=list)
    patterns_used: list[str] = Field(default_factory=list)


class ScanProgress(BaseModel):
    scan_id: str
    status: Literal["running", "completed", "failed", "stopped"]
    phase: str = ""
    progress_pct: float = Field(default=0.0, ge=0.0, le=100.0)
    pages_crawled: int = 0
    paths_tested: int = 0
    xss_checks: int = 0
    flags_found: int = 0
    elapsed_ms: int = Field(default=0, ge=0)
    message: str = ""


class ActiveReconResponse(BaseModel):
    scan_id: str
    target_url: str
    target_scope: Literal["ctf", "lab", "owned"]
    status: Literal["completed", "failed", "stopped"]
    crawl: CrawlResult | None = None
    dirbust: DirBustResult | None = None
    param_fuzz: ParamFuzzResult | None = None
    browser: BrowserCapture | None = None
    xss: XssScanResult | None = None
    flags: FlagResult | None = None
    warnings: list[str] = Field(default_factory=list)
    elapsed_ms: int = Field(default=0, ge=0)
    started_at: datetime | None = None
    completed_at: datetime | None = None


# Resolve forward references
CrawledPage.model_rebuild()
