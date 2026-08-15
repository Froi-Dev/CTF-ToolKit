from __future__ import annotations

from datetime import datetime
from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field, HttpUrl, StringConstraints, field_validator, model_validator


BoundedText = Annotated[str, StringConstraints(max_length=16_384)]


class WebAnalysisRequest(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True)

    url: HttpUrl
    target_scope: Literal["ctf", "lab", "owned"]
    authorization_confirmed: bool
    method: Literal["GET", "HEAD"] = "GET"
    headers: dict[str, BoundedText] = Field(default_factory=dict)
    cookies: dict[str, BoundedText] = Field(default_factory=dict)
    fetch_robots: bool = True
    fetch_sitemap: bool = True
    fetch_javascript: bool = True
    compare_without_auth: bool = False
    timeout_ms: int = Field(default=8_000, ge=1_000, le=15_000)

    @model_validator(mode="after")
    def require_authorization(self) -> "WebAnalysisRequest":
        if not self.authorization_confirmed:
            raise ValueError("authorization_confirmed must be true for active web analysis")
        return self

    @field_validator("headers")
    @classmethod
    def validate_headers(cls, values: dict[str, str]) -> dict[str, str]:
        if len(values) > 32:
            raise ValueError("at most 32 request headers are allowed")
        forbidden = {"host", "content-length", "transfer-encoding", "connection", "proxy-authorization"}
        clean: dict[str, str] = {}
        for name, value in values.items():
            normalized = name.strip()
            if not normalized or normalized.lower() in forbidden:
                raise ValueError(f"request header {name!r} is not allowed")
            if any(character in normalized + value for character in "\r\n\0"):
                raise ValueError("request headers cannot contain control-line characters")
            clean[normalized] = value
        return clean

    @field_validator("cookies")
    @classmethod
    def validate_cookies(cls, values: dict[str, str]) -> dict[str, str]:
        if len(values) > 32:
            raise ValueError("at most 32 cookies are allowed")
        for name, value in values.items():
            if not name.strip() or any(character in name + value for character in "\r\n\0;"):
                raise ValueError("cookie names and values must be valid single-line values")
        return values


class HeaderRecord(BaseModel):
    name: str
    value: str


class HttpExchange(BaseModel):
    url: str
    method: str
    status_code: int
    reason_phrase: str
    elapsed_ms: int = Field(ge=0)
    request_headers: list[HeaderRecord]
    response_headers: list[HeaderRecord]
    content_type: str | None
    body_bytes: int = Field(ge=0)
    body_truncated: bool
    redirect_chain: list[str]


class HeaderAssessment(BaseModel):
    name: str
    value: str | None
    source: Literal["request", "response"]
    status: Literal["present", "missing", "informational", "warning"]
    note: str


class CookieRecord(BaseModel):
    name: str
    value: str
    source: Literal["request", "response"]
    domain: str | None = None
    path: str | None = None
    secure: bool = False
    http_only: bool = False
    same_site: str | None = None
    expires: str | None = None
    issues: list[str] = Field(default_factory=list)


class DiscoveryDocument(BaseModel):
    kind: Literal["robots", "sitemap", "javascript", "source-map"]
    url: str
    status_code: int | None
    content_type: str | None = None
    size: int = Field(default=0, ge=0)
    truncated: bool = False
    error: str | None = None


class CommentRecord(BaseModel):
    source: str
    line: int = Field(ge=1)
    text: str


class ScriptRecord(BaseModel):
    url: str | None
    inline: bool
    status_code: int | None = None
    size: int = Field(default=0, ge=0)
    source_maps: list[str] = Field(default_factory=list)


class EndpointRecord(BaseModel):
    url: str
    path: str
    method: str
    parameters: list[str]
    sources: list[str]


class ParameterRecord(BaseModel):
    name: str
    locations: list[Literal["query", "form", "javascript", "path"]]
    sources: list[str]


class TechnologyRecord(BaseModel):
    name: str
    version: str | None = None
    evidence: list[str]
    confidence: float = Field(ge=0.0, le=1.0)


class LoginFormRecord(BaseModel):
    action: str
    method: str
    username_fields: list[str]
    password_fields: list[str]


class AuthenticationInspection(BaseModel):
    request_authorization_scheme: str | None
    response_challenges: list[str]
    login_forms: list[LoginFormRecord]
    session_cookie_names: list[str]
    observations: list[str]


class JwtRecord(BaseModel):
    source: str
    token_preview: str
    algorithm: str | None
    token_type: str | None
    header: dict[str, object]
    payload: dict[str, object]
    signature_present: bool
    expires_at: datetime | None
    expired: bool | None
    issues: list[str]
    signature_verified: Literal[False] = False


class ResponseComparison(BaseModel):
    performed: bool
    baseline_status: int | None = None
    comparison_status: int | None = None
    baseline_bytes: int | None = None
    comparison_bytes: int | None = None
    body_similarity: float | None = Field(default=None, ge=0.0, le=1.0)
    differing_headers: list[str] = Field(default_factory=list)
    authentication_effect: str | None = None
    error: str | None = None


class WebLimits(BaseModel):
    max_response_bytes: int
    max_documents: int
    max_javascript_files: int
    max_redirects: int


class WebAnalysisResponse(BaseModel):
    analysis_id: str
    analyzer: str
    category: Literal["web"] = "web"
    target_scope: Literal["ctf", "lab", "owned"]
    exchange: HttpExchange
    headers: list[HeaderAssessment]
    cookies: list[CookieRecord]
    documents: list[DiscoveryDocument]
    robots_rules: list[str]
    sitemap_urls: list[str]
    comments: list[CommentRecord]
    scripts: list[ScriptRecord]
    endpoints: list[EndpointRecord]
    parameters: list[ParameterRecord]
    technologies: list[TechnologyRecord]
    authentication: AuthenticationInspection
    jwts: list[JwtRecord]
    comparison: ResponseComparison
    warnings: list[str]
    limits: WebLimits
