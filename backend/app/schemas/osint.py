from __future__ import annotations

from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator


TargetType = Literal["auto", "domain", "ip", "username", "url"]
ResolvedTargetType = Literal["domain", "ip", "username", "url"]
ProviderName = Literal[
    "dns",
    "whois",
    "rdap",
    "certificates",
    "ip_metadata",
    "usernames",
    "web_metadata",
    "google_search",
]


class OsintInvestigationRequest(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True)

    target: str = Field(min_length=1, max_length=2_048)
    target_type: TargetType = "auto"
    providers: list[ProviderName] | None = None
    include_search_results: bool = False
    include_web_metadata: bool = True
    timeout_ms: int = Field(default=6_000, ge=1_000, le=15_000)
    max_certificates: int = Field(default=50, ge=1, le=100)
    max_search_results: int = Field(default=10, ge=1, le=10)

    @field_validator("providers")
    @classmethod
    def unique_providers(
        cls, value: list[ProviderName] | None
    ) -> list[ProviderName] | None:
        if value is None:
            return None
        return list(dict.fromkeys(value))


class ProviderRun(BaseModel):
    name: str
    status: Literal["success", "no_data", "unavailable", "error"]
    source: str
    record_count: int = Field(ge=0)
    duration_ms: int = Field(ge=0)
    error: str | None = None


class DnsRecord(BaseModel):
    name: str
    record_type: str
    value: str
    ttl: int | None = Field(default=None, ge=0)
    priority: int | None = Field(default=None, ge=0)


class WhoisSummary(BaseModel):
    server: str
    registrar: str | None = None
    organization: str | None = None
    country: str | None = None
    created_at: str | None = None
    updated_at: str | None = None
    expires_at: str | None = None
    nameservers: list[str] = Field(default_factory=list)
    statuses: list[str] = Field(default_factory=list)


class RdapSummary(BaseModel):
    query: str
    object_class: str | None = None
    handle: str | None = None
    name: str | None = None
    country: str | None = None
    registry: str | None = None
    statuses: list[str] = Field(default_factory=list)
    nameservers: list[str] = Field(default_factory=list)
    events: dict[str, str] = Field(default_factory=dict)
    entities: list[dict[str, object]] = Field(default_factory=list)
    notices: list[str] = Field(default_factory=list)


class IpMetadata(BaseModel):
    address: str
    reverse_dns: str | None = None
    prefix: str | None = None
    asns: list[int] = Field(default_factory=list)
    registry: str | None = None
    name: str | None = None
    country: str | None = None


class CertificateRecord(BaseModel):
    certificate_id: str
    common_name: str | None = None
    dns_names: list[str] = Field(default_factory=list)
    issuer: str | None = None
    not_before: str | None = None
    not_after: str | None = None


class UsernameProfile(BaseModel):
    platform: str
    username: str
    exists: bool | None
    profile_url: str
    display_name: str | None = None
    bio: str | None = None
    attributes: dict[str, object] = Field(default_factory=dict)


class WebMetadata(BaseModel):
    url: str
    final_url: str
    status_code: int
    title: str | None = None
    description: str | None = None
    author: str | None = None
    canonical_url: str | None = None
    open_graph: dict[str, str] = Field(default_factory=dict)
    json_ld_types: list[str] = Field(default_factory=list)
    links: list[str] = Field(default_factory=list)


class SearchQuery(BaseModel):
    label: str
    query: str
    google_url: str


class SearchResult(BaseModel):
    title: str
    url: str
    snippet: str | None = None
    display_link: str | None = None


class OsintEntity(BaseModel):
    id: str
    entity_type: Literal[
        "domain",
        "ip",
        "username",
        "account",
        "asn",
        "organization",
        "certificate",
        "url",
    ]
    value: str
    attributes: dict[str, object] = Field(default_factory=dict)
    sources: list[str] = Field(default_factory=list)


class OsintRelationship(BaseModel):
    source_id: str
    target_id: str
    relationship: str
    confidence: float = Field(ge=0.0, le=1.0)
    sources: list[str]
    attributes: dict[str, object] = Field(default_factory=dict)


class OsintInvestigationResponse(BaseModel):
    analysis_id: str
    analyzer: str
    category: Literal["osint"] = "osint"
    target: str
    normalized_target: str
    target_type: ResolvedTargetType
    generated_at: datetime
    providers: list[ProviderRun]
    dns_records: list[DnsRecord]
    whois: WhoisSummary | None = None
    rdap: list[RdapSummary]
    ip_metadata: list[IpMetadata]
    certificates: list[CertificateRecord]
    username_profiles: list[UsernameProfile]
    web_metadata: WebMetadata | None = None
    search_queries: list[SearchQuery]
    search_results: list[SearchResult]
    entities: list[OsintEntity]
    relationships: list[OsintRelationship]
    warnings: list[str]
