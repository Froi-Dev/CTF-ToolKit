from __future__ import annotations

import asyncio
import ipaddress
import re
from datetime import datetime, timezone
from urllib.parse import urlsplit, urlunsplit
from uuid import uuid4

import httpx

from app.analyzers.osint import OsintAnalyzer
from app.core.errors import InvalidOsintTargetError
from app.integrations.osint import (
    CertificateTransparencyAdapter,
    DnsOverHttpsAdapter,
    GoogleSearchAdapter,
    RdapAdapter,
    RipeNetworkInfoAdapter,
    WebMetadataAdapter,
    WhoisAdapter,
    default_username_adapters,
)
from app.integrations.osint.base import AdapterOutput
from app.schemas.osint import (
    CertificateRecord,
    DnsRecord,
    IpMetadata,
    OsintEntity,
    OsintInvestigationRequest,
    OsintInvestigationResponse,
    OsintRelationship,
    ProviderRun,
    RdapSummary,
    SearchQuery,
    SearchResult,
    UsernameProfile,
    WebMetadata,
    WhoisSummary,
)


_DOMAIN_LABEL_RE = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$", re.I)
_USERNAME_RE = re.compile(r"^[A-Za-z0-9_.-]{1,64}$")
DEFAULT_DOMAIN_PROVIDERS = {"dns", "whois", "rdap", "certificates", "ip_metadata"}
DEFAULT_IP_PROVIDERS = {"rdap", "ip_metadata"}
DEFAULT_USERNAME_PROVIDERS = {"usernames"}


class OsintService:
    def __init__(
        self,
        *,
        transport: httpx.AsyncBaseTransport | None = None,
        whois: WhoisAdapter | None = None,
        rdap: RdapAdapter | None = None,
        dns: DnsOverHttpsAdapter | None = None,
        certificates: CertificateTransparencyAdapter | None = None,
        ip_metadata: RipeNetworkInfoAdapter | None = None,
        username_adapters: list[object] | None = None,
        google_search: GoogleSearchAdapter | None = None,
        web_metadata: WebMetadataAdapter | None = None,
        analyzer: OsintAnalyzer | None = None,
    ) -> None:
        self._transport = transport
        self._whois = whois or WhoisAdapter()
        self._rdap = rdap or RdapAdapter()
        self._dns = dns or DnsOverHttpsAdapter()
        self._certificates = certificates or CertificateTransparencyAdapter()
        self._ip_metadata = ip_metadata or RipeNetworkInfoAdapter()
        self._username_adapters = (
            username_adapters
            if username_adapters is not None
            else default_username_adapters()
        )
        self._google_search = google_search or GoogleSearchAdapter()
        self._web_metadata = web_metadata or WebMetadataAdapter()
        self._analyzer = analyzer or OsintAnalyzer()

    async def investigate(
        self, request: OsintInvestigationRequest
    ) -> OsintInvestigationResponse:
        target_type, normalized, subject_type, subject = normalize_target(
            request.target, request.target_type
        )
        domain = subject if subject_type == "domain" else ""
        selected = self._selected_providers(request, subject_type, target_type)
        timeout = request.timeout_ms / 1_000
        outputs: list[AdapterOutput] = []

        async with httpx.AsyncClient(
            timeout=httpx.Timeout(timeout),
            follow_redirects=False,
            trust_env=False,
            transport=self._transport,
            limits=httpx.Limits(max_connections=12, max_keepalive_connections=4),
            headers={"User-Agent": "CTFKit-OSINT/0.1", "Accept": "application/json"},
        ) as client:
            tasks = []
            if subject_type == "domain":
                if "dns" in selected:
                    tasks.append(self._dns.collect(subject, client))
                if "whois" in selected:
                    tasks.append(self._whois.collect(subject, timeout))
                if "rdap" in selected:
                    tasks.append(self._rdap.collect(subject, "domain", client))
                if "certificates" in selected:
                    tasks.append(
                        self._certificates.collect(
                            subject, client, request.max_certificates
                        )
                    )
            elif subject_type == "ip":
                if "rdap" in selected:
                    tasks.append(self._rdap.collect(subject, "ip", client))
                if "ip_metadata" in selected:
                    tasks.append(self._ip_metadata.collect(subject, client))
            elif subject_type == "username" and "usernames" in selected:
                tasks.extend(
                    adapter.collect(subject, client)
                    for adapter in self._username_adapters
                )  # type: ignore[attr-defined]

            if (
                target_type == "url"
                and request.include_web_metadata
                and "web_metadata" in selected
            ):
                tasks.append(self._web_metadata.collect(normalized, client))

            if tasks:
                outputs.extend(await asyncio.gather(*tasks))

            discovered_ips = self._discovered_ips(outputs)
            if subject_type == "domain" and discovered_ips:
                enrichment_tasks = []
                for address in discovered_ips[:4]:
                    if "ip_metadata" in selected:
                        enrichment_tasks.append(
                            self._ip_metadata.collect(address, client)
                        )
                    if "rdap" in selected:
                        enrichment_tasks.append(
                            self._rdap.collect(address, "ip", client)
                        )
                if enrichment_tasks:
                    outputs.extend(await asyncio.gather(*enrichment_tasks))

            search_queries = [
                SearchQuery.model_validate(item)
                for item in self._analyzer.search_queries(subject, subject_type)
            ]
            if (
                "google_search" in selected
                and request.include_search_results
                and search_queries
            ):
                outputs.append(
                    await self._google_search.collect(
                        search_queries[0].query, client, request.max_search_results
                    )
                )

            graph = self._analyzer.analyze(
                {
                    "normalized_target": normalized,
                    "target_type": target_type,
                    "subject_type": subject_type,
                    "subject": subject,
                    "domain": domain,
                    "outputs": outputs,
                }
            )

        return self._response(
            request, target_type, normalized, outputs, graph, search_queries
        )

    @staticmethod
    def _selected_providers(
        request: OsintInvestigationRequest, subject_type: str, target_type: str
    ) -> set[str]:
        if request.providers is not None:
            selected = set(request.providers)
        elif subject_type == "domain":
            selected = set(DEFAULT_DOMAIN_PROVIDERS)
        elif subject_type == "ip":
            selected = set(DEFAULT_IP_PROVIDERS)
        else:
            selected = set(DEFAULT_USERNAME_PROVIDERS)
        if target_type == "url" and request.include_web_metadata:
            selected.add("web_metadata")
        if request.include_search_results:
            selected.add("google_search")
        return selected

    @staticmethod
    def _discovered_ips(outputs: list[AdapterOutput]) -> list[str]:
        addresses = []
        for output in outputs:
            if output.name != "dns":
                continue
            for record in output.records:
                if record.get("record_type") in {"A", "AAAA"}:
                    try:
                        addresses.append(
                            str(ipaddress.ip_address(str(record.get("value"))))
                        )
                    except ValueError:
                        continue
        return list(dict.fromkeys(addresses))

    @staticmethod
    def _response(
        request: OsintInvestigationRequest,
        target_type: str,
        normalized: str,
        outputs: list[AdapterOutput],
        graph: dict[str, list[dict[str, object]]],
        search_queries: list[SearchQuery],
    ) -> OsintInvestigationResponse:
        by_name: dict[str, list[dict[str, object]]] = {}
        warnings: list[str] = []
        providers = []
        for output in outputs:
            by_name.setdefault(output.name.split(":", 1)[0], []).extend(output.records)
            providers.append(
                ProviderRun(
                    name=output.name,
                    status=output.status,  # type: ignore[arg-type]
                    source=output.source,
                    record_count=len(output.records),
                    duration_ms=output.duration_ms,
                    error=output.error,
                )
            )
            if output.error:
                warnings.append(f"{output.name}: {output.error}")

        whois_records = by_name.get("whois", [])
        web_records = by_name.get("web_metadata", [])
        rdap_records = by_name.get("rdap", [])
        ip_records = [dict(item) for item in by_name.get("ip_metadata", [])]
        for ip_record in ip_records:
            registration = next(
                (
                    item
                    for item in rdap_records
                    if item.get("query") == ip_record.get("address")
                ),
                None,
            )
            if registration:
                ip_record.update(
                    {
                        key: registration.get(key)
                        for key in ("registry", "name", "country")
                        if registration.get(key) is not None
                    }
                )
        return OsintInvestigationResponse(
            analysis_id=str(uuid4()),
            analyzer="passive-osint",
            target=request.target,
            normalized_target=normalized,
            target_type=target_type,  # type: ignore[arg-type]
            generated_at=datetime.now(timezone.utc),
            providers=providers,
            dns_records=[
                DnsRecord.model_validate(item) for item in by_name.get("dns", [])
            ],
            whois=WhoisSummary.model_validate(whois_records[0])
            if whois_records
            else None,
            rdap=[RdapSummary.model_validate(item) for item in rdap_records],
            ip_metadata=[IpMetadata.model_validate(item) for item in ip_records],
            certificates=[
                CertificateRecord.model_validate(item)
                for item in by_name.get("certificates", [])
            ],
            username_profiles=[
                UsernameProfile.model_validate(item)
                for item in by_name.get("usernames", [])
            ],
            web_metadata=WebMetadata.model_validate(web_records[0])
            if web_records
            else None,
            search_queries=search_queries,
            search_results=[
                SearchResult.model_validate(item)
                for item in by_name.get("google_search", [])
            ],
            entities=[OsintEntity.model_validate(item) for item in graph["entities"]],
            relationships=[
                OsintRelationship.model_validate(item)
                for item in graph["relationships"]
            ],
            warnings=warnings,
        )


def normalize_target(raw_target: str, requested_type: str) -> tuple[str, str, str, str]:
    raw = raw_target.strip()
    detected = requested_type
    if requested_type == "auto":
        if "://" in raw:
            detected = "url"
        else:
            try:
                ipaddress.ip_address(raw.strip("[]"))
                detected = "ip"
            except ValueError:
                detected = "domain" if "." in raw else "username"

    if detected == "ip":
        try:
            address = ipaddress.ip_address(raw.strip("[]"))
        except ValueError as exc:
            raise InvalidOsintTargetError(
                "The target is not a valid IP address."
            ) from exc
        if not address.is_global:
            raise InvalidOsintTargetError(
                "OSINT IP targets must be publicly routable addresses."
            )
        normalized = str(address)
        return "ip", normalized, "ip", normalized

    if detected == "domain":
        normalized = _normalize_domain(raw)
        return "domain", normalized, "domain", normalized

    if detected == "username":
        if not _USERNAME_RE.fullmatch(raw):
            raise InvalidOsintTargetError(
                "Usernames may contain only letters, numbers, dots, underscores, and hyphens."
            )
        return "username", raw, "username", raw

    if detected == "url":
        parts = urlsplit(raw)
        if (
            parts.scheme.lower() not in {"http", "https"}
            or not parts.hostname
            or parts.username
            or parts.password
        ):
            raise InvalidOsintTargetError(
                "URLs must use HTTP(S), include a host, and omit embedded credentials."
            )
        try:
            port = parts.port
        except ValueError as exc:
            raise InvalidOsintTargetError("The URL contains an invalid port.") from exc
        host = parts.hostname
        try:
            address = ipaddress.ip_address(host)
            if not address.is_global:
                raise InvalidOsintTargetError(
                    "OSINT URLs must use a publicly routable host."
                )
            subject_type, subject = "ip", str(address)
            rendered_host = f"[{subject}]" if address.version == 6 else subject
        except ValueError:
            subject_type, subject = "domain", _normalize_domain(host)
            rendered_host = subject
        netloc = f"{rendered_host}:{port}" if port else rendered_host
        normalized = urlunsplit(
            (parts.scheme.lower(), netloc, parts.path or "/", parts.query, "")
        )
        return "url", normalized, subject_type, subject

    raise InvalidOsintTargetError("Unsupported OSINT target type.")


def _normalize_domain(value: str) -> str:
    value = value.strip().lower().rstrip(".")
    if value.startswith("*."):
        value = value[2:]
    try:
        ascii_domain = value.encode("idna").decode("ascii")
    except UnicodeError as exc:
        raise InvalidOsintTargetError("The domain name is not valid IDNA.") from exc
    if len(ascii_domain) > 253 or "." not in ascii_domain:
        raise InvalidOsintTargetError(
            "A fully qualified public domain name is required."
        )
    if any(not _DOMAIN_LABEL_RE.fullmatch(label) for label in ascii_domain.split(".")):
        raise InvalidOsintTargetError("The domain name contains an invalid label.")
    try:
        address = ipaddress.ip_address(ascii_domain)
    except ValueError:
        return ascii_domain
    raise InvalidOsintTargetError(f"Use target_type 'ip' for {address}.")
