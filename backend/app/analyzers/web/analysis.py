from __future__ import annotations

import base64
import json
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from html.parser import HTMLParser
from http.cookies import SimpleCookie
from typing import Iterable
from urllib.parse import parse_qsl, urljoin, urlsplit, urlunsplit

from app.core.analyzers import BaseAnalyzer
from app.analyzers.web.triage import (
    build_attack_surface,
    build_notable_findings,
    build_raw_evidence,
    detect_flags,
)
from app.analyzers.web.similarity import bounded_body_similarity
from app.schemas.web import (
    AuthenticationInspection,
    CommentRecord,
    CookieRecord,
    DiscoveryDocument,
    EndpointRecord,
    FormFieldRecord,
    FormRecord,
    HeaderAssessment,
    HttpExchange,
    JwtRecord,
    LoginFormRecord,
    ParameterRecord,
    PageRecord,
    ReconTreeNode,
    ResponseComparison,
    ScriptRecord,
    TechnologyRecord,
    TargetSummary,
    WebAnalysisResponse,
    WebLimits,
)

_SOURCE_MAP_RE = re.compile(r"(?://[#@]|/\*[#@])\s*sourceMappingURL\s*=\s*([^\s*]+)", re.I)
_JS_URL_RE = re.compile(
    r"(?:fetch\s*\(|axios(?:\.[a-z]+)?\s*\(|\.(?:get|post|put|patch|delete)\s*\(|url\s*:)\s*[`'\"]([^`'\"]+)",
    re.I,
)
_GENERIC_PATH_RE = re.compile(r"[`'\"]((?:https?://|/)[^`'\"\s]{1,500})[`'\"]")
_JWT_RE = re.compile(r"(?<![A-Za-z0-9_-])([A-Za-z0-9_-]{2,}\.[A-Za-z0-9_-]{2,}\.[A-Za-z0-9_-]*)(?![A-Za-z0-9_-])")
_SESSION_COOKIE_RE = re.compile(r"(?:sess|session|auth|token|jwt|sid)", re.I)
_SECURITY_HEADERS = {
    "content-security-policy": "Restricts browser content sources and script execution.",
    "x-content-type-options": "Prevents MIME-type sniffing when set to nosniff.",
    "x-frame-options": "Provides legacy framing protection.",
    "referrer-policy": "Controls referrer data sent to other origins.",
    "permissions-policy": "Restricts access to browser capabilities.",
}


@dataclass(slots=True)
class FetchedDocument:
    kind: str
    url: str
    status_code: int | None
    headers: list[tuple[str, str]] = field(default_factory=list)
    body: bytes = b""
    elapsed_ms: int = 0
    truncated: bool = False
    error: str | None = None
    depth: int = 0
    parent_url: str | None = None
    source: str = "direct"
    wildcard_like: bool = False
    authenticated: bool = False

    @property
    def text(self) -> str:
        return self.body.decode("utf-8", errors="replace")

    @property
    def content_type(self) -> str | None:
        return _first_header(self.headers, "content-type")


@dataclass(slots=True)
class WebInput:
    analysis_id: str
    target_scope: str
    method: str
    request_headers: list[tuple[str, str]]
    redirect_chain: list[str]
    primary: FetchedDocument
    documents: list[FetchedDocument]
    comparison: FetchedDocument | None
    comparison_error: str | None
    limits: WebLimits


@dataclass(slots=True)
class _Form:
    action: str
    method: str
    enctype: str | None = None
    inputs: list[tuple[str, str, str | None]] = field(default_factory=list)


class _PageParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.comments: list[tuple[int, str]] = []
        self.links: list[tuple[str, str]] = []
        self.scripts: list[tuple[str | None, str]] = []
        self.forms: list[_Form] = []
        self.meta: list[dict[str, str]] = []
        self._form: _Form | None = None
        self._script_source: str | None = None
        self._script_parts: list[str] = []
        self._in_script = False

    def handle_comment(self, data: str) -> None:
        self.comments.append((self.getpos()[0], data.strip()))

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        values = {name.lower(): value or "" for name, value in attrs}
        tag = tag.lower()
        if tag in {"a", "link", "img", "iframe", "source"}:
            attribute = "href" if tag in {"a", "link"} else "src"
            if values.get(attribute):
                self.links.append((tag, values[attribute]))
        if tag == "script":
            self._in_script = True
            self._script_source = values.get("src") or None
            self._script_parts = []
        elif tag == "form":
            self._form = _Form(
                values.get("action", ""), values.get("method", "GET").upper(),
                values.get("enctype") or None,
            )
            self.forms.append(self._form)
        elif tag in {"input", "textarea", "select", "button"} and self._form is not None:
            name = values.get("name", "").strip()
            if name:
                self._form.inputs.append((name, values.get("type", tag).lower(), values.get("value") or None))
        elif tag == "meta":
            self.meta.append(values)

    def handle_endtag(self, tag: str) -> None:
        if tag.lower() == "script":
            self.scripts.append((self._script_source, "".join(self._script_parts)))
            self._in_script = False
            self._script_source = None
            self._script_parts = []
        elif tag.lower() == "form":
            self._form = None

    def handle_data(self, data: str) -> None:
        if self._in_script:
            self._script_parts.append(data)


def _first_header(headers: Iterable[tuple[str, str]], name: str) -> str | None:
    lowered = name.lower()
    return next((value for key, value in headers if key.lower() == lowered), None)


def _all_headers(headers: Iterable[tuple[str, str]], name: str) -> list[str]:
    lowered = name.lower()
    return [value for key, value in headers if key.lower() == lowered]


def _display_url(value: str) -> str:
    parts = urlsplit(value)
    return urlunsplit((parts.scheme, parts.netloc, parts.path or "/", parts.query, ""))


def _parse_cookie(value: str, source: str, url: str, authenticated: bool) -> CookieRecord | None:
    jar = SimpleCookie()
    try:
        jar.load(value)
    except Exception:
        return None
    if not jar:
        return None
    name, morsel = next(iter(jar.items()))
    secure = bool(morsel["secure"])
    http_only = bool(morsel["httponly"])
    same_site = morsel["samesite"] or None
    issues: list[str] = []
    if not secure:
        issues.append("Secure is missing.")
    if not http_only:
        issues.append("HttpOnly is missing.")
    if same_site is None:
        issues.append("SameSite is not explicit.")
    elif same_site.lower() == "none" and not secure:
        issues.append("SameSite=None is set without Secure.")
    return CookieRecord(
        name=name,
        value=morsel.value,
        source=source,
        url=url,
        authenticated=authenticated,
        domain=morsel["domain"] or None,
        path=morsel["path"] or None,
        secure=secure,
        http_only=http_only,
        same_site=same_site,
        expires=morsel["expires"] or None,
        issues=issues,
    )


def _b64_json(value: str) -> dict[str, object] | None:
    try:
        raw = base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
        decoded = json.loads(raw)
        return decoded if isinstance(decoded, dict) else None
    except (ValueError, UnicodeDecodeError, json.JSONDecodeError):
        return None


def _jwt_record(
    token: str,
    source: str,
    source_type: str,
    url: str,
    authenticated: bool,
    cookie_name: str | None = None,
) -> JwtRecord | None:
    segments = token.split(".")
    if len(segments) != 3:
        return None
    header, payload = _b64_json(segments[0]), _b64_json(segments[1])
    if header is None or payload is None:
        return None
    algorithm = str(header.get("alg")) if header.get("alg") is not None else None
    token_type = str(header.get("typ")) if header.get("typ") is not None else None
    issues: list[str] = []
    if not algorithm or algorithm.lower() == "none":
        issues.append("The token declares no signature algorithm.")
    signature_present = bool(segments[2])
    if not signature_present:
        issues.append("The token has an empty signature segment.")
    expires_at: datetime | None = None
    expired: bool | None = None
    expiry = payload.get("exp")
    if isinstance(expiry, (int, float)):
        try:
            expires_at = datetime.fromtimestamp(expiry, timezone.utc)
            expired = expires_at < datetime.now(timezone.utc)
            if expired:
                issues.append("The token is expired according to its exp claim.")
        except (OverflowError, OSError, ValueError):
            issues.append("The exp claim is outside the supported date range.")
    else:
        issues.append("The token has no numeric exp claim.")
    preview = token if len(token) <= 32 else f"{token[:16]}…{token[-8:]}"
    return JwtRecord(
        source=source,
        source_type=source_type,
        url=url,
        cookie_name=cookie_name,
        authenticated=authenticated,
        token_preview=preview,
        algorithm=algorithm,
        token_type=token_type,
        header=header,
        payload=payload,
        signature_present=signature_present,
        expires_at=expires_at,
        expired=expired,
        issues=issues,
    )


def _jwt_candidates(value: str) -> Iterable[str]:
    yield from (match.group(1) for match in _JWT_RE.finditer(value))


def _technology(name: str, version: str | None, evidence: str, confidence: float) -> TechnologyRecord:
    return TechnologyRecord(name=name, version=version, evidence=[evidence], confidence=confidence)


class WebAnalyzer(BaseAnalyzer[WebInput, WebAnalysisResponse]):
    name = "web_passive_analyzer"
    category = "web"

    def supports(self, value: object) -> bool:
        return isinstance(value, WebInput) and value.primary.status_code is not None

    def analyze(self, value: WebInput) -> WebAnalysisResponse:
        if not self.supports(value):
            raise TypeError("WebAnalyzer requires a successful primary HTTP exchange")

        primary = value.primary
        page_url = primary.url
        parser = _PageParser()
        content_type = (primary.content_type or "").lower()
        if "html" in content_type or primary.text.lstrip().lower().startswith(("<!doctype", "<html")):
            parser.feed(primary.text)
        page_parsers: list[tuple[FetchedDocument, _PageParser]] = [(primary, parser)]
        for document in value.documents:
            if document.kind != "page" or document.status_code is None:
                continue
            document_type = (document.content_type or "").lower()
            if "html" not in document_type and not document.text.lstrip().lower().startswith(("<!doctype", "<html")):
                continue
            page_parser = _PageParser()
            page_parser.feed(document.text)
            page_parsers.append((document, page_parser))

        header_assessments = self._headers(value)
        cookies = self._cookies(value)
        comments = [
            CommentRecord(source=document.url, line=line, text=text[:2_000])
            for document, page_parser in page_parsers
            for line, text in page_parser.comments
            if text
        ][:500]
        robots_rules, sitemap_urls = self._discovery_text(value.documents)
        scripts = self._scripts(page_parsers, value.documents, page_url)
        endpoints, parameters = self._endpoints(page_parsers, value.documents, page_url, robots_rules, sitemap_urls)
        endpoints = self._rank_endpoints(endpoints)
        forms = self._forms(page_parsers)
        pages = [
            PageRecord(
                url=document.url, status_code=document.status_code or 0,
                content_type=document.content_type, depth=document.depth,
                source=document.source, parent_url=document.parent_url,
            )
            for document, _ in page_parsers
        ]
        technologies = self._technologies(primary, parser)
        authentication = self._authentication(value, parser, cookies, page_url)
        jwts = self._jwts(value, cookies)
        comparison = self._comparison(primary, value.comparison, value.comparison_error)
        evidence_documents = [primary, *value.documents]
        flags = detect_flags(evidence_documents, cookies)
        attack_surface = build_attack_surface(endpoints, forms)
        notable_findings = build_notable_findings(evidence_documents, endpoints, cookies, jwts, scripts, flags)
        flag_status = "found" if flags else "possible_lead" if any(item.score >= 60 for item in notable_findings) else "not_found"
        documents = [
            DiscoveryDocument(
                kind=document.kind, url=document.url, status_code=document.status_code,
                content_type=document.content_type, size=len(document.body),
                truncated=document.truncated, error=document.error,
            )
            for document in value.documents
        ]
        warnings = [document.error for document in value.documents if document.error]
        if primary.truncated:
            warnings.append("The primary response body reached the configured byte limit.")

        return WebAnalysisResponse(
            analysis_id=value.analysis_id,
            analyzer=self.name,
            target_scope=value.target_scope,
            exchange=HttpExchange(
                url=_display_url(page_url), method=value.method,
                status_code=primary.status_code or 0,
                reason_phrase=_first_header(primary.headers, "x-ctfkit-reason") or "",
                elapsed_ms=primary.elapsed_ms,
                request_headers=[{"name": key, "value": item} for key, item in value.request_headers],
                response_headers=[{"name": key, "value": item} for key, item in primary.headers if key.lower() != "x-ctfkit-reason"],
                content_type=primary.content_type, body_bytes=len(primary.body),
                body_truncated=primary.truncated, redirect_chain=value.redirect_chain,
            ),
            headers=header_assessments,
            cookies=cookies,
            documents=documents,
            robots_rules=robots_rules,
            sitemap_urls=sitemap_urls,
            comments=comments,
            scripts=scripts,
            endpoints=endpoints,
            parameters=parameters,
            forms=forms,
            attack_surface=attack_surface,
            pages=pages,
            technologies=technologies,
            authentication=authentication,
            jwts=jwts,
            comparison=comparison,
            target_summary=TargetSummary(
                url=_display_url(value.primary.url if not value.redirect_chain else value.redirect_chain[0]),
                final_url=_display_url(page_url),
                server=_first_header(primary.headers, "server"),
                technologies=[item.name + (f" {item.version}" if item.version else "") for item in technologies],
                pages_analyzed=len(pages),
                endpoints_discovered=len(endpoints),
                javascript_files_analyzed=sum(not item.inline and item.status_code is not None for item in scripts),
            ),
            flag_status=flag_status,
            flags=flags,
            notable_findings=notable_findings,
            recon_tree=[
                ReconTreeNode(
                    url=document.url, parent_url=document.parent_url,
                    source=document.source if document.kind != "primary" else "target",
                    depth=document.depth,
                )
                for document in evidence_documents
                if document.kind != "wildcard-probe"
            ],
            raw_evidence=build_raw_evidence(evidence_documents),
            warnings=warnings,
            limits=value.limits,
        )

    def _headers(self, value: WebInput) -> list[HeaderAssessment]:
        response = {key.lower(): item for key, item in value.primary.headers}
        results: list[HeaderAssessment] = []
        for name, note in _SECURITY_HEADERS.items():
            item = response.get(name)
            results.append(HeaderAssessment(
                name=name, value=item, source="response",
                status="present" if item else "missing",
                note=note if item else f"Missing. {note}",
            ))
        for name in ("server", "x-powered-by", "via"):
            if name in response:
                results.append(HeaderAssessment(
                    name=name, value=response[name], source="response",
                    status="informational", note="May disclose implementation or intermediary details.",
                ))
        for name, item in value.request_headers:
            results.append(HeaderAssessment(
                name=name, value=item, source="request", status="present",
                note="Header sent by the analyst for this request.",
            ))
        return results

    def _cookies(self, value: WebInput) -> list[CookieRecord]:
        records: list[CookieRecord] = []
        cookie_header = _first_header(value.request_headers, "cookie")
        if cookie_header:
            jar = SimpleCookie()
            try:
                jar.load(cookie_header)
                records.extend(CookieRecord(
                    name=name,
                    value=morsel.value,
                    source="request",
                    url=value.primary.url,
                    authenticated=value.primary.authenticated,
                ) for name, morsel in jar.items())
            except Exception:
                pass
        for document in (value.primary, *value.documents):
            for header in _all_headers(document.headers, "set-cookie"):
                parsed = _parse_cookie(header, "response", document.url, document.authenticated)
                if parsed:
                    records.append(parsed)
        return records

    def _discovery_text(self, documents: list[FetchedDocument]) -> tuple[list[str], list[str]]:
        rules: list[str] = []
        urls: list[str] = []
        for document in documents:
            if document.status_code is None or not 200 <= document.status_code < 300:
                continue
            if document.kind == "robots":
                for line in document.text.splitlines():
                    clean = line.split("#", 1)[0].strip()
                    if clean and ":" in clean:
                        name, item = clean.split(":", 1)
                        if name.lower() in {"allow", "disallow", "sitemap", "user-agent"}:
                            rules.append(f"{name.strip()}: {item.strip()}")
                            if name.lower() == "sitemap":
                                urls.append(urljoin(document.url, item.strip()))
            elif document.kind == "sitemap":
                urls.extend(re.findall(r"<loc>\s*([^<]+?)\s*</loc>", document.text, re.I))
        return list(dict.fromkeys(rules))[:500], list(dict.fromkeys(urls))[:500]

    def _scripts(self, page_parsers: list[tuple[FetchedDocument, _PageParser]], documents: list[FetchedDocument], page_url: str) -> list[ScriptRecord]:
        records: list[ScriptRecord] = []
        for page_document, parser in page_parsers:
          for source, inline in parser.scripts:
            if source:
                absolute = urljoin(page_document.url, source)
                fetched = next((item for item in documents if item.kind == "javascript" and item.url == absolute), None)
                text = fetched.text if fetched else ""
                maps = [urljoin(absolute, item) for item in _SOURCE_MAP_RE.findall(text)]
                if fetched:
                    header_map = next((item for key, item in fetched.headers if key.lower() in {"sourcemap", "x-sourcemap"}), None)
                    if header_map:
                        maps.append(urljoin(absolute, header_map))
                maps = list(dict.fromkeys(maps))
                records.append(ScriptRecord(url=absolute, inline=False, status_code=fetched.status_code if fetched else None, size=len(fetched.body) if fetched else 0, source_maps=maps))
            elif inline.strip():
                maps = [urljoin(page_document.url, item) for item in _SOURCE_MAP_RE.findall(inline)]
                records.append(ScriptRecord(url=None, inline=True, size=len(inline.encode()), source_maps=maps))
        for document in documents:
            if document.kind == "javascript" and not any(record.url == document.url for record in records):
                maps = [urljoin(document.url, item) for item in _SOURCE_MAP_RE.findall(document.text)]
                header_map = next((item for key, item in document.headers if key.lower() in {"sourcemap", "x-sourcemap"}), None)
                if header_map:
                    maps.append(urljoin(document.url, header_map))
                maps = list(dict.fromkeys(maps))
                records.append(ScriptRecord(url=document.url, inline=False, status_code=document.status_code, size=len(document.body), source_maps=maps))
        return records[:100]

    def _endpoints(self, page_parsers: list[tuple[FetchedDocument, _PageParser]], documents: list[FetchedDocument], page_url: str, robots: list[str], sitemap_urls: list[str]) -> tuple[list[EndpointRecord], list[ParameterRecord]]:
        found: dict[tuple[str, str], dict[str, set[str]]] = {}

        def add(raw: str, method: str, source: str, form_parameters: Iterable[str] = ()) -> None:
            if not raw or raw.startswith(("#", "javascript:", "data:", "mailto:")):
                return
            absolute = urljoin(page_url, raw)
            parts = urlsplit(absolute)
            if parts.scheme not in {"http", "https"}:
                return
            clean_url = urlunsplit((parts.scheme, parts.netloc, parts.path or "/", parts.query, ""))
            key = (clean_url, method.upper())
            entry = found.setdefault(key, {"sources": set(), "parameters": set()})
            entry["sources"].add(source)
            entry["parameters"].update(name for name, _ in parse_qsl(parts.query, keep_blank_values=True))
            entry["parameters"].update(form_parameters)

        add(page_url, "GET", "primary response")
        for page_document, parser in page_parsers:
            add(page_document.url, "GET", page_document.source)
            for tag, link in parser.links:
                add(urljoin(page_document.url, link), "GET", f"HTML {tag}")
            for form in parser.forms:
                add(urljoin(page_document.url, form.action or page_document.url), form.method, "HTML form", (name for name, _, _ in form.inputs))
        for rule in robots:
            name, item = rule.split(":", 1)
            if name.lower() in {"allow", "disallow"} and item.strip():
                add(item.strip(), "GET", "robots.txt")
        for item in sitemap_urls:
            add(item, "GET", "sitemap")
        for document in documents:
            if document.kind == "sensitive" and document.status_code is not None and not document.wildcard_like and document.status_code < 500:
                add(document.url, "GET", "targeted check")
        script_texts = [inline for _, parser in page_parsers for source, inline in parser.scripts if not source and inline]
        script_texts.extend(document.text for document in documents if document.kind in {"javascript", "source-map"} and document.status_code is not None)
        for index, script in enumerate(script_texts):
            source = f"JavaScript #{index + 1}"
            for raw in _JS_URL_RE.findall(script):
                add(raw, "UNKNOWN", source)
            for raw in _GENERIC_PATH_RE.findall(script):
                add(raw, "UNKNOWN", source)

        endpoints = [
            EndpointRecord(url=url, path=urlsplit(url).path or "/", method=method,
                           parameters=sorted(data["parameters"]), sources=sorted(data["sources"]))
            for (url, method), data in found.items()
        ]
        endpoints.sort(key=lambda item: (item.path, item.method, item.url))

        parameter_map: dict[str, dict[str, set[str]]] = {}
        for endpoint in endpoints:
            query_names = {name for name, _ in parse_qsl(urlsplit(endpoint.url).query, keep_blank_values=True)}
            for name in endpoint.parameters:
                item = parameter_map.setdefault(name, {"locations": set(), "sources": set()})
                item["locations"].add("query" if name in query_names else "form")
                if any(source.startswith("JavaScript") for source in endpoint.sources):
                    item["locations"].add("javascript")
                item["sources"].update(endpoint.sources)
        parameters = [ParameterRecord(name=name, locations=sorted(data["locations"]), sources=sorted(data["sources"])) for name, data in sorted(parameter_map.items())]
        return endpoints[:1_000], parameters[:500]

    def _forms(self, page_parsers: list[tuple[FetchedDocument, _PageParser]]) -> list[FormRecord]:
        records: list[FormRecord] = []
        for document, parser in page_parsers:
            for form in parser.forms:
                records.append(FormRecord(
                    page_url=document.url,
                    action=urljoin(document.url, form.action or document.url),
                    method=form.method,
                    enctype=form.enctype,
                    fields=[FormFieldRecord(name=name, input_type=kind, value=field_value) for name, kind, field_value in form.inputs],
                ))
        return records[:500]

    @staticmethod
    def _rank_endpoints(endpoints: list[EndpointRecord]) -> list[EndpointRecord]:
        for endpoint in endpoints:
            lowered = endpoint.path.lower()
            score = 25
            reason = "Discovered during same-origin reconnaissance."
            if any(token in lowered for token in ("admin", "debug", "internal", "secret")):
                score, reason = 78, "Route name suggests an administrative, debug, or internal surface."
            elif any(token in lowered for token in ("/api", "graphql", "swagger", "openapi")):
                score, reason = 68, "Route appears to expose an API surface."
            elif any(source == "robots.txt" for source in endpoint.sources):
                score, reason = 64, "Route was disclosed by robots.txt rather than a normal page link."
            if len(endpoint.sources) > 1:
                score = min(90, score + (len(endpoint.sources) - 1) * 4)
                reason += " Multiple independent sources corroborate it."
            endpoint.priority = score
            endpoint.reason = reason
        return sorted(endpoints, key=lambda item: (-item.priority, item.path, item.method))

    def _technologies(self, primary: FetchedDocument, parser: _PageParser) -> list[TechnologyRecord]:
        candidates: dict[str, TechnologyRecord] = {}
        server = _first_header(primary.headers, "server")
        powered = _first_header(primary.headers, "x-powered-by")
        for header_name, value in (("Server", server), ("X-Powered-By", powered)):
            if value:
                match = re.match(r"([^/\s]+)(?:/([^\s]+))?", value)
                if match:
                    item = _technology(match.group(1), match.group(2), f"{header_name}: {value}", 0.92)
                    candidates[item.name.lower()] = item
        generator = next((meta.get("content") for meta in parser.meta if meta.get("name", "").lower() == "generator"), None)
        if generator:
            match = re.match(r"(.+?)(?:\s+([0-9][\w.-]*))?$", generator)
            if match:
                item = _technology(match.group(1), match.group(2), f"meta generator: {generator}", 0.9)
                candidates[item.name.lower()] = item
        evidence_text = primary.text[:1_000_000]
        patterns = [
            ("WordPress", None, r"/wp-(?:content|includes)/", 0.9),
            ("jQuery", r"([0-9]+(?:\.[0-9]+){1,2})", r"jquery(?:-|\.min\.)?([0-9]+(?:\.[0-9]+){1,2})?", 0.84),
            ("React", None, r"(?:data-reactroot|__REACT_DEVTOOLS_GLOBAL_HOOK__)", 0.78),
            ("Vue.js", None, r"(?:data-v-[a-f0-9]+|__VUE__)", 0.75),
            ("Angular", None, r"(?:ng-version|ng-app)", 0.82),
            ("Bootstrap", r"([0-9]+(?:\.[0-9]+){1,2})", r"bootstrap(?:\.min)?(?:-|@)([0-9]+(?:\.[0-9]+){1,2})?", 0.78),
        ]
        for name, version_pattern, pattern, confidence in patterns:
            match = re.search(pattern, evidence_text, re.I)
            if match:
                version = match.group(1) if version_pattern and match.lastindex else None
                candidates.setdefault(name.lower(), _technology(name, version, "HTML or asset signature", confidence))
        return list(candidates.values())

    def _authentication(self, value: WebInput, parser: _PageParser, cookies: list[CookieRecord], page_url: str) -> AuthenticationInspection:
        authorization = _first_header(value.request_headers, "authorization")
        scheme = authorization.split(None, 1)[0] if authorization else None
        challenges = _all_headers(value.primary.headers, "www-authenticate")
        if value.comparison is not None:
            challenges.extend(_all_headers(value.comparison.headers, "www-authenticate"))
        challenges = list(dict.fromkeys(challenges))
        forms: list[LoginFormRecord] = []
        for form in parser.forms:
            passwords = [name for name, kind, _ in form.inputs if kind == "password"]
            usernames = [name for name, kind, _ in form.inputs if kind in {"text", "email"} and re.search(r"user|email|login", name, re.I)]
            if passwords:
                forms.append(LoginFormRecord(action=urljoin(page_url, form.action or page_url), method=form.method, username_fields=usernames, password_fields=passwords))
        session_names = sorted({cookie.name for cookie in cookies if _SESSION_COOKIE_RE.search(cookie.name)})
        observations: list[str] = []
        if challenges:
            observations.append("The response advertised one or more HTTP authentication challenges.")
        if forms:
            observations.append("A password-bearing HTML form was discovered.")
        if session_names:
            observations.append("Session-like cookie names were observed.")
        if value.primary.status_code in {401, 403}:
            observations.append(f"The target returned an authentication-related HTTP {value.primary.status_code} status.")
        return AuthenticationInspection(request_authorization_scheme=scheme, response_challenges=challenges, login_forms=forms, session_cookie_names=session_names, observations=observations)

    def _jwts(self, value: WebInput, cookies: list[CookieRecord]) -> list[JwtRecord]:
        found: list[JwtRecord] = []
        seen: set[str] = set()
        sources: list[tuple[str, str, str, str, bool, str | None]] = []
        sources.extend((
            f"{cookie.source} cookie {cookie.name}", cookie.value, "cookie:jwt",
            cookie.url, cookie.authenticated, cookie.name,
        ) for cookie in cookies)
        sources.extend((
            f"request header {name}", item, "header:jwt", value.primary.url,
            value.primary.authenticated, None,
        ) for name, item in value.request_headers)
        sources.append((
            "response body", value.primary.text[:1_000_000], "content:jwt",
            value.primary.url, value.primary.authenticated, None,
        ))
        sources.extend((
            f"{document.kind} {document.url}", document.text[:1_000_000], "content:jwt",
            document.url, document.authenticated, None,
        ) for document in value.documents if document.status_code is not None)
        for source, text, source_type, url, authenticated, cookie_name in sources:
            for token in _jwt_candidates(text):
                if token in seen:
                    continue
                seen.add(token)
                record = _jwt_record(token, source, source_type, url, authenticated, cookie_name)
                if record:
                    found.append(record)
        return found[:100]

    def _comparison(self, primary: FetchedDocument, comparison: FetchedDocument | None, error: str | None) -> ResponseComparison:
        if comparison is None:
            return ResponseComparison(performed=bool(error), error=error)
        ignored = {"date", "set-cookie", "content-length", "etag", "last-modified"}
        first_headers = {key.lower(): item for key, item in primary.headers if key.lower() not in ignored}
        second_headers = {key.lower(): item for key, item in comparison.headers if key.lower() not in ignored}
        differences = sorted(key for key in first_headers.keys() | second_headers.keys() if first_headers.get(key) != second_headers.get(key))
        similarity = bounded_body_similarity(primary.body, comparison.body)
        if primary.status_code != comparison.status_code:
            effect = f"Status changed from {primary.status_code} to {comparison.status_code} when authentication state was removed."
        elif similarity < 0.8:
            effect = "The response body changed materially when authentication state was removed."
        else:
            effect = "No material authentication-dependent response difference was detected."
        return ResponseComparison(performed=True, baseline_status=primary.status_code, comparison_status=comparison.status_code, baseline_bytes=len(primary.body), comparison_bytes=len(comparison.body), body_similarity=round(similarity, 4), differing_headers=differences[:100], authentication_effect=effect)
