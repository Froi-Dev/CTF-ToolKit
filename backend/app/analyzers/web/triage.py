from __future__ import annotations

import base64
import html
import json
import re
from collections import defaultdict
from collections.abc import Iterable, Sequence
from typing import Protocol
from urllib.parse import urlsplit
from urllib.parse import unquote

from app.schemas.web import (
    AttackSurfaceRecord,
    CookieRecord,
    EndpointRecord,
    FormRecord,
    JwtRecord,
    NotableFinding,
    RawEvidenceRecord,
    ScriptRecord,
    WebFlagCandidate,
)


class DocumentLike(Protocol):
    kind: str
    url: str
    status_code: int | None
    headers: list[tuple[str, str]]
    body: bytes
    truncated: bool
    error: str | None
    wildcard_like: bool
    authenticated: bool

    @property
    def text(self) -> str: ...


_FLAG_RE = re.compile(
    r"(?i)(?<![A-Za-z0-9_-])((?:flag|ctf|picoCTF|HTB|THM|[A-Za-z][A-Za-z0-9_-]{1,24})\{[^{}\r\n]{1,256}\})"
)
_SECRET_RE = re.compile(
    r"(?im)\b(?:api[_-]?key|secret|password|passwd|token|client[_-]?secret)\b\s*[:=]\s*['\"]?([^\s'\";,}{]{4,256})"
)
_ERROR_RE = re.compile(
    r"(?i)(traceback \(most recent call last\)|stack trace|sql syntax|PDOException|TemplateSyntaxError|"
    r"/var/www/|/home/[\w.-]+/|[A-Z]:\\[^\r\n]+|debug mode)"
)
_BASE64_RE = re.compile(r"(?<![A-Za-z0-9+/=_-])([A-Za-z0-9+/_-]{16,2048}={0,2})(?![A-Za-z0-9+/=_-])")
_HEX_RE = re.compile(r"(?i)(?<![0-9a-f])([0-9a-f]{16,2048})(?![0-9a-f])")
_SIGNIFICANT_COOKIE_NAME_RE = re.compile(r"(?:role|isadmin|admin|level|perm|access|debug|flag)", re.I)
_SESSION_COOKIE_NAME_RE = re.compile(r"(?:sess|session)", re.I)
_SENSITIVE_PATHS = {
    "/.env": (94, "Exposed environment configuration", "Environment files commonly contain application secrets and service credentials."),
    "/.git/HEAD": (92, "Exposed Git repository", "Git metadata may permit source reconstruction, including deleted or historical files."),
    "/.git/config": (92, "Exposed Git repository", "Git configuration confirms accessible repository metadata and may disclose remotes."),
    "/backup.zip": (90, "Exposed backup archive", "Backup archives can expose application source, configuration, and credentials."),
    "/backup.tar.gz": (90, "Exposed backup archive", "Backup archives can expose application source, configuration, and credentials."),
    "/database.sql": (90, "Exposed database dump", "Database dumps may contain credentials, tokens, challenge data, or flags."),
    "/dump.sql": (90, "Exposed database dump", "Database dumps may contain credentials, tokens, challenge data, or flags."),
    "/config.php": (87, "Exposed application configuration", "Application configuration may disclose database or signing secrets."),
    "/config.json": (87, "Exposed application configuration", "Application configuration may disclose service endpoints or secrets."),
    "/settings.py": (87, "Exposed application settings", "Framework settings may disclose secret keys and debug configuration."),
    "/swagger.json": (76, "Exposed API specification", "An API specification reveals undocumented routes, methods, and parameters."),
    "/openapi.json": (76, "Exposed API specification", "An API specification reveals undocumented routes, methods, and parameters."),
}


def _severity(score: int) -> str:
    if score >= 95:
        return "critical"
    if score >= 75:
        return "high"
    if score >= 60:
        return "medium"
    if score >= 40:
        return "low"
    return "info"


def _snippet(text: str, start: int = 0, size: int = 260) -> str:
    clean = " ".join(text[max(0, start - 80): start + size].split())
    return clean[:360]


def _decoded_variants(text: str) -> Iterable[tuple[str, str]]:
    decoded_text = html.unescape(unquote(text))
    if decoded_text != text:
        yield "URL/HTML decoded", decoded_text
    for match in _BASE64_RE.finditer(text):
        token = match.group(1)
        try:
            decoded = base64.urlsafe_b64decode(token + "=" * (-len(token) % 4)).decode("utf-8")
        except (ValueError, UnicodeDecodeError):
            continue
        if decoded and sum(character.isprintable() for character in decoded) / len(decoded) >= 0.85:
            yield "Base64 decoded", decoded
    for match in _HEX_RE.finditer(text):
        token = match.group(1)
        if len(token) % 2:
            continue
        try:
            decoded = bytes.fromhex(token).decode("utf-8")
        except (ValueError, UnicodeDecodeError):
            continue
        if decoded and sum(character.isprintable() for character in decoded) / len(decoded) >= 0.85:
            yield "hex decoded", decoded


def _decode_cookie_value(value: str) -> str | None:
    if not value:
        return None
    try:
        decoded = base64.urlsafe_b64decode(value + "=" * (-len(value) % 4)).decode("utf-8")
    except (ValueError, UnicodeDecodeError):
        return None
    return decoded if decoded and all(character.isprintable() for character in decoded) else None


def _cookie_name_is_significant(name: str, value: str) -> bool:
    if _SIGNIFICANT_COOKIE_NAME_RE.search(name):
        return True
    if not _SESSION_COOKIE_NAME_RE.search(name):
        return False
    return len(value) <= 16 or bool(re.fullmatch(r"(?:\d+|true|false|yes|no|user|guest|admin)", value, re.I))


def _jwt_has_high_value_claims(jwt: JwtRecord) -> bool:
    serialized = json.dumps(jwt.payload, ensure_ascii=False, sort_keys=True, default=str)
    claim_names = " ".join(str(name).lower() for name in jwt.payload)
    return bool(
        re.search(r"(?:role|permission|admin|scope|access|privilege)", claim_names)
        or re.search(r'(?i)"(?:role|permission|admin|scope|access|privilege)[^"]*"\s*:\s*"?admin', serialized)
        or _FLAG_RE.search(serialized)
    )


def _finding(
    identifier: str,
    score: int,
    title: str,
    evidence: Iterable[str],
    location: str,
    why: str,
    suggestion: str,
    confidence: float,
    sources: Iterable[str] = (),
    *,
    url: str | None = None,
    source_type: str = "recon:lead",
    context: str | None = None,
    authenticated: bool = False,
) -> NotableFinding:
    evidence_items = list(dict.fromkeys(evidence))[:8]
    return NotableFinding(
        id=identifier,
        score=score,
        severity=_severity(score),
        title=title,
        evidence=evidence_items,
        location=location,
        why_it_matters=why,
        suggested_investigation=suggestion,
        confidence=confidence,
        sources=list(dict.fromkeys(sources))[:12],
        url=url or location,
        source_type=source_type,
        context=context if context is not None else "\n".join(evidence_items),
        authenticated=authenticated,
    )


def detect_flags(documents: Sequence[DocumentLike], cookies: Sequence[CookieRecord]) -> list[WebFlagCandidate]:
    sources: list[tuple[str, str, str, str, str, bool]] = []
    for document in documents:
        if document.status_code is not None:
            sources.append((document.kind, document.url, document.text, "content:flag", document.url, document.authenticated))
            sources.extend((
                f"{document.kind} header", document.url, f"{name}: {value}",
                "header:flag", document.url, document.authenticated,
            ) for name, value in document.headers)
    sources.extend((
        f"{cookie.source} cookie", cookie.name, cookie.value,
        "cookie:flag", cookie.url, cookie.authenticated,
    ) for cookie in cookies)
    sources.extend(
        (
            f"{encoding} from {source}", location, decoded,
            "cookie:decoded" if source_type.startswith("cookie:") else f"{source_type}:decoded",
            url, authenticated,
        )
        for source, location, text, source_type, url, authenticated in list(sources)
        for encoding, decoded in _decoded_variants(text)
    )
    found: list[WebFlagCandidate] = []
    seen: set[str] = set()
    for source, location, text, source_type, url, authenticated in sources:
        for match in _FLAG_RE.finditer(text):
            value = match.group(1)
            if value in seen:
                continue
            seen.add(value)
            prefix = value.split("{", 1)[0]
            known = prefix.lower() in {"flag", "ctf", "picoctf", "htb", "thm"}
            found.append(WebFlagCandidate(
                value=value,
                pattern=f"{prefix}{{...}}",
                source=source,
                location=location,
                context=_snippet(text, match.start()),
                confidence=0.98 if known else 0.82,
                source_type=source_type,
                url=url,
                authenticated=authenticated,
            ))
    return found[:100]


def build_attack_surface(endpoints: Sequence[EndpointRecord], forms: Sequence[FormRecord]) -> list[AttackSurfaceRecord]:
    records: list[AttackSurfaceRecord] = []
    seen: set[tuple[str, str, str, str]] = set()

    def category(name: str, input_type: str | None) -> str:
        lowered = name.lower()
        if input_type == "file" or any(word in lowered for word in ("file", "upload", "path")):
            return "file handling"
        if any(word in lowered for word in ("user", "email", "pass", "login", "otp")):
            return "authentication"
        if lowered in {"id", "uid", "user_id", "account_id", "object_id"} or lowered.endswith("_id"):
            return "object authorization"
        if any(word in lowered for word in ("url", "uri", "host", "domain", "callback", "redirect")):
            return "server-side URL handling"
        if any(word in lowered for word in ("cmd", "command", "exec", "shell")):
            return "command input"
        return "general input"

    for form in forms:
        for field in form.fields:
            key = (field.name, form.action, form.method, "form")
            if key not in seen:
                seen.add(key)
                records.append(AttackSurfaceRecord(
                    parameter=field.name, endpoint=form.action, method=form.method,
                    location="form", input_type=field.input_type,
                    potential_category=category(field.name, field.input_type),
                ))
    for endpoint in endpoints:
        query_names = {item.split("=", 1)[0] for item in urlsplit(endpoint.url).query.split("&") if item}
        for name in endpoint.parameters:
            location = "javascript" if any(source.startswith("JavaScript") for source in endpoint.sources) else "query" if name in query_names else "path"
            key = (name, endpoint.path, endpoint.method, location)
            if key not in seen:
                seen.add(key)
                records.append(AttackSurfaceRecord(
                    parameter=name, endpoint=endpoint.path, method=endpoint.method,
                    location=location, potential_category=category(name, None),
                ))
    return records[:500]


def build_notable_findings(
    documents: Sequence[DocumentLike],
    endpoints: Sequence[EndpointRecord],
    cookies: Sequence[CookieRecord],
    jwts: Sequence[JwtRecord],
    scripts: Sequence[ScriptRecord],
    flags: Sequence[WebFlagCandidate],
) -> list[NotableFinding]:
    findings: list[NotableFinding] = []
    for index, flag in enumerate(flags):
        findings.append(_finding(
            f"flag-{index}", 100, "Complete flag pattern discovered", [flag.value, flag.context],
            flag.location, "A complete CTF-style flag pattern was present in collected evidence.",
            "Verify the candidate in the challenge context and submit it if appropriate.", flag.confidence, [flag.source],
            url=flag.url, source_type=flag.source_type, context=flag.context,
            authenticated=flag.authenticated,
        ))

    sensitive_groups: dict[str, list[DocumentLike]] = defaultdict(list)
    for document in documents:
        path = urlsplit(document.url).path
        details = _SENSITIVE_PATHS.get(path)
        if not details or document.status_code is None or not 200 <= document.status_code < 300 or document.wildcard_like:
            continue
        sensitive_groups[details[1]].append(document)
    for title, group in sensitive_groups.items():
        score, _, why = _SENSITIVE_PATHS[urlsplit(group[0].url).path]
        findings.append(_finding(
            f"sensitive-{len(findings)}", score, title,
            [f"{urlsplit(item.url).path} -> HTTP {item.status_code}: {_snippet(item.text)}" for item in group],
            ", ".join(urlsplit(item.url).path for item in group), why,
            "Open the resource manually and preserve relevant source or configuration evidence.", 0.97,
            [item.kind for item in group],
        ))

    for document in documents:
        if document.status_code is None or document.wildcard_like:
            continue
        for match in _SECRET_RE.finditer(document.text):
            findings.append(_finding(
                f"secret-{len(findings)}", 88, "Hardcoded secret or credential-like value",
                [_snippet(document.text, match.start())], document.url,
                "A credential-like assignment appears directly in collected source or configuration.",
                "Determine what component consumes this value; do not assume it is valid outside the challenge.",
                0.86, [document.kind],
            ))
            break
        if document.status_code in {403, 404, 500} and _ERROR_RE.search(document.text):
            match = _ERROR_RE.search(document.text)
            findings.append(_finding(
                f"error-{len(findings)}", 72, "Verbose error information disclosed",
                [_snippet(document.text, match.start() if match else 0)], document.url,
                "Error output can reveal frameworks, filesystem layout, or backend behavior.",
                "Reproduce the response manually and trace the disclosed component or route.", 0.9, [document.kind],
            ))

    exposed_maps = [item for item in documents if item.kind == "source-map" and item.status_code == 200 and not item.wildcard_like]
    if exposed_maps:
        findings.append(_finding(
            "source-maps", 82, "Exposed JavaScript source map",
            [f"{item.url} -> HTTP 200 ({len(item.body)} bytes)" for item in exposed_maps],
            exposed_maps[0].url, "Source maps can expose original filenames, source code, comments, and hidden endpoints.",
            "Inspect the sources and sourcesContent fields for challenge-specific leads.", 0.98,
            ["JavaScript sourceMappingURL", "HTTP verification"],
        ))

    path_groups: dict[str, list[EndpointRecord]] = defaultdict(list)
    for endpoint in endpoints:
        segments = [segment for segment in endpoint.path.lower().split("/") if segment]
        root = f"/{segments[0]}" if segments and any(token in segments[0] for token in ("admin", "debug", "internal", "secret", "api", "graphql")) else endpoint.path
        path_groups[root].append(endpoint)
    for path, group in path_groups.items():
        sources = sorted({source for item in group for source in item.sources})
        paths = sorted({item.path for item in group})
        lowered = " ".join(paths).lower()
        interesting = any(token in lowered for token in ("admin", "debug", "internal", "secret", "/api", "graphql"))
        if not interesting:
            if re.search(r"/\d+(?:/|$)", path):
                findings.append(_finding(
                    f"idor-{path}", 60, "Possible object-identifier authorization surface",
                    [f"{item.method} {path}" for item in group], path,
                    "A numeric object identifier appears directly in a discovered route; authorization behavior may be worth reviewing.",
                    "Compare access behavior between authorized object identifiers without assuming IDOR is present.", 0.7, sources,
                ))
            continue
        score = min(84, 62 + max(0, len(sources) - 1) * 6)
        if "robots.txt" in sources:
            score += 6
        score = min(84, score)
        title = "Correlated hidden application surface" if len(sources) > 1 or len(paths) > 1 else "Interesting hidden endpoint"
        findings.append(_finding(
            f"endpoint-{path}", score, title,
            [f"{item.method} {item.path} from {', '.join(item.sources)}" for item in group], path,
            "The route name and discovery source make it a strong CTF investigation lead.",
            "Open the route and inspect its authentication and response behavior; do not assume a vulnerability.",
            min(0.96, 0.7 + len(sources) * 0.08), sources,
        ))

    jwt_cookies: set[tuple[str, str]] = set()
    for jwt in jwts:
        high_value = _jwt_has_high_value_claims(jwt)
        context = json.dumps(
            {
                "cookie_name": jwt.cookie_name,
                "header": jwt.header,
                "payload": jwt.payload,
            },
            ensure_ascii=False,
            sort_keys=True,
            default=str,
        )
        if jwt.cookie_name is not None:
            jwt_cookies.add((jwt.url, jwt.cookie_name))
        findings.append(_finding(
            f"jwt-{len(findings)}", 88 if high_value else 64,
            "JWT cookie decoded" if jwt.source_type == "cookie:jwt" else "JWT decoded",
            [context, f"alg={jwt.algorithm or 'unknown'}; signature verified={jwt.signature_verified}"],
            f"{jwt.url} [{jwt.source}]",
            "Decoded JWT claims can reveal identity, role, permission, and application-state context without verifying or modifying the token.",
            "Review how the application uses these claims; no signature verification or token modification was attempted.",
            0.95 if high_value else 0.75,
            [jwt.source],
            url=jwt.url,
            source_type=jwt.source_type,
            context=context,
            authenticated=jwt.authenticated,
        ))

    for cookie in cookies:
        location = f"{cookie.url} [cookie {cookie.name}]"
        if (cookie.url, cookie.name) not in jwt_cookies:
            decoded = _decode_cookie_value(cookie.value)
            if decoded is not None:
                flag_match = _FLAG_RE.search(decoded)
                context = json.dumps(
                    {"cookie_name": cookie.name, "decoded_value": decoded},
                    ensure_ascii=False,
                    sort_keys=True,
                )
                findings.append(_finding(
                    f"cookie-decoded-{len(findings)}", 96 if flag_match else 35,
                    "Cookie value contains a decoded flag" if flag_match else "Printable Base64 cookie value decoded",
                    [context], location,
                    "A passively decoded cookie may expose challenge state, identifiers, or flag material.",
                    "Review the decoded value manually; CTFKit did not alter or replay it.",
                    0.98 if flag_match else 0.4,
                    ["Set-Cookie" if cookie.source == "response" else "Cookie"],
                    url=cookie.url,
                    source_type="cookie:decoded",
                    context=context,
                    authenticated=cookie.authenticated,
                ))
            elif _cookie_name_is_significant(cookie.name, cookie.value):
                context = json.dumps(
                    {"cookie_name": cookie.name, "value": cookie.value},
                    ensure_ascii=False,
                    sort_keys=True,
                )
                findings.append(_finding(
                    f"cookie-name-{len(findings)}", 35, "Security-significant cookie name observed",
                    [context], location,
                    "The cookie name suggests it may influence role, permission, debug, level, flag, or predictable session state.",
                    "Review server-side handling manually; no cookie tampering was attempted.",
                    0.4,
                    ["Set-Cookie" if cookie.source == "response" else "Cookie"],
                    url=cookie.url,
                    source_type="cookie:name",
                    context=context,
                    authenticated=cookie.authenticated,
                ))

        if cookie.source == "response" and cookie.issues:
            context = json.dumps(
                {"cookie_name": cookie.name, "observations": cookie.issues},
                ensure_ascii=False,
                sort_keys=True,
            )
            findings.append(_finding(
                f"cookie-security-{len(findings)}", 38, "Cookie security attributes worth reviewing",
                [f"{cookie.name}: {issue}" for issue in cookie.issues], location,
                "Missing cookie attributes can matter when correlated with other browser-side findings, but are not proof of exploitability.",
                "Review the attributes in context; no exploit or cookie modification was attempted.",
                0.45,
                ["Set-Cookie"],
                url=cookie.url,
                source_type="cookie:security",
                context=context,
                authenticated=cookie.authenticated,
            ))

    findings.sort(key=lambda item: (-item.score, item.title, item.location))
    deduped: list[NotableFinding] = []
    seen: set[tuple[str, str]] = set()
    for finding in findings:
        key = (finding.title, finding.location)
        if key not in seen:
            seen.add(key)
            deduped.append(finding)
    return deduped[:100]


def build_raw_evidence(documents: Sequence[DocumentLike]) -> list[RawEvidenceRecord]:
    records: list[RawEvidenceRecord] = []
    for document in documents[:40]:
        records.append(RawEvidenceRecord(
            kind=document.kind,
            url=document.url,
            status_code=document.status_code,
            headers=[{"name": name, "value": value} for name, value in document.headers[:100]],
            body_preview=document.text[:12_000],
            truncated=document.truncated or len(document.text) > 12_000,
            authenticated=document.authenticated,
        ))
    return records
