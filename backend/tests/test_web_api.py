from __future__ import annotations

import base64
import asyncio
import json
import socket
import time

import httpx
from fastapi.testclient import TestClient

from app.api.v1.routes import web as web_route
from app.analyzers.web.analysis import FetchedDocument
from app.main import app
from app.services.web import WebAnalysisService
from app.schemas.web import WebAnalysisRequest

client = TestClient(app)


def _part(value: dict[str, object]) -> str:
    return base64.urlsafe_b64encode(json.dumps(value, separators=(",", ":")).encode()).decode().rstrip("=")


def _jwt() -> str:
    return f"{_part({'alg': 'none', 'typ': 'JWT'})}.{_part({'sub': 'ctf-user', 'exp': 1})}."


def _resolver(host: str, port: int, family: int, socktype: int) -> list[tuple[object, ...]]:
    del host, family
    return [(socket.AF_INET, socktype, 6, "", ("127.0.0.1", port))]


def _handler(request: httpx.Request) -> httpx.Response:
    if request.url.path == "/robots.txt":
        return httpx.Response(200, text="User-agent: *\nDisallow: /admin\nSitemap: /sitemap.xml", headers={"Content-Type": "text/plain"})
    if request.url.path == "/sitemap.xml":
        return httpx.Response(200, text="<urlset><url><loc>http://lab.local/profile?id=7</loc></url></urlset>", headers={"Content-Type": "application/xml"})
    if request.url.path == "/app.js":
        return httpx.Response(200, text="fetch('/api/users?role=admin');\n//# sourceMappingURL=app.js.map", headers={"Content-Type": "application/javascript", "SourceMap": "/app.js.map"})
    if request.url.path == "/app.js.map":
        return httpx.Response(200, json={"version": 3, "sources": ["app.ts"]})
    if request.headers.get("authorization") is None:
        return httpx.Response(401, text="login required", headers={"WWW-Authenticate": "Bearer"})
    token = _jwt()
    html = f"""<!doctype html><html><head><meta name="generator" content="ChallengeCMS 2.1"><script src="/app.js"></script></head>
    <body><!-- TODO remove /debug --><a href="/account?tab=keys">Account</a>
    <form method="post" action="/login"><input name="username"><input name="password" type="password"></form>
    <script>fetch('/api/inline?debug=1')</script><div>{token}</div></body></html>"""
    return httpx.Response(
        200,
        text=html,
        headers=[
            ("Content-Type", "text/html"),
            ("Server", "nginx/1.25"),
            ("Content-Security-Policy", "default-src 'self'"),
            ("Set-Cookie", f"session={token}; Path=/; HttpOnly; SameSite=Lax"),
        ],
    )


def test_web_analysis_derives_real_discovery_auth_and_jwt(monkeypatch) -> None:
    service = WebAnalysisService(transport=httpx.MockTransport(_handler), resolver=_resolver)
    monkeypatch.setattr(web_route, "service", service)

    response = client.post(
        "/api/v1/web/analyze",
        json={
            "url": "http://lab.local/",
            "target_scope": "lab",
            "authorization_confirmed": True,
            "headers": {"Authorization": "Bearer analyst-token"},
            "compare_without_auth": True,
        },
    )

    assert response.status_code == 200
    payload = response.json()
    assert payload["exchange"]["status_code"] == 200
    assert payload["comparison"]["comparison_status"] == 401
    assert payload["authentication"]["request_authorization_scheme"] == "Bearer"
    assert payload["authentication"]["response_challenges"] == ["Bearer"]
    assert payload["authentication"]["login_forms"][0]["password_fields"] == ["password"]
    assert any(item["path"] == "/api/users" and "role" in item["parameters"] for item in payload["endpoints"])
    assert any(item["path"] == "/api/inline" and "debug" in item["parameters"] for item in payload["endpoints"])
    assert any(item["path"] == "/admin" for item in payload["endpoints"])
    assert payload["comments"][0]["text"] == "TODO remove /debug"
    assert any(item["name"] == "ChallengeCMS" for item in payload["technologies"])
    assert any(item["kind"] == "source-map" and item["status_code"] == 200 for item in payload["documents"])
    assert next(item for item in payload["scripts"] if item["url"] == "http://lab.local/app.js")["source_maps"] == ["http://lab.local/app.js.map"]
    assert payload["jwts"][0]["algorithm"] == "none"
    assert payload["jwts"][0]["expired"] is True
    assert payload["jwts"][0]["signature_verified"] is False
    cookie = next(item for item in payload["cookies"] if item["name"] == "session")
    assert cookie["http_only"] is True
    assert "Secure is missing" in " ".join(cookie["issues"])
    jwt_lead = next(item for item in payload["notable_findings"] if item["source_type"] == "cookie:jwt")
    assert jwt_lead["url"] == "http://lab.local/"
    assert jwt_lead["authenticated"] is True
    assert jwt_lead["confidence"] == 0.75


def test_web_analysis_requires_explicit_authorization_confirmation() -> None:
    response = client.post(
        "/api/v1/web/analyze",
        json={"url": "http://127.0.0.1:8001", "target_scope": "lab", "authorization_confirmed": False},
    )
    assert response.status_code == 422
    assert response.json()["error"]["code"] == "VALIDATION_ERROR"


def test_metadata_and_link_local_targets_are_blocked(monkeypatch) -> None:
    service = WebAnalysisService(transport=httpx.MockTransport(_handler))
    monkeypatch.setattr(web_route, "service", service)
    response = client.post(
        "/api/v1/web/analyze",
        json={"url": "http://169.254.169.254/latest/meta-data", "target_scope": "lab", "authorization_confirmed": True},
    )
    assert response.status_code == 400
    assert response.json()["error"]["code"] == "UNSAFE_WEB_TARGET"


def test_forbidden_transport_headers_are_rejected() -> None:
    response = client.post(
        "/api/v1/web/analyze",
        json={
            "url": "http://127.0.0.1:8001", "target_scope": "lab",
            "authorization_confirmed": True, "headers": {"Host": "metadata.internal"},
        },
    )
    assert response.status_code == 422


def test_cross_origin_redirect_does_not_forward_authentication(monkeypatch) -> None:
    forwarded: list[tuple[str | None, str | None, str | None]] = []

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.host == "lab.local":
            return httpx.Response(302, headers={"Location": "http://other.local/landing"})
        if request.url.host == "other.local":
            forwarded.append((
                request.headers.get("authorization"),
                request.headers.get("cookie"),
                request.headers.get("x-api-key"),
            ))
        if request.url.path == "/landing":
            return httpx.Response(200, text="<html>redirected</html>", headers={"Content-Type": "text/html"})
        return httpx.Response(404)

    monkeypatch.setattr(
        web_route,
        "service",
        WebAnalysisService(transport=httpx.MockTransport(handler), resolver=_resolver),
    )
    response = client.post(
        "/api/v1/web/analyze",
        json={
            "url": "http://lab.local/start", "target_scope": "ctf",
            "authorization_confirmed": True,
            "headers": {"Authorization": "Bearer secret", "X-API-Key": "custom-secret"},
            "cookies": {"session": "secret"},
            "fetch_robots": False, "fetch_sitemap": False, "fetch_javascript": False,
        },
    )
    assert response.status_code == 200
    assert forwarded
    assert all(values == (None, None, None) for values in forwarded)


def test_response_body_is_bounded(monkeypatch) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, content=b"A" * 600_000, headers={"Content-Type": "text/plain"})

    monkeypatch.setattr(
        web_route,
        "service",
        WebAnalysisService(transport=httpx.MockTransport(handler), resolver=_resolver),
    )
    response = client.post(
        "/api/v1/web/analyze",
        json={
            "url": "http://lab.local/large", "target_scope": "lab",
            "authorization_confirmed": True,
            "fetch_robots": False, "fetch_sitemap": False, "fetch_javascript": False,
        },
    )
    assert response.status_code == 200
    assert response.json()["exchange"]["body_bytes"] == 512 * 1024
    assert response.json()["exchange"]["body_truncated"] is True


def test_web_recon_correlates_and_ranks_real_ctf_evidence(monkeypatch) -> None:
    encoded_flag = base64.b64encode(b"flag{decoded_web_recon}").decode()

    def handler(request: httpx.Request) -> httpx.Response:
        path = request.url.path
        if path == "/":
            return httpx.Response(200, text=(
                '<html><script src="/app.js"></script><a href="/internal">Internal</a>'
                '<form action="/login" method="post"><input name="username">'
                '<input name="password" type="password"><input name="next_url"></form></html>'
            ), headers={"Content-Type": "text/html", "Server": "nginx/1.25"})
        if path == "/robots.txt":
            return httpx.Response(200, text="User-agent: *\nDisallow: /internal", headers={"Content-Type": "text/plain"})
        if path == "/sitemap.xml":
            return httpx.Response(200, text="<urlset></urlset>", headers={"Content-Type": "application/xml"})
        if path == "/app.js":
            return httpx.Response(200, text=f"fetch('/internal/api/config'); const clue='{encoded_flag}';\n//# sourceMappingURL=app.js.map", headers={"Content-Type": "application/javascript"})
        if path == "/app.js.map":
            return httpx.Response(200, json={"version": 3, "sources": ["src/admin.ts"], "sourcesContent": ["const secretRoute='/internal/api/config'"]})
        if path == "/.git/HEAD":
            return httpx.Response(200, text="ref: refs/heads/main\n", headers={"Content-Type": "text/plain"})
        if path == "/internal":
            return httpx.Response(200, text="<html>internal application</html>", headers={"Content-Type": "text/html"})
        return httpx.Response(404, text="not found", headers={"Content-Type": "text/plain"})

    monkeypatch.setattr(web_route, "service", WebAnalysisService(transport=httpx.MockTransport(handler), resolver=_resolver))
    response = client.post("/api/v1/web/analyze", json={
        "url": "http://lab.local/", "target_scope": "ctf", "authorization_confirmed": True,
        "scan_depth": 2, "max_pages": 10,
    })

    assert response.status_code == 200
    payload = response.json()
    assert payload["flag_status"] == "found"
    assert payload["flags"][0]["value"] == "flag{decoded_web_recon}"
    assert "Base64 decoded" in payload["flags"][0]["source"]
    assert payload["notable_findings"] == sorted(payload["notable_findings"], key=lambda item: -item["score"])
    assert any(item["title"] == "Exposed Git repository" for item in payload["notable_findings"])
    assert any(item["title"] == "Exposed JavaScript source map" for item in payload["notable_findings"])
    correlated = next(item for item in payload["notable_findings"] if item["title"] == "Correlated hidden application surface")
    assert correlated["location"] == "/internal"
    assert any(item["potential_category"] == "authentication" for item in payload["attack_surface"])
    assert any(item["potential_category"] == "server-side URL handling" for item in payload["attack_surface"])
    assert payload["target_summary"]["pages_analyzed"] == 2
    assert payload["target_summary"]["javascript_files_analyzed"] == 1
    assert any(item["kind"] == "source-map" for item in payload["raw_evidence"])


def test_wildcard_200_responses_do_not_become_sensitive_file_findings(monkeypatch) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        del request
        return httpx.Response(200, text="<html><h1>custom not found</h1></html>", headers={"Content-Type": "text/html"})

    monkeypatch.setattr(web_route, "service", WebAnalysisService(transport=httpx.MockTransport(handler), resolver=_resolver))
    response = client.post("/api/v1/web/analyze", json={
        "url": "http://lab.local/", "target_scope": "lab", "authorization_confirmed": True,
        "crawl_same_origin": False, "fetch_javascript": False,
    })

    assert response.status_code == 200
    titles = [item["title"] for item in response.json()["notable_findings"]]
    assert not any(title.startswith("Exposed ") for title in titles)


def test_independent_discovery_requests_run_concurrently() -> None:
    active_requests = 0
    maximum_active_requests = 0

    async def handler(request: httpx.Request) -> httpx.Response:
        nonlocal active_requests, maximum_active_requests
        active_requests += 1
        maximum_active_requests = max(maximum_active_requests, active_requests)
        await asyncio.sleep(0.01)
        active_requests -= 1
        if request.url.path == "/":
            return httpx.Response(200, text="<html>target</html>", headers={"Content-Type": "text/html"})
        return httpx.Response(404, text="not found", headers={"Content-Type": "text/plain"})

    service = WebAnalysisService(transport=httpx.MockTransport(handler), resolver=_resolver)
    result = asyncio.run(service.analyze(WebAnalysisRequest(
        url="http://lab.local/",
        target_scope="lab",
        authorization_confirmed=True,
        crawl_same_origin=False,
        fetch_javascript=False,
    )))

    assert result.exchange.status_code == 200
    assert maximum_active_requests >= 4


def test_large_wildcard_comparison_is_bounded_and_linear() -> None:
    left = (b"<div>route-not-found repeating-template </div>" * 4_000)[:131_072]
    right = (b"<div>route-is-missing repeating-template </div>" * 4_000)[:131_072]
    document = FetchedDocument(
        "sensitive", "http://lab.local/.env", 200,
        [("content-type", "text/html")], left,
    )
    probe = FetchedDocument(
        "wildcard-probe", "http://lab.local/.ctfkit-not-found-random", 200,
        [("content-type", "text/html")], right,
    )

    started = time.perf_counter()
    WebAnalysisService._matches_wildcard(document, [probe])
    elapsed = time.perf_counter() - started

    assert elapsed < 0.25


def test_authenticated_crawl_validates_cookie_session_and_analyzes_all_set_cookies(monkeypatch) -> None:
    calls: list[tuple[str, str | None]] = []
    jwt = f"{_part({'alg': 'HS256', 'typ': 'JWT'})}.{_part({'sub': 'operator', 'role': 'admin'})}.signature"
    encoded_flag = base64.b64encode(b"flag{cookie_analysis_passed}").decode()

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append((request.url.path, request.headers.get("cookie")))
        if request.headers.get("cookie") != "session=browser-session":
            return httpx.Response(401, text="login required")
        if request.url.path == "/dashboard":
            return httpx.Response(200, text="<html>authenticated dashboard</html>", headers={"Content-Type": "text/html"})
        if request.url.path == "/":
            return httpx.Response(
                200,
                text='<html><a href="/private">Private</a></html>',
                headers=[
                    ("Content-Type", "text/html"),
                    ("Set-Cookie", f"identity={jwt}; Path=/; HttpOnly; SameSite=Lax"),
                ],
            )
        if request.url.path == "/private":
            return httpx.Response(
                200,
                text="<html>private page</html>",
                headers=[
                    ("Content-Type", "text/html"),
                    ("Set-Cookie", f"clue={encoded_flag}; Path=/"),
                    ("Set-Cookie", "note=aGVsbG8=; Path=/; HttpOnly; Secure; SameSite=Strict"),
                    ("Set-Cookie", "debug=on; Path=/; HttpOnly; Secure; SameSite=Strict"),
                ],
            )
        return httpx.Response(404)

    monkeypatch.setattr(
        web_route,
        "service",
        WebAnalysisService(transport=httpx.MockTransport(handler), resolver=_resolver),
    )
    response = client.post("/api/v1/web/analyze", json={
        "url": "http://lab.local/",
        "target_scope": "ctf",
        "authorization_confirmed": True,
        "headers": {"Cookie": "session=browser-session"},
        "authenticated_url": "http://lab.local/dashboard",
        "fetch_robots": False,
        "fetch_sitemap": False,
        "fetch_javascript": False,
        "directory_discovery": False,
        "api_discovery": False,
        "sensitive_file_checks": False,
        "scan_depth": 1,
        "max_pages": 5,
    })

    assert response.status_code == 200
    payload = response.json()
    assert calls[0] == ("/dashboard", "session=browser-session")
    assert ("/private", "session=browser-session") in calls
    assert all(cookie == "session=browser-session" for _, cookie in calls)
    source_types = {item["source_type"] for item in payload["notable_findings"]}
    assert {"cookie:jwt", "cookie:decoded", "cookie:name", "cookie:security"} <= source_types
    jwt_lead = next(item for item in payload["notable_findings"] if item["source_type"] == "cookie:jwt")
    assert jwt_lead["confidence"] == 0.95
    assert '"role": "admin"' in jwt_lead["context"]
    decoded_leads = [item for item in payload["notable_findings"] if item["source_type"] == "cookie:decoded"]
    assert {item["confidence"] for item in decoded_leads} == {0.4, 0.98}
    assert all(item["authenticated"] for item in decoded_leads)
    assert any(item["value"] == "flag{cookie_analysis_passed}" for item in payload["flags"])
    assert all(item["authenticated"] for item in payload["raw_evidence"])


def test_invalid_authenticated_session_stops_before_crawl(monkeypatch) -> None:
    paths: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        paths.append(request.url.path)
        if request.url.path == "/dashboard":
            return httpx.Response(302, headers={"Location": "/login"})
        if request.url.path == "/login":
            return httpx.Response(200, text="login")
        return httpx.Response(200, text="should not crawl")

    monkeypatch.setattr(
        web_route,
        "service",
        WebAnalysisService(transport=httpx.MockTransport(handler), resolver=_resolver),
    )
    response = client.post("/api/v1/web/analyze", json={
        "url": "http://lab.local/",
        "target_scope": "lab",
        "authorization_confirmed": True,
        "cookies": {"session": "expired"},
        "authenticated_url": "http://lab.local/dashboard",
    })

    assert response.status_code == 401
    assert response.json()["error"]["code"] == "AUTH_SESSION_INVALID"
    assert paths == ["/dashboard", "/login"]


def test_authenticated_url_requires_auth_material() -> None:
    response = client.post("/api/v1/web/analyze", json={
        "url": "http://lab.local/",
        "target_scope": "lab",
        "authorization_confirmed": True,
        "authenticated_url": "http://lab.local/dashboard",
    })

    assert response.status_code == 422
