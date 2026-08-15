from __future__ import annotations

import base64
import json
import socket

import httpx
from fastapi.testclient import TestClient

from app.api.v1.routes import web as web_route
from app.main import app
from app.services.web import WebAnalysisService

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
    assert "Secure is missing" not in " ".join(cookie["issues"])


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
    forwarded: list[tuple[str | None, str | None]] = []

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.host == "lab.local":
            return httpx.Response(302, headers={"Location": "http://other.local/landing"})
        if request.url.path == "/landing":
            forwarded.append((request.headers.get("authorization"), request.headers.get("cookie")))
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
            "headers": {"Authorization": "Bearer secret"},
            "cookies": {"session": "secret"},
            "fetch_robots": False, "fetch_sitemap": False, "fetch_javascript": False,
        },
    )
    assert response.status_code == 200
    assert forwarded == [(None, None)]


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
