from __future__ import annotations

import socket
import re

import httpx
from fastapi.testclient import TestClient

from app.api.v1.routes import osint as osint_route
from app.analyzers.osint import OsintAnalyzer
from app.integrations.osint import (
    GoogleSearchAdapter,
    RipeNetworkInfoAdapter,
    WebMetadataAdapter,
    WhoisAdapter,
)
from app.main import app
from app.services.osint import OsintService


client = TestClient(app)


def _whois(domain: str, timeout: float) -> tuple[str, str]:
    del timeout
    return (
        "whois.example",
        f"Domain Name: {domain}\nRegistrar: Example Registrar\nCreation Date: 2020-01-01\n"
        "Registry Expiry Date: 2030-01-01\nName Server: NS1.EXAMPLE.NET\n",
    )


def _domain_handler(request: httpx.Request) -> httpx.Response:
    host = request.url.host
    if host == "cloudflare-dns.com":
        record_type = request.url.params["type"]
        answers = {
            "A": [
                {"name": "example.com.", "type": 1, "TTL": 300, "data": "93.184.216.34"}
            ],
            "MX": [
                {
                    "name": "example.com.",
                    "type": 15,
                    "TTL": 300,
                    "data": "10 mail.example.com.",
                }
            ],
            "NS": [
                {
                    "name": "example.com.",
                    "type": 2,
                    "TTL": 300,
                    "data": "ns1.example.net.",
                }
            ],
        }.get(record_type, [])
        return httpx.Response(200, json={"Status": 0, "Answer": answers})
    if host == "rdap.org" and request.url.path == "/domain/example.com":
        return httpx.Response(
            200,
            json={
                "objectClassName": "domain",
                "handle": "EXAMPLE",
                "ldhName": "example.com",
                "status": ["active"],
                "nameservers": [{"ldhName": "ns1.example.net"}],
                "events": [
                    {"eventAction": "registration", "eventDate": "2020-01-01T00:00:00Z"}
                ],
                "entities": [
                    {
                        "handle": "REG",
                        "roles": ["registrar"],
                        "vcardArray": [
                            "vcard",
                            [["fn", {}, "text", "Example Registrar"]],
                        ],
                    }
                ],
            },
        )
    if host == "rdap.org" and request.url.path == "/ip/93.184.216.34":
        return httpx.Response(
            200,
            json={
                "objectClassName": "ip network",
                "handle": "NET-1",
                "name": "EXAMPLE-NET",
                "country": "US",
                "port43": "whois.example.net",
            },
        )
    if host == "crt.sh":
        return httpx.Response(
            200,
            json=[
                {
                    "id": 123,
                    "common_name": "example.com",
                    "name_value": "example.com\nwww.example.com",
                    "issuer_name": "CN=Test CA",
                    "not_before": "2026-01-01",
                    "not_after": "2026-04-01",
                }
            ],
        )
    if host == "stat.ripe.net":
        return httpx.Response(
            200, json={"data": {"prefix": "93.184.216.0/24", "asns": [15133]}}
        )
    return httpx.Response(404)


def test_domain_investigation_correlates_public_provider_evidence(monkeypatch) -> None:
    service = OsintService(
        transport=httpx.MockTransport(_domain_handler),
        whois=WhoisAdapter(_whois),
        ip_metadata=RipeNetworkInfoAdapter(
            reverse_lookup=lambda address: ("edge.example.net", [], [address])
        ),
    )
    monkeypatch.setattr(osint_route, "service", service)

    response = client.post(
        "/api/v1/osint/investigate",
        json={"target": "Example.COM", "target_type": "auto"},
    )

    assert response.status_code == 200
    payload = response.json()
    assert payload["normalized_target"] == "example.com"
    assert {item["record_type"] for item in payload["dns_records"]} >= {"A", "MX", "NS"}
    assert payload["whois"]["registrar"] == "Example Registrar"
    assert payload["ip_metadata"][0]["prefix"] == "93.184.216.0/24"
    assert payload["ip_metadata"][0]["country"] == "US"
    assert payload["ip_metadata"][0]["registry"] == "whois.example.net"
    assert payload["certificates"][0]["dns_names"] == ["example.com", "www.example.com"]
    assert any(
        item["entity_type"] == "asn" and item["value"] == "AS15133"
        for item in payload["entities"]
    )
    assert any(
        item["relationship"] == "resolves-to" for item in payload["relationships"]
    )
    assert any(
        item["query"] == "site:example.com" for item in payload["search_queries"]
    )


def test_username_adapters_report_observed_and_absent_profiles(monkeypatch) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.host == "api.github.com":
            return httpx.Response(
                200,
                json={
                    "login": "alice",
                    "html_url": "https://github.com/alice",
                    "name": "Alice",
                    "public_repos": 4,
                },
            )
        if request.url.host == "gitlab.com":
            return httpx.Response(200, json=[])
        if request.url.host == "www.reddit.com":
            return httpx.Response(404, json={})
        if request.url.host == "hacker-news.firebaseio.com":
            return httpx.Response(200, json={"id": "alice", "karma": 12})
        return httpx.Response(404)

    monkeypatch.setattr(
        osint_route, "service", OsintService(transport=httpx.MockTransport(handler))
    )
    response = client.post(
        "/api/v1/osint/investigate", json={"target": "alice", "target_type": "username"}
    )

    assert response.status_code == 200
    profiles = {item["platform"]: item for item in response.json()["username_profiles"]}
    assert profiles["GitHub"]["exists"] is True
    assert profiles["GitLab"]["exists"] is False
    assert profiles["Reddit"]["exists"] is False
    assert profiles["Hacker News"]["attributes"]["karma"] == 12
    assert (
        len(
            [
                item
                for item in response.json()["relationships"]
                if item["relationship"] == "possible-profile"
            ]
        )
        == 2
    )


def test_provider_failures_are_returned_without_fabricated_records(monkeypatch) -> None:
    def offline(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("sensitive internal detail", request=request)

    def broken_whois(domain: str, timeout: float) -> tuple[str, str]:
        del domain, timeout
        raise TimeoutError("offline")

    monkeypatch.setattr(
        osint_route,
        "service",
        OsintService(
            transport=httpx.MockTransport(offline), whois=WhoisAdapter(broken_whois)
        ),
    )
    response = client.post("/api/v1/osint/investigate", json={"target": "example.com"})

    assert response.status_code == 200
    payload = response.json()
    assert payload["dns_records"] == []
    assert payload["certificates"] == []
    assert payload["warnings"]
    assert all(item["status"] in {"error", "no_data"} for item in payload["providers"])
    assert "sensitive internal detail" not in " ".join(payload["warnings"])


def test_private_ip_target_is_rejected() -> None:
    response = client.post(
        "/api/v1/osint/investigate", json={"target": "127.0.0.1", "target_type": "ip"}
    )
    assert response.status_code == 400
    assert response.json()["error"]["code"] == "INVALID_OSINT_TARGET"


def test_url_metadata_and_configured_google_search(monkeypatch) -> None:
    def resolver(
        host: str, port: int, family: int, socktype: int
    ) -> list[tuple[object, ...]]:
        del host, family
        return [(socket.AF_INET, socktype, 6, "", ("93.184.216.34", port))]

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.host == "example.com":
            return httpx.Response(
                200,
                text='<html><head><title>Example</title><meta name="description" content="Public profile"><link rel="canonical" href="/home"></head></html>',
                headers={"Content-Type": "text/html"},
            )
        if request.url.host == "customsearch.googleapis.com":
            return httpx.Response(
                200,
                json={
                    "items": [
                        {
                            "title": "Example result",
                            "link": "https://public.example/result",
                            "snippet": "Public result",
                        }
                    ]
                },
            )
        return httpx.Response(404)

    service = OsintService(
        transport=httpx.MockTransport(handler),
        web_metadata=WebMetadataAdapter(resolver=resolver),
        google_search=GoogleSearchAdapter("test-key", "test-engine"),
    )
    monkeypatch.setattr(osint_route, "service", service)
    response = client.post(
        "/api/v1/osint/investigate",
        json={
            "target": "https://example.com/about#team",
            "target_type": "url",
            "providers": ["web_metadata", "google_search"],
            "include_search_results": True,
        },
    )

    assert response.status_code == 200
    payload = response.json()
    assert payload["web_metadata"]["title"] == "Example"
    assert payload["web_metadata"]["canonical_url"] == "https://example.com/home"
    assert payload["search_results"][0]["url"] == "https://public.example/result"


def test_request_validation_rejects_unknown_provider() -> None:
    response = client.post(
        "/api/v1/osint/investigate",
        json={"target": "example.com", "providers": ["mystery"]},
    )
    assert response.status_code == 422
    assert response.json()["error"]["code"] == "VALIDATION_ERROR"


def test_generated_google_dorks_use_supported_operator_shapes() -> None:
    query_sets = [
        OsintAnalyzer.search_queries("example.com", "domain"),
        OsintAnalyzer.search_queries("alice", "username"),
    ]

    for item in [item for query_set in query_sets for item in query_set]:
        query = str(item["query"])
        assert not re.search(r"\bsite:[^\s)]+/", query)
        assert not re.search(r"\bsite:\*\.", query)
        assert not re.search(r"\b\d{4}\.\.\d{4}\b", query)
        assert "author:" not in query
        assert "filetype:pdf author" not in query

    subdomain_query = next(
        item["query"]
        for item in query_sets[0]
        if item["label"] == "Subdomains"
    )
    assert subdomain_query == "site:example.com -site:www.example.com"
