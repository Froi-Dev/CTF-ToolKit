from __future__ import annotations

import hashlib
from urllib.parse import quote_plus

from app.core.analyzers import BaseAnalyzer
from app.integrations.osint.base import AdapterOutput


class OsintAnalyzer(
    BaseAnalyzer[dict[str, object], dict[str, list[dict[str, object]]]]
):
    name = "passive-osint"
    category = "osint"

    def supports(self, value: object) -> bool:
        return isinstance(value, dict) and isinstance(
            value.get("normalized_target"), str
        )

    def analyze(self, value: dict[str, object]) -> dict[str, list[dict[str, object]]]:
        if not self.supports(value):
            raise ValueError("OSINT analyzer received an unsupported input.")
        target = str(value["normalized_target"])
        target_type = str(value["target_type"])
        subject_type = str(value.get("subject_type") or target_type)
        domain = str(value.get("domain") or "")
        outputs = value.get("outputs", [])
        provider_outputs = (
            [output for output in outputs if isinstance(output, AdapterOutput)]
            if isinstance(outputs, list)
            else []
        )

        entities: dict[str, dict[str, object]] = {}
        relationships: dict[tuple[str, str, str], dict[str, object]] = {}

        root_kind = subject_type
        root_value = (
            domain
            if root_kind == "domain"
            else (str(value.get("subject") or target) if root_kind == "ip" else target)
        )
        root_id = self._entity(entities, root_kind, root_value, "request")

        for output in provider_outputs:
            for record in output.records:
                if output.name == "dns":
                    self._dns(record, root_id, entities, relationships, output.name)
                elif output.name == "whois":
                    self._whois(record, root_id, entities, relationships, output.name)
                elif output.name == "rdap":
                    self._rdap(record, root_id, entities, relationships, output.name)
                elif output.name == "certificates":
                    self._certificate(
                        record, root_id, entities, relationships, output.name
                    )
                elif output.name == "ip_metadata":
                    self._ip(
                        record,
                        entities,
                        relationships,
                        output.name,
                        root_id if root_kind == "ip" else None,
                    )
                elif (
                    output.name.startswith("usernames:")
                    and record.get("exists") is True
                ):
                    account_id = self._entity(
                        entities,
                        "account",
                        str(record.get("profile_url")),
                        output.name,
                        {
                            "platform": record.get("platform"),
                            "username": record.get("username"),
                        },
                    )
                    self._relationship(
                        relationships,
                        root_id,
                        account_id,
                        "possible-profile",
                        0.85,
                        output.name,
                    )
                elif output.name == "web_metadata":
                    page_id = self._entity(
                        entities, "url", str(record.get("final_url")), output.name
                    )
                    self._relationship(
                        relationships,
                        root_id,
                        page_id,
                        "has-web-page",
                        1.0,
                        output.name,
                    )
                    canonical = record.get("canonical_url")
                    if canonical:
                        canonical_id = self._entity(
                            entities, "url", str(canonical), output.name
                        )
                        self._relationship(
                            relationships,
                            page_id,
                            canonical_id,
                            "declares-canonical",
                            1.0,
                            output.name,
                        )
                elif output.name == "google_search" and record.get("url"):
                    result_id = self._entity(
                        entities,
                        "url",
                        str(record["url"]),
                        output.name,
                        {"title": record.get("title")},
                    )
                    self._relationship(
                        relationships,
                        root_id,
                        result_id,
                        "appears-in-search-result",
                        0.8,
                        output.name,
                    )

        return {
            "entities": list(entities.values())[:500],
            "relationships": list(relationships.values())[:750],
            "search_queries": self.search_queries(root_value, root_kind),
        }

    @staticmethod
    def search_queries(target: str, target_type: str) -> list[dict[str, object]]:
        if target_type == "domain":
            queries = [
                ("Indexed pages", f"site:{target}"),
                (
                    "Documents",
                    f"site:{target} (filetype:pdf OR filetype:docx OR filetype:xlsx)",
                ),
                (
                    "Authentication surfaces",
                    f"site:{target} (inurl:login OR inurl:signin OR inurl:admin)",
                ),
                (
                    "Public configuration",
                    f"site:{target} (ext:env OR ext:yaml OR ext:json OR ext:conf)",
                ),
                ("Subdomains", f"site:{target} -site:www.{target}"),
            ]
        elif target_type == "username":
            quoted = f'"{target}"'
            queries = [
                ("Exact username", quoted),
                (
                    "Developer profiles",
                    f"{quoted} (site:github.com OR site:gitlab.com)",
                ),
                (
                    "Social profiles",
                    f"{quoted} (site:reddit.com OR site:medium.com OR site:dev.to)",
                ),
                (
                    "Documents",
                    f"{quoted} (filetype:pdf OR filetype:txt OR filetype:csv)",
                ),
            ]
        elif target_type == "ip":
            queries = [
                ("Exact IP", f'"{target}"'),
                ("Public reports", f'"{target}" (report OR scan OR abuse)'),
            ]
        else:
            queries = [("Exact URL", f'"{target}"')]
        return [
            {
                "label": label,
                "query": query,
                "google_url": f"https://www.google.com/search?q={quote_plus(query)}",
            }
            for label, query in queries
        ]

    def _dns(
        self,
        record: dict[str, object],
        root_id: str,
        entities: dict[str, dict[str, object]],
        relationships: dict[tuple[str, str, str], dict[str, object]],
        source: str,
    ) -> None:
        record_type = str(record.get("record_type", ""))
        value = str(record.get("value", ""))
        mapping = {
            "A": ("ip", "resolves-to"),
            "AAAA": ("ip", "resolves-to"),
            "NS": ("domain", "uses-name-server"),
            "MX": ("domain", "mail-handled-by"),
            "CNAME": ("domain", "aliases-to"),
        }
        if record_type not in mapping or not value:
            return
        entity_type, relationship = mapping[record_type]
        target_id = self._entity(entities, entity_type, value, source)
        self._relationship(
            relationships,
            root_id,
            target_id,
            relationship,
            1.0,
            source,
            {"record_type": record_type},
        )

    def _whois(
        self,
        record: dict[str, object],
        root_id: str,
        entities: dict[str, dict[str, object]],
        relationships: dict[tuple[str, str, str], dict[str, object]],
        source: str,
    ) -> None:
        for key, relation in (
            ("registrar", "registered-with"),
            ("organization", "registration-associated-with"),
        ):
            if record.get(key):
                entity_id = self._entity(
                    entities, "organization", str(record[key]), source
                )
                self._relationship(
                    relationships, root_id, entity_id, relation, 0.95, source
                )
        for nameserver in (
            record.get("nameservers", [])
            if isinstance(record.get("nameservers"), list)
            else []
        ):
            entity_id = self._entity(entities, "domain", str(nameserver), source)
            self._relationship(
                relationships, root_id, entity_id, "uses-name-server", 1.0, source
            )

    def _rdap(
        self,
        record: dict[str, object],
        root_id: str,
        entities: dict[str, dict[str, object]],
        relationships: dict[tuple[str, str, str], dict[str, object]],
        source: str,
    ) -> None:
        for nameserver in (
            record.get("nameservers", [])
            if isinstance(record.get("nameservers"), list)
            else []
        ):
            entity_id = self._entity(entities, "domain", str(nameserver), source)
            self._relationship(
                relationships, root_id, entity_id, "uses-name-server", 1.0, source
            )
        for entity in (
            record.get("entities", [])
            if isinstance(record.get("entities"), list)
            else []
        ):
            if not isinstance(entity, dict):
                continue
            name = entity.get("org") or entity.get("fn")
            if name:
                entity_id = self._entity(
                    entities,
                    "organization",
                    str(name),
                    source,
                    {"roles": entity.get("roles", [])},
                )
                self._relationship(
                    relationships,
                    root_id,
                    entity_id,
                    "rdap-associated-with",
                    0.9,
                    source,
                )

    def _certificate(
        self,
        record: dict[str, object],
        root_id: str,
        entities: dict[str, dict[str, object]],
        relationships: dict[tuple[str, str, str], dict[str, object]],
        source: str,
    ) -> None:
        certificate_id = self._entity(
            entities,
            "certificate",
            str(record.get("certificate_id")),
            source,
            {"issuer": record.get("issuer"), "not_after": record.get("not_after")},
        )
        self._relationship(
            relationships,
            root_id,
            certificate_id,
            "observed-in-certificate",
            1.0,
            source,
        )
        for domain in (
            record.get("dns_names", [])
            if isinstance(record.get("dns_names"), list)
            else []
        ):
            domain_id = self._entity(entities, "domain", str(domain), source)
            self._relationship(
                relationships,
                certificate_id,
                domain_id,
                "certificate-covers",
                1.0,
                source,
            )

    def _ip(
        self,
        record: dict[str, object],
        entities: dict[str, dict[str, object]],
        relationships: dict[tuple[str, str, str], dict[str, object]],
        source: str,
        root_id: str | None,
    ) -> None:
        address = str(record.get("address", ""))
        ip_id = self._entity(
            entities,
            "ip",
            address,
            source,
            {"prefix": record.get("prefix"), "reverse_dns": record.get("reverse_dns")},
        )
        if root_id and root_id != ip_id:
            self._relationship(relationships, root_id, ip_id, "refers-to", 1.0, source)
        for asn in (
            record.get("asns", []) if isinstance(record.get("asns"), list) else []
        ):
            asn_id = self._entity(entities, "asn", f"AS{asn}", source)
            self._relationship(
                relationships, ip_id, asn_id, "announced-by", 1.0, source
            )
        reverse = record.get("reverse_dns")
        if reverse:
            reverse_id = self._entity(entities, "domain", str(reverse), source)
            self._relationship(
                relationships, ip_id, reverse_id, "reverse-resolves-to", 1.0, source
            )

    @staticmethod
    def _entity(
        entities: dict[str, dict[str, object]],
        entity_type: str,
        value: str,
        source: str,
        attributes: dict[str, object] | None = None,
    ) -> str:
        normalized = value.strip()
        entity_id = hashlib.sha256(
            f"{entity_type}:{normalized.lower()}".encode()
        ).hexdigest()[:20]
        existing = entities.get(entity_id)
        if existing:
            sources = existing["sources"]
            if isinstance(sources, list) and source not in sources:
                sources.append(source)
            if attributes:
                existing_attributes = existing["attributes"]
                if isinstance(existing_attributes, dict):
                    existing_attributes.update(
                        {
                            key: value
                            for key, value in attributes.items()
                            if value is not None
                        }
                    )
        else:
            entities[entity_id] = {
                "id": entity_id,
                "entity_type": entity_type,
                "value": normalized,
                "attributes": {
                    key: value
                    for key, value in (attributes or {}).items()
                    if value is not None
                },
                "sources": [source],
            }
        return entity_id

    @staticmethod
    def _relationship(
        relationships: dict[tuple[str, str, str], dict[str, object]],
        source_id: str,
        target_id: str,
        relationship: str,
        confidence: float,
        provider: str,
        attributes: dict[str, object] | None = None,
    ) -> None:
        key = (source_id, target_id, relationship)
        existing = relationships.get(key)
        if existing:
            sources = existing["sources"]
            if isinstance(sources, list) and provider not in sources:
                sources.append(provider)
        else:
            relationships[key] = {
                "source_id": source_id,
                "target_id": target_id,
                "relationship": relationship,
                "confidence": confidence,
                "sources": [provider],
                "attributes": attributes or {},
            }
