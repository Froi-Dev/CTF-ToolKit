"""Modular passive OSINT provider integrations."""

from app.integrations.osint.certificates import CertificateTransparencyAdapter
from app.integrations.osint.dns import DnsOverHttpsAdapter
from app.integrations.osint.ip_metadata import RipeNetworkInfoAdapter
from app.integrations.osint.rdap import RdapAdapter
from app.integrations.osint.search import GoogleSearchAdapter
from app.integrations.osint.usernames import default_username_adapters
from app.integrations.osint.web_metadata import WebMetadataAdapter
from app.integrations.osint.whois import WhoisAdapter

__all__ = [
    "CertificateTransparencyAdapter",
    "DnsOverHttpsAdapter",
    "GoogleSearchAdapter",
    "RdapAdapter",
    "RipeNetworkInfoAdapter",
    "WebMetadataAdapter",
    "WhoisAdapter",
    "default_username_adapters",
]
