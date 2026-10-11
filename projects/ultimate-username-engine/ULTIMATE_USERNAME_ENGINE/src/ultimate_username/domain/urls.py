"""URL identity and component encoding; never interpret a username as a URL."""

from __future__ import annotations

import hashlib
import ipaddress
import json
import socket
import string
from collections.abc import Callable, Sequence
from urllib.parse import quote, urlsplit

from ultimate_username.domain.models import TransportRequest


def origin(url: str) -> str:
    parsed = urlsplit(url)
    if parsed.scheme not in ("http", "https") or not parsed.hostname:
        raise ValueError("Expected absolute HTTP(S) URL")
    if parsed.username is not None or parsed.password is not None:
        raise ValueError("Credentials in URLs are not supported")
    if any(c.isspace() or ord(c) < 32 for c in url):
        raise ValueError("URL contains whitespace/control characters")
    host = parsed.hostname.encode("idna").decode("ascii").lower()
    if any(c in host for c in "{}\\%") or host.startswith(".") or ".." in host:
        raise ValueError("Invalid hostname")
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    formatted_host = f"[{host}]" if ":" in host else host
    return f"{parsed.scheme}://{formatted_host}:{port}"


# Registrable domains with a two-label public suffix (co.uk, com.br ...) keep three labels.
# A small built-in list, not the full Public Suffix List.
_SECOND_LEVEL = ("co", "com", "org", "net", "gov", "edu", "ac", "or", "ne", "go")
_COUNTRIES = (
    "uk br jp au tr nz za in kr mx ar cn hk sg tw il id my th ph vn ua pl pe ve cl eg sa ng ke "
    "pk bd ru"
).split()
_TWO_LEVEL_SUFFIXES = frozenset(f"{s}.{c}" for s in _SECOND_LEVEL for c in _COUNTRIES) | {
    "me.uk",
    "ltd.uk",
    "plc.uk",
    "info.pl",
}


def host_without_www(host: str) -> str:
    host = host.lower().rstrip(".")
    return host[4:] if host.startswith("www.") and len(host) > 4 else host


def registrable_domain(host: str) -> str:
    """Approximate eTLD+1: last two labels, last three under a known two-level suffix."""
    labels = host.lower().rstrip(".").split(".")
    if len(labels) <= 2:
        return ".".join(labels)
    if ".".join(labels[-2:]) in _TWO_LEVEL_SUFFIXES:
        return ".".join(labels[-3:])
    return ".".join(labels[-2:])


_LOCAL_SUFFIXES = (
    ".localhost",
    ".local",
    ".internal",
    ".lan",
    ".home",
    ".localdomain",
    ".home.arpa",
)


_HOST_FORBIDDEN = frozenset(chr(c) for c in (47, 92, 64))  # / \ @


def numeric_ipv4(host: str) -> ipaddress.IPv4Address | None:
    """The IPv4 address a resolver would read from ``host``, e.g. ``127.1`` or ``0x7f000001``.

    ``socket.inet_aton`` accepts the legacy short, octal, hexadecimal and 32-bit decimal forms
    that browsers and ``getaddrinfo`` also accept; ``ipaddress`` does not.
    """
    try:
        return ipaddress.IPv4Address(socket.inet_aton(host))
    except (OSError, ValueError):
        return None


def is_local_name(host: str) -> bool:
    """``localhost`` and the well-known local-only suffixes never name a public host."""
    host = host.lower().rstrip(".")
    return host == "localhost" or host.endswith(_LOCAL_SUFFIXES)


def _address_is_public(ip: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped is not None:
        ip = ip.ipv4_mapped
    return ip.is_global and not ip.is_multicast


def is_public_host(host: str, resolver: Callable[[str], Sequence[str]] | None = None) -> bool:
    """False for non-global IP literals (any numeric spelling) and for local-only names.

    With a ``resolver`` (host -> address strings) a name is also rejected when any resolved
    address is not public, which is how DNS names pointing at internal hosts are caught. A name
    that does not resolve is not a request target, so it passes (the transport reports DNS).
    """
    host = host.strip().strip("[]").lower().rstrip(".")
    if not host or any(c.isspace() or c in _HOST_FORBIDDEN for c in host):
        return False
    try:
        literal: ipaddress.IPv4Address | ipaddress.IPv6Address | None = ipaddress.ip_address(host)
    except ValueError:
        literal = numeric_ipv4(host)
    if literal is not None:
        return _address_is_public(literal)
    if ":" in host or host.startswith("0x"):
        return False  # IPv6 with a zone id, or a malformed numeric form
    if "." not in host or is_local_name(host):
        return False
    if resolver is None:
        return True
    try:
        addresses = list(resolver(host))
    except Exception:  # noqa: BLE001 - nothing resolves, so nothing is contacted
        return True
    for address in addresses:
        try:
            if not _address_is_public(ipaddress.ip_address(address.split("%", 1)[0])):
                return False
        except ValueError:
            return False
    return True


def validate_template(template: str) -> None:
    parts = urlsplit(template)
    if "{" in parts.netloc or "}" in parts.netloc:
        raise ValueError("Username placeholder cannot alter origin")
    if parts.fragment:
        raise ValueError("URL fragments are not sent to HTTP servers")
    for _, field, spec, conversion in string.Formatter().parse(template):
        if field is not None and (field != "username" or spec or conversion):
            raise ValueError("Only plain {username} placeholder is supported")
    rendered = template.format(username="validation")
    origin(rendered)


def render_url(template: str, username: str) -> str:
    validate_template(template)
    return template.format(username=quote(username, safe=""))


def request_key(request: TransportRequest) -> str:
    """Preserve path case/query/body/context; normalize only origin/header names."""
    p = urlsplit(request.url)
    data = [
        request.method.value,
        origin(request.url),
        p.path,
        p.query,
        sorted((k.lower(), v) for k, v in request.headers),
        hashlib.sha256(request.body or b"").hexdigest(),
        request.context_id,
    ]
    return hashlib.sha256(json.dumps(data, ensure_ascii=False).encode()).hexdigest()
