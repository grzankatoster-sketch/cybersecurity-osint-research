"""Redaction helpers so diagnostics never carry secrets or full identifiers.

Used by the forward proxy and the guard before anything reaches a log sink.
Data minimisation is the default: emails, tokens, cookies and ``Authorization``
material are masked; URLs keep only scheme + host (+ port).
"""

from __future__ import annotations

import re
from collections.abc import Iterable, Mapping
from urllib.parse import urlsplit

_PLACEHOLDER = "<REDACTED>"

_EMAIL = re.compile(r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}")
# Long opaque secrets: JWTs, bearer tokens, API keys, hex/base64 blobs.
_BEARER = re.compile(r"(?i)\b(bearer|token|apikey|api_key|secret|password)\s*[:=]\s*\S+")
_JWT = re.compile(r"\beyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\b")
_LONG_TOKEN = re.compile(r"\b[A-Za-z0-9_\-]{32,}\b")

_SENSITIVE_HEADERS = frozenset(
    {"authorization", "proxy-authorization", "cookie", "set-cookie", "x-api-key", "x-auth-token"}
)


def mask_email(value: str) -> str:
    """Keep only the first character of the local part and the TLD shape."""

    def _mask(match: re.Match[str]) -> str:
        local, _, domain = match.group(0).partition("@")
        head = local[0] if local else ""
        return f"{head}***@{_PLACEHOLDER}"

    return _EMAIL.sub(_mask, value)


def redact_text(value: str) -> str:
    out = _JWT.sub(_PLACEHOLDER, value)
    out = _BEARER.sub(lambda m: f"{m.group(1)}={_PLACEHOLDER}", out)
    out = mask_email(out)
    out = _LONG_TOKEN.sub(_PLACEHOLDER, out)
    return out


def redact_url(url: str) -> str:
    """Reduce a URL to ``scheme://host[:port]`` - no path, query or credentials."""

    parts = urlsplit(url)
    if not parts.scheme or not parts.hostname:
        return redact_text(url)
    netloc = parts.hostname
    if parts.port is not None:
        netloc = f"{netloc}:{parts.port}"
    return f"{parts.scheme}://{netloc}"


def redact_headers(headers: Mapping[str, str] | Iterable[tuple[str, str]]) -> dict[str, str]:
    items = headers.items() if isinstance(headers, Mapping) else headers
    result: dict[str, str] = {}
    for name, value in items:
        result[name] = _PLACEHOLDER if name.lower() in _SENSITIVE_HEADERS else redact_text(value)
    return result
