"""Operator-authorised API credentials for site definitions (deny by default).

A site definition may name an environment variable in ``credential_env``. Catalogues are
third-party data, so that name alone never grants access to the process environment. A
credential is attached to a request only when all of the following hold:

1. the variable name matches ``UEE_CRED_[A-Z0-9_]+`` (generic names such as
   ``AWS_SECRET_ACCESS_KEY`` or ``GITHUB_TOKEN`` are never read);
2. the operator authorised the variable for specific hosts in ``UEE_CREDENTIAL_SCOPES``, e.g.
   ``UEE_CREDENTIAL_SCOPES="UEE_CRED_EXAMPLE=api.example.com|api2.example.com,UEE_CRED_B=b.test"``;
3. the request goes over ``https`` to one of those hosts exactly (no parent-domain matching, no
   userinfo in the URL, default port 443 only);
4. the value is non-empty and contains no CR/LF.

Anything else yields no credential, so the request is skipped as ``API_CREDENTIAL_REQUIRED``.
The credential value is never logged or returned in a reason string.
"""

from __future__ import annotations

import os
import re
from collections.abc import Mapping
from dataclasses import dataclass
from urllib.parse import urlsplit

CREDENTIAL_PREFIX = "UEE_CRED_"
SCOPES_ENV = "UEE_CREDENTIAL_SCOPES"
_NAME = re.compile(r"UEE_CRED_[A-Z0-9_]{1,64}")
_HOST = re.compile(
    r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+"
)


def valid_credential_name(name: str) -> bool:
    return _NAME.fullmatch(name) is not None


@dataclass(frozen=True, slots=True)
class CredentialDecision:
    value: str | None
    reason: str  # never contains the credential value


def parse_scopes(raw: str | None) -> tuple[dict[str, frozenset[str]], list[str]]:
    """Parse ``NAME=host|host,NAME2=host``; malformed entries are reported and ignored."""

    scopes: dict[str, frozenset[str]] = {}
    errors: list[str] = []
    if not raw or not raw.strip():
        return scopes, errors
    for entry in raw.replace(";", ",").split(","):
        entry = entry.strip()
        if not entry:
            continue
        name, sep, hosts_raw = entry.partition("=")
        name = name.strip()
        if not sep or not valid_credential_name(name):
            errors.append(f"{SCOPES_ENV}: invalid entry for {name or '<empty>'!r}")
            continue
        hosts = {h.strip().rstrip(".").lower() for h in hosts_raw.split("|") if h.strip()}
        bad = sorted(h for h in hosts if not _HOST.fullmatch(h))
        if not hosts or bad:
            errors.append(f"{SCOPES_ENV}: {name} needs one or more plain host names")
            continue
        scopes[name] = scopes.get(name, frozenset()) | frozenset(hosts)
    return scopes, errors


def resolve_credential(
    credential_env: str, url: str, env: Mapping[str, str] | None = None
) -> CredentialDecision:
    """Return the credential for ``url`` only if the operator authorised it for that host."""

    src = os.environ if env is None else env
    if not credential_env:
        return CredentialDecision(None, "no credential configured")
    if not valid_credential_name(credential_env):
        return CredentialDecision(None, f"credential name must start with {CREDENTIAL_PREFIX}")
    scopes, _ = parse_scopes(src.get(SCOPES_ENV))
    allowed = scopes.get(credential_env)
    if not allowed:
        return CredentialDecision(None, f"{credential_env} is not authorised in {SCOPES_ENV}")
    try:
        parts = urlsplit(url)
        port = parts.port
    except ValueError:
        return CredentialDecision(None, "invalid destination URL")
    host = (parts.hostname or "").rstrip(".").lower()
    if parts.scheme.lower() != "https":
        return CredentialDecision(None, "credentials are sent over https only")
    if parts.username is not None or parts.password is not None:
        return CredentialDecision(None, "credentials are not sent to URLs with userinfo")
    if port not in (None, 443):
        return CredentialDecision(None, "credentials are sent to port 443 only")
    if host not in allowed:
        return CredentialDecision(None, f"{credential_env} is not authorised for this host")
    value = src.get(credential_env)
    if not value or any(c in value for c in "\r\n"):
        return CredentialDecision(None, f"{credential_env} is empty or malformed")
    return CredentialDecision(value, "authorised")
