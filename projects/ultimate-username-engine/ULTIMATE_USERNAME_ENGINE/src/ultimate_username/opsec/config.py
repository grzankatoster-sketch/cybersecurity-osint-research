"""Configuration for the OSINT_OPSEC proxy, sourced from the environment.

No secrets are ever written back to the repository; the proxy-auth token and
upstream URL are read from the process environment only. See
``env.opsec.example`` for the documented variable set.
"""

from __future__ import annotations

import os
import re
from collections.abc import Mapping
from dataclasses import dataclass, field

from ultimate_username.opsec.policy import EgressPolicy

_TRUE = frozenset({"1", "true", "yes", "on"})
_FALSE = frozenset({"0", "false", "no", "off"})
_PORT = re.compile(r"[0-9]{1,5}")


def _as_bool(
    name: str, value: str | None, default: bool, errors: list[str], *, on_invalid: bool
) -> bool:
    """Strict boolean: unknown spellings are errors and resolve to the safer value."""

    if value is None or value.strip() == "":
        return default
    word = value.strip().lower()
    if word in _TRUE:
        return True
    if word in _FALSE:
        return False
    errors.append(f"{name}: invalid boolean (expected 1/0, true/false, yes/no, on/off)")
    return on_invalid


def _as_int(
    name: str, value: str | None, default: int, errors: list[str], *, low: int, high: int
) -> int:
    if value is None or value.strip() == "":
        return default
    try:
        number = int(value.strip())
    except ValueError:
        errors.append(f"{name}: not an integer")
        return default
    if not low <= number <= high:
        errors.append(f"{name}: out of range {low}-{high}")
        return default
    return number


def _split(value: str | None) -> frozenset[str]:
    if not value:
        return frozenset()
    return frozenset(item.strip() for item in value.replace(";", ",").split(",") if item.strip())


def _ports(value: str | None, errors: list[str]) -> frozenset[int]:
    """Explicit port list; any malformed entry is an error (never "all ports")."""

    if value is None or value.strip() == "":
        return frozenset({443})
    items = _split(value)
    ports: set[int] = set()
    for item in items:
        if not _PORT.fullmatch(item) or not 1 <= int(item) <= 65535:
            errors.append("OSINT_PROXY_ALLOWED_PORTS: invalid port entry")
            return frozenset({443})
        ports.add(int(item))
    if not ports:
        errors.append("OSINT_PROXY_ALLOWED_PORTS: empty port list")
        return frozenset({443})
    return frozenset(ports)


@dataclass(frozen=True, slots=True)
class ProxyConfig:
    enabled: bool = False
    bind_host: str = "127.0.0.1"
    bind_port: int = 8080
    upstream_url: str | None = None
    timeout: float = 10.0
    fail_closed: bool = True
    log_level: str = "WARNING"
    auth_token: str | None = None
    allowed_hosts: frozenset[str] = field(default_factory=frozenset)
    allowed_ports: frozenset[int] = field(default_factory=lambda: frozenset({443}))
    require_allowlist: bool = True
    # Parse errors from load(); any entry makes validate() refuse start-up (fail-closed).
    errors: tuple[str, ...] = ()

    def policy(self) -> EgressPolicy:
        return EgressPolicy(
            allowed_hosts=self.allowed_hosts,
            allowed_ports=self.allowed_ports,
            allowed_schemes=frozenset({"https"}),
            require_allowlist=self.require_allowlist,
            block_private_ips=True,
        )

    def validate(self) -> list[str]:
        """Return configuration errors that must stop start-up (fail-closed)."""

        problems: list[str] = list(self.errors)
        if self.timeout <= 0:
            problems.append("timeout must be positive")
        if self.bind_host not in ("127.0.0.1", "::1", "localhost") and self.auth_token is None:
            problems.append(
                "non-loopback bind requires OSINT_PROXY_AUTH_TOKEN (refusing to run an open proxy)"
            )
        if self.fail_closed and self.require_allowlist and not self.allowed_hosts:
            problems.append(
                "fail-closed with an empty allowlist denies all traffic; "
                "set OSINT_PROXY_ALLOWED_HOSTS or disable OSINT_PROXY_REQUIRE_ALLOWLIST"
            )
        if self.bind_port < 0 or self.bind_port > 65535:
            problems.append("bind port out of range")
        return problems


def load(env: Mapping[str, str] | None = None) -> ProxyConfig:
    """Read the proxy configuration; malformed values are recorded in ``errors``.

    Safe fallbacks: an unparseable ``OSINT_PROXY_ENABLED`` enables the proxy (so ``validate`` runs
    and refuses start-up instead of silently sending direct traffic); unparseable
    ``OSINT_PROXY_FAIL_CLOSED`` / ``OSINT_PROXY_REQUIRE_ALLOWLIST`` stay ``True``; a malformed port
    list falls back to 443 and is reported.
    """

    src = os.environ if env is None else env
    errors: list[str] = []
    token = src.get("OSINT_PROXY_AUTH_TOKEN") or None
    config = ProxyConfig(
        enabled=_as_bool(
            "OSINT_PROXY_ENABLED", src.get("OSINT_PROXY_ENABLED"), False, errors, on_invalid=True
        ),
        bind_host=src.get("OSINT_PROXY_BIND_HOST") or "127.0.0.1",
        bind_port=_as_int(
            "OSINT_PROXY_BIND_PORT",
            src.get("OSINT_PROXY_BIND_PORT"),
            8080,
            errors,
            low=0,
            high=65535,
        ),
        upstream_url=(src.get("OSINT_PROXY_UPSTREAM_URL") or None),
        timeout=float(
            _as_int(
                "OSINT_PROXY_TIMEOUT", src.get("OSINT_PROXY_TIMEOUT"), 10, errors, low=1, high=600
            )
        ),
        fail_closed=_as_bool(
            "OSINT_PROXY_FAIL_CLOSED",
            src.get("OSINT_PROXY_FAIL_CLOSED"),
            True,
            errors,
            on_invalid=True,
        ),
        log_level=(src.get("OSINT_PROXY_LOG_LEVEL") or "WARNING").upper(),
        auth_token=token,
        allowed_hosts=_split(src.get("OSINT_PROXY_ALLOWED_HOSTS")),
        allowed_ports=_ports(src.get("OSINT_PROXY_ALLOWED_PORTS"), errors),
        require_allowlist=_as_bool(
            "OSINT_PROXY_REQUIRE_ALLOWLIST",
            src.get("OSINT_PROXY_REQUIRE_ALLOWLIST"),
            True,
            errors,
            on_invalid=True,
        ),
        errors=tuple(errors),
    )
    return config
