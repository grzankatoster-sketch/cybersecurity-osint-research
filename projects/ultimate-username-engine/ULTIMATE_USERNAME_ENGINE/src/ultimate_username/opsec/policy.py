"""Egress policy: destination allowlisting plus SSRF defence for OSINT_OPSEC.

Pure, dependency-free decision logic shared by the local forward proxy
(``server.py``) and the application-side guard (``guard.py``). No sockets are
opened here; DNS resolution is injected so the logic is fully testable offline.
"""

from __future__ import annotations

import ipaddress
from collections.abc import Callable, Sequence
from dataclasses import dataclass, field
from urllib.parse import urlsplit

from ultimate_username.domain.urls import is_local_name, numeric_ipv4

# Address space that must never be a research egress target. ``is_global`` is the
# final gate; these explicit ranges give precise, auditable reasons and cover the
# cloud instance-metadata endpoints (link-local 169.254.0.0/16 and fd00:ec2::/10).
_FORBIDDEN_V4 = tuple(
    ipaddress.ip_network(n)
    for n in (
        "0.0.0.0/8",
        "10.0.0.0/8",
        "100.64.0.0/10",  # CGNAT / shared address space
        "127.0.0.0/8",
        "169.254.0.0/16",  # link-local incl. 169.254.169.254 metadata
        "172.16.0.0/12",
        "192.0.0.0/24",
        "192.0.2.0/24",
        "192.168.0.0/16",
        "198.18.0.0/15",
        "198.51.100.0/24",
        "203.0.113.0/24",
        "224.0.0.0/4",
        "240.0.0.0/4",
        "255.255.255.255/32",
    )
)
_FORBIDDEN_V6 = tuple(
    ipaddress.ip_network(n)
    for n in (
        "::1/128",
        "::/128",
        "64:ff9b::/96",  # NAT64 to IPv4
        "100::/64",  # discard-only
        "2001:db8::/32",
        "fc00::/7",  # unique-local incl. cloud metadata mirrors
        "fe80::/10",  # link-local
        "ff00::/8",  # multicast
    )
)

Resolver = Callable[[str], Sequence[str]]
"""Maps a hostname to one or more IP address strings. Injected for testability."""


def classify_ip(value: str) -> str | None:
    """Return a human reason if ``value`` is a forbidden egress IP, else ``None``.

    IPv4-mapped IPv6 addresses are unwrapped so ``::ffff:169.254.169.254`` cannot
    smuggle a metadata address past the IPv4 checks.
    """

    try:
        ip: ipaddress.IPv4Address | ipaddress.IPv6Address = ipaddress.ip_address(value)
    except ValueError:
        return "not an IP address"
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped is not None:
        ip = ip.ipv4_mapped
    if ip.is_unspecified:
        return "unspecified address"
    if ip.is_loopback:
        return "loopback"
    if ip.is_link_local:
        return "link-local (cloud metadata range)"
    if ip.is_multicast:
        return "multicast"
    if ip.is_reserved:
        return "reserved"
    if ip.is_private:
        return "private network"
    networks = _FORBIDDEN_V4 if isinstance(ip, ipaddress.IPv4Address) else _FORBIDDEN_V6
    if any(ip in net for net in networks):
        return "forbidden reserved range"
    if not ip.is_global:
        return "non-global address"
    return None


@dataclass(frozen=True, slots=True)
class Decision:
    allowed: bool
    reason: str
    host: str = ""
    port: int | None = None
    resolved_ips: tuple[str, ...] = ()
    dns_failed: bool = False


@dataclass(frozen=True, slots=True)
class EgressPolicy:
    """Deny-by-default destination policy.

    With ``require_allowlist`` and an empty ``allowed_hosts`` the policy denies
    every destination: that is the fail-closed posture. An entry matches a host
    exactly or as a parent domain (``example.com`` matches ``api.example.com``).
    """

    allowed_hosts: frozenset[str] = field(default_factory=frozenset)
    allowed_schemes: frozenset[str] = field(default_factory=lambda: frozenset({"https"}))
    allowed_ports: frozenset[int] = field(default_factory=lambda: frozenset({443}))
    require_allowlist: bool = True
    block_private_ips: bool = True
    allow_userinfo: bool = False

    def _host_allowed(self, host: str) -> bool:
        host = host.rstrip(".").lower()
        if not self.allowed_hosts:
            return not self.require_allowlist
        return any(
            host == entry or host.endswith("." + entry)
            for entry in (e.strip(".").lower() for e in self.allowed_hosts)
        )

    def check_url(self, url: str, resolver: Resolver) -> Decision:
        parts = urlsplit(url)
        scheme = parts.scheme.lower()
        if scheme not in self.allowed_schemes:
            return Decision(False, f"scheme {scheme!r} not allowed")
        if parts.username or parts.password:
            if not self.allow_userinfo:
                return Decision(False, "credentials in URL are not allowed")
        host = parts.hostname or ""
        if not host:
            return Decision(False, "missing host")
        try:
            port = parts.port if parts.port is not None else (443 if scheme == "https" else 80)
        except ValueError:
            return Decision(False, "invalid port")
        return self.check_target(host, port, resolver)

    def check_target(self, host: str, port: int, resolver: Resolver) -> Decision:
        host = host.strip("[]").rstrip(".").lower()
        if not host:
            return Decision(False, "missing host")
        if self.allowed_ports and port not in self.allowed_ports:
            return Decision(False, f"port {port} not allowed", host=host, port=port)
        if not self._host_allowed(host):
            return Decision(False, "host not in allowlist", host=host, port=port)

        # A literal IP in the destination skips DNS; validate it directly. Legacy numeric spellings
        # (127.1, 0177.0.0.1, 2130706433, 0x7f000001) are IPv4 literals to every resolver.
        literal = numeric_ipv4(host)
        try:
            ipaddress.ip_address(host)
            addresses: Sequence[str] = [host]
        except ValueError:
            if literal is not None:
                addresses = [str(literal)]
            elif self.block_private_ips and is_local_name(host):
                return Decision(
                    False,
                    "destination resolves to forbidden address (local-only name)",
                    host=host,
                    port=port,
                )
            else:
                try:
                    addresses = list(resolver(host))
                except Exception as exc:  # noqa: BLE001 - any resolver failure is fail-closed
                    return Decision(
                        False,
                        f"DNS resolution failed: {type(exc).__name__}",
                        host=host,
                        dns_failed=True,
                    )
                if not addresses:
                    return Decision(
                        False, "DNS returned no addresses", host=host, port=port, dns_failed=True
                    )

        if self.block_private_ips:
            for addr in addresses:
                reason = classify_ip(addr)
                if reason is not None:
                    return Decision(
                        False,
                        f"destination resolves to forbidden address ({reason})",
                        host=host,
                        port=port,
                        resolved_ips=tuple(addresses),
                    )
        return Decision(True, "allowed", host=host, port=port, resolved_ips=tuple(addresses))
