"""Cel audytu: normalizacja URL i straznik adresow (SSRF).

Straznik rozwiazuje nazwe i odrzuca cel, jesli KTORYKOLWIEK adres nie jest publiczny
(prywatne, loopback, link-local, CGNAT, zarezerwowane). Sprawdzany jest kazdy skok
przekierowania, a polaczenie idzie na sprawdzony adres (bez drugiej rezolucji: DNS rebinding).
"""

from __future__ import annotations

import ipaddress
import socket
from dataclasses import dataclass
from typing import Callable
from urllib.parse import quote, urlsplit, urlunsplit

ALLOWED_SCHEMES = ("http", "https")
DEFAULT_PORTS = {"http": 80, "https": 443}

Resolver = Callable[[str, int], list[str]]


class TargetError(ValueError):
    """Nieprawidlowy albo zablokowany cel."""


class BlockedAddress(TargetError):
    """Cel rozwiazuje sie na adres niepubliczny."""


@dataclass(frozen=True)
class Target:
    scheme: str
    host: str          # ASCII (IDNA), bez nawiasow dla IPv6
    port: int
    path: str          # sciezka + query, zawsze zaczyna sie od "/"

    @property
    def default_port(self) -> bool:
        return DEFAULT_PORTS[self.scheme] == self.port

    @property
    def netloc(self) -> str:
        h = f"[{self.host}]" if ":" in self.host else self.host
        return h if self.default_port else f"{h}:{self.port}"

    @property
    def origin(self) -> str:
        return f"{self.scheme}://{self.netloc}"

    @property
    def url(self) -> str:
        return self.origin + self.path

    def with_path(self, path: str) -> "Target":
        return Target(self.scheme, self.host, self.port, path)

    def with_scheme(self, scheme: str) -> "Target":
        return Target(scheme, self.host, DEFAULT_PORTS[scheme], self.path)


def parse_target(raw: str) -> Target:
    s = raw.strip()
    if not s:
        raise TargetError("pusty adres")
    if "://" not in s:
        s = "https://" + s
    try:
        parts = urlsplit(s)
        port = parts.port
    except ValueError as exc:
        raise TargetError(f"nieprawidłowy adres: {raw!r}") from exc
    scheme = parts.scheme.lower()
    if scheme not in ALLOWED_SCHEMES:
        raise TargetError(f"dozwolone tylko http i https (podano {scheme!r})")
    if parts.username is not None or parts.password is not None:
        raise TargetError("adres z danymi logowania (user@host) nie jest obsługiwany")
    host = (parts.hostname or "").rstrip(".")
    if not host:
        raise TargetError(f"brak nazwy hosta: {raw!r}")
    if any(c in host for c in " \t\r\n/\\"):
        raise TargetError(f"nieprawidłowa nazwa hosta: {raw!r}")
    if not _is_ip(host):
        try:
            host = host.encode("idna").decode("ascii").lower()
        except UnicodeError as exc:
            raise TargetError(f"nieprawidłowa nazwa hosta: {raw!r}") from exc
        if len(host) > 253 or any(not 0 < len(label) <= 63 for label in host.split(".")):
            raise TargetError(f"nieprawidłowa nazwa hosta: {raw!r}")
    path = urlunsplit(("", "", parts.path or "/", parts.query, ""))
    if not path.startswith("/"):
        path = "/" + path
    if any(ord(c) < 0x21 or ord(c) == 0x7F for c in path):
        raise TargetError("ścieżka zawiera znaki sterujące lub spacje")
    # http.client wysyla sciezke jako ASCII: znaki spoza ASCII kodujemy procentowo
    path = quote(path, safe="!#$%&'()*+,/:;=?@[]~")
    return Target(scheme, host, port or DEFAULT_PORTS[scheme], path)


def _is_ip(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


def system_resolver(host: str, port: int) -> list[str]:
    infos = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    out: list[str] = []
    for info in infos:
        ip = info[4][0]
        if ip not in out:
            out.append(ip)
    return out


# NAT64 (RFC 6052 / RFC 8215): IPv4 osadzony w ostatnich 32 bitach. Translator moglby
# przetlumaczyc "globalny" IPv6 na prywatny IPv4, wiec oceniamy osadzony adres.
_NAT64 = (ipaddress.ip_network("64:ff9b::/96"), ipaddress.ip_network("64:ff9b:1::/48"))


def _embedded_ipv4(addr: ipaddress.IPv6Address) -> ipaddress.IPv4Address | None:
    if addr.ipv4_mapped is not None:
        return addr.ipv4_mapped
    if any(addr in net for net in _NAT64):
        return ipaddress.IPv4Address(int(addr) & 0xFFFFFFFF)
    if addr.sixtofour is not None:
        return addr.sixtofour
    if addr.teredo is not None:
        return addr.teredo[1]
    return None


def is_public(ip: str) -> bool:
    addr = ipaddress.ip_address(ip.split("%", 1)[0])
    if isinstance(addr, ipaddress.IPv6Address):
        if addr.ipv4_mapped is not None:
            addr = addr.ipv4_mapped
        else:
            inner = _embedded_ipv4(addr)
            if inner is not None and not (inner.is_global and not inner.is_multicast):
                return False
    return addr.is_global and not addr.is_multicast


def resolve_checked(host: str, port: int, resolver: Resolver, allow_private: bool = False) -> list[str]:
    """Adresy hosta po kontroli. Brak adresow albo jakikolwiek niepubliczny -> wyjatek."""
    try:
        ips = resolver(host, port)
    except OSError as exc:
        raise TargetError(f"nie udało się rozwiązać {host}: {exc}") from exc
    if not ips:
        raise TargetError(f"{host} nie ma adresu")
    if not allow_private:
        bad = [ip for ip in ips if not is_public(ip)]
        if bad:
            raise BlockedAddress(
                f"{host} wskazuje na adres niepubliczny ({', '.join(bad)}); "
                "audyt sieci lokalnej tylko z --allow-private"
            )
    return ips
