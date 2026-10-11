"""Informacje o adresie IP: ipinfo.io (bez tokenu lub z IPINFO_TOKEN) + odwrotny DNS (PTR) jako drugie zrodlo.

Adresy prywatne i zarezerwowane sa opisywane lokalnie, bez zadnego zapytania (ani do ipinfo, ani do DNS).
"""

from __future__ import annotations

import ipaddress
import json
import re
import socket
import threading
from dataclasses import dataclass, field
from typing import Callable

from .http import Fetch, FetchError

IPINFO_URL = "https://ipinfo.io/{ip}/json"
TOKEN_ENV = "IPINFO_TOKEN"
_ORG_RE = re.compile(r"^(AS\d+)\s+(.+)$")


def parse_ip(raw: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address:
    text = raw.strip()
    if text.startswith("[") and text.endswith("]"):
        text = text[1:-1]
    try:
        return ipaddress.ip_address(text)
    except ValueError as exc:
        raise ValueError(f"nieprawidłowy adres IP: {raw!r}") from exc


def local_scope(ip: ipaddress.IPv4Address | ipaddress.IPv6Address) -> str | None:
    """Opis, dlaczego adres nie jest publiczny (None = publiczny, mozna pytac zewnetrzne zrodla)."""
    if ip.is_global and not ip.is_multicast:
        return None
    if ip.is_loopback:
        kind = "pętli zwrotnej (loopback)"
    elif ip.is_link_local:
        kind = "link-local"
    elif ip.is_multicast:
        kind = "multicast"
    elif ip.is_unspecified:
        kind = "nieokreślony"
    elif ip.is_private and not ip.is_reserved:
        kind = "prywatny"
    else:
        kind = "zarezerwowany / niepubliczny"
    return f"adres prywatny/zarezerwowany ({kind}); nie wykonano żadnego zapytania sieciowego"


def split_org(org: str | None) -> tuple[str | None, str | None]:
    """'AS15169 Google LLC' -> ('AS15169', 'Google LLC')."""
    if not org:
        return None, None
    m = _ORG_RE.match(org.strip())
    if m:
        return m.group(1), m.group(2).strip()
    return None, org.strip()


@dataclass
class IpInfo:
    ip: str
    hostname: str | None = None
    asn: str | None = None
    org_name: str | None = None
    city: str | None = None
    region: str | None = None
    country: str | None = None
    timezone: str | None = None
    anycast: bool | None = None
    bogon: bool = False

    def to_dict(self) -> dict:
        return {
            "ip": self.ip, "hostname": self.hostname, "asn": self.asn, "org": self.org_name,
            "city": self.city, "region": self.region, "country": self.country,
            "timezone": self.timezone, "anycast": self.anycast, "bogon": self.bogon,
        }


def _s(v) -> str | None:
    return v.strip() if isinstance(v, str) and v.strip() else None


def parse_ipinfo(data: dict, ip: str) -> IpInfo:
    asn, name = split_org(_s(data.get("org")))
    anycast = data.get("anycast")
    return IpInfo(
        ip=_s(data.get("ip")) or ip,
        hostname=_s(data.get("hostname")),
        asn=asn, org_name=name,
        city=_s(data.get("city")), region=_s(data.get("region")),
        country=_s(data.get("country")), timezone=_s(data.get("timezone")),
        anycast=anycast if isinstance(anycast, bool) else None,
        bogon=data.get("bogon") is True,
    )


def fetch_ipinfo(ip: str, fetch: Fetch, timeout: float, token: str | None = None) -> tuple[IpInfo | None, str]:
    """(informacje, blad). Dokladnie jedno z nich jest niepuste. Token idzie tylko w naglowku i nigdy do komunikatow."""
    headers = {"Accept": "application/json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    try:
        resp = fetch(IPINFO_URL.format(ip=ip), headers=headers, timeout=timeout)
    except FetchError as exc:
        return None, str(exc)
    if resp.status == 429:
        return None, f"limit zapytań ipinfo.io (HTTP 429); darmowy limit bez tokenu jest niski (zmienna {TOKEN_ENV})"
    if resp.status in (401, 403):
        return None, f"ipinfo.io odrzuciło zapytanie (HTTP {resp.status}); sprawdź token {TOKEN_ENV}"
    if resp.status != 200:
        return None, f"HTTP {resp.status}"
    try:
        data = json.loads(resp.text)
    except ValueError:
        return None, "nieprawidłowy JSON w odpowiedzi"
    if not isinstance(data, dict):
        return None, "nieoczekiwany format odpowiedzi"
    if "error" in data and "ip" not in data:
        err = data["error"]
        msg = err.get("message") if isinstance(err, dict) else err
        return None, f"ipinfo.io: {str(msg)[:100]}"
    return parse_ipinfo(data, ip), ""


@dataclass
class Rdns:
    """status: ok (nazwy), none (brak PTR: poprawna odpowiedz), error (nie udalo sie sprawdzic)."""

    status: str
    names: list[str] = field(default_factory=list)
    error: str = ""


def reverse_lookup(ip: str, timeout: float,
                   resolver: Callable[[str], tuple] = socket.gethostbyaddr) -> Rdns:
    """PTR przez resolver systemowy. gethostbyaddr nie ma timeoutu, wiec idzie w watku z limitem czasu."""
    box: dict = {}

    def work() -> None:
        try:
            box["res"] = resolver(ip)
        except BaseException as exc:  # noqa: BLE001 - wynik oceniany w watku glownym
            box["exc"] = exc

    t = threading.Thread(target=work, daemon=True)
    t.start()
    t.join(timeout)
    if t.is_alive():
        return Rdns("error", error="przekroczono limit czasu")
    exc = box.get("exc")
    if isinstance(exc, socket.herror):
        return Rdns("none")
    if exc is not None:
        return Rdns("error", error=f"błąd resolvera: {exc}")
    host, aliases, _ = box["res"]
    names = sorted({n.rstrip(".").lower() for n in [host, *aliases] if n and n.rstrip(".").lower() != ip.lower()})
    return Rdns("ok", names) if names else Rdns("none")
