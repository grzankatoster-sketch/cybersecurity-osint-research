"""Wspólna normalizacja adresów URL (deduplikacja serwisów w sources.py, porównania linków w correlate.py).

Zasady: schemat i host małymi literami, bez „www.”; ścieżka z zachowaną wielkością liter (na wielu serwisach
/User i /user to różne zasoby), bez ukośnika końcowego; query zachowane (posortowane) — bywa jedynym nośnikiem
identyfikatora; fragment pomijany. Niepoprawny adres (np. `http://[bad`) daje pusty tekst, nigdy wyjątek."""
from __future__ import annotations

from urllib.parse import parse_qsl, urlencode, urlsplit


def normalize_url(url: str, keep_fragment: bool = False) -> str:
    try:
        parts = urlsplit(url.strip())
        host = (parts.hostname or "").lower()
        port = parts.port
    except (ValueError, AttributeError):
        return ""
    host = host.removeprefix("www.")
    if port:
        host += f":{port}"
    if not host and not parts.path:
        return ""
    query = urlencode(sorted(parse_qsl(parts.query, keep_blank_values=True)))
    out = host + parts.path.rstrip("/") + ("?" + query if query else "")
    if keep_fragment and parts.fragment:
        out += "#" + parts.fragment
    return out


def is_http_url(url: str) -> bool:
    """Czy to poprawny adres http/https z hostem (bez znaków sterujących i spacji). Do atrybutów href i celów zapytań."""
    if not isinstance(url, str) or not url or any(ord(c) <= 0x20 or ord(c) == 0x7F for c in url):
        return False
    try:
        parts = urlsplit(url)
        parts.port  # noqa: B018 — wymusza walidację portu
    except ValueError:
        return False
    return parts.scheme.lower() in ("http", "https") and bool(parts.hostname)
