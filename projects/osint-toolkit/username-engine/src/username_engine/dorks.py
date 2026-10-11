"""Warstwa wyszukiwarek i archiwum: linki z dorkami (do otwarcia ręcznie — bez scrapowania wyszukiwarek)
oraz Wayback CDX, który pokazuje profile istniejące kiedyś, a dziś usunięte."""
from __future__ import annotations

import json
import re
from dataclasses import dataclass
from urllib.parse import quote_plus, urlencode, urlsplit

from .models import Site
from .sources import site_tags
from .urlnorm import is_http_url

# Serwisy, w których nazwa użytkownika najczęściej pojawia się w URL profilu (do dorka site:)
SOCIAL_DOMAINS = (
    "facebook.com", "instagram.com", "x.com", "twitter.com", "tiktok.com", "youtube.com", "linkedin.com",
    "reddit.com", "github.com", "pinterest.com", "twitch.tv", "medium.com", "threads.com", "threads.net", "t.me",
    "wykop.pl", "filmweb.pl", "olx.pl", "allegro.pl",
)

ENGINES = {
    "google": "https://www.google.com/search?q=",
    "bing": "https://www.bing.com/search?q=",
    "duckduckgo": "https://duckduckgo.com/?q=",
    "yandex": "https://yandex.com/search/?text=",
}

CDX_URL = "https://web.archive.org/cdx/search/cdx"


def _or_group(prefix: str, values: list[str]) -> str:
    return "(" + " OR ".join(f"{prefix}{v}" for v in values) + ")"


def build_queries(names: list[str], domains: tuple[str, ...] = SOCIAL_DOMAINS, chunk: int = 9) -> list[str]:
    """Zapytania: dokładna nazwa (i warianty) w cudzysłowie + grupy site: po `chunk` domen
    (długie zapytania wyszukiwarki obcinają) + wariant inurl: dla profili."""
    if not names:
        return []
    phrase = _or_group("", [f'"{n}"' for n in names]) if len(names) > 1 else f'"{names[0]}"'
    queries = [phrase]
    for i in range(0, len(domains), chunk):
        queries.append(f"{phrase} {_or_group('site:', list(domains[i:i + chunk]))}")
    queries.append(_or_group("inurl:", names) + " -site:" + " -site:".join(("pinterest.com",)))
    return queries


def search_links(queries: list[str], engines: tuple[str, ...] = ("google", "bing", "duckduckgo")) -> list[dict]:
    return [{"engine": e, "query": q, "url": ENGINES[e] + quote_plus(q)} for q in queries for e in engines]


def cdx_query_url(profile_url: str, limit: int = 5) -> str:
    """Zapytanie CDX: tylko zrzuty z kodem 200, zwinięte po treści (bez duplikatów)."""
    parts = urlsplit(profile_url)
    target = parts.netloc + parts.path
    if parts.query:
        target += "?" + parts.query
    params = {
        "url": target,
        "output": "json",
        "fl": "timestamp,original,statuscode",
        "filter": "statuscode:200",
        "collapse": "digest",
        "limit": str(limit),
    }
    return CDX_URL + "?" + urlencode(params)


@dataclass
class Snapshot:
    timestamp: str        # YYYYMMDDhhmmss
    original: str

    @property
    def date(self) -> str:
        t = self.timestamp
        return f"{t[0:4]}-{t[4:6]}-{t[6:8]}" if len(t) >= 8 else t

    @property
    def archive_url(self) -> str:
        return f"https://web.archive.org/web/{self.timestamp}/{self.original}"


_CDX_TIMESTAMP = re.compile(r"\d{14}")
_CDX_MAX_FIELD = 2000


def parse_cdx(text: str) -> list[Snapshot]:
    """CDX JSON: pierwszy wiersz to nagłówek (lista tekstów), potem wiersze danych. Pusta odpowiedź = brak zrzutów.
    Każda niezgodność ze schematem (zły JSON, typy, timestamp inny niż 14 cyfr, za krótki wiersz) -> ValueError
    (to błąd odpowiedzi archiwum, nie „brak zrzutów”)."""
    text = text.strip()
    if not text:
        return []
    rows = json.loads(text)
    if not isinstance(rows, list):
        raise ValueError("CDX: oczekiwano listy")
    if not rows:
        return []
    header = rows[0]
    if not isinstance(header, list) or not all(isinstance(h, str) for h in header):
        raise ValueError("CDX: nagłówek nie jest listą tekstów")
    try:
        ti, oi = header.index("timestamp"), header.index("original")
    except ValueError as e:
        raise ValueError(f"CDX: brak kolumn w nagłówku {header[:8]}") from e
    out = []
    for r in rows[1:]:
        if not isinstance(r, list) or len(r) < len(header):
            raise ValueError("CDX: wiersz nie jest listą pasującą do nagłówka")
        ts, original = r[ti], r[oi]
        if not isinstance(ts, str) or not _CDX_TIMESTAMP.fullmatch(ts):
            raise ValueError("CDX: timestamp musi mieć 14 cyfr")
        if not isinstance(original, str) or not original or len(original) > _CDX_MAX_FIELD:
            raise ValueError("CDX: niepoprawne pole original")
        out.append(Snapshot(ts, original))
    return out


def wayback_targets(sites: list[Site], username: str, tags: set[str] | None = None, limit: int = 30) -> list[str]:
    """Adresy profili do sprawdzenia w archiwum: bez API (probe_url) i bez POST, z wybranych tagów."""
    out = []
    for s in sites:
        if s.method != "GET" or "{username}" not in s.url.split("#", 1)[0]:
            continue
        if tags and not (tags & {t.lower() for t in site_tags(s)}):
            continue
        url = s.profile_url(username)
        if not is_http_url(url):
            continue                      # niepoprawny adres z bazy: pomijamy, nie przerywamy
        out.append(url)
        if len(out) >= limit:
            break
    return out
