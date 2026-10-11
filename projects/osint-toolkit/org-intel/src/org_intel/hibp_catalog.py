"""Opcjonalny konektor sieciowy do PUBLICZNEGO katalogu metadanych HIBP: GET https://haveibeenpwned.com/api/v3/breaches.

Bez klucza API: konektor go ani nie wymaga, ani nie przyjmuje (naglowki to wylacznie User-Agent i Accept; zmienna
srodowiskowa z kluczem nie jest czytana). Tylko ten jeden adres: w tym pakiecie NIE MA endpointow breachedaccount,
pasteaccount, stealerlogs ani breacheddomain (wyszukiwanie po adresie/domenie i stealer logs zostaja w `hibp-monitor`).
Wymagany User-Agent z konfiguracji, timeout, odstep min. 1,6 s miedzy zapytaniami, cache na dysku (TTL 24 h),
limit rozmiaru odpowiedzi, obsluga 429/Retry-After (maks. 3 proby).

Minimalizacja danych: na dysk (cache) trafia WYLACZNIE zminimalizowany katalog (tylko pola z `CATALOG_FIELDS`, bez
LogoPath i pol spoza listy, adresy e-mail w tytule/opisie zamaskowane; rekordy z polami kont, adresow e-mail albo
sekretow odrzucone). Surowa odpowiedz nie jest zapisywana; zostaje po niej tylko skrot sha256 (`content_hash`),
ETag i Last-Modified jako proweniencja.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import tempfile
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path

from . import guards
from .guards import RejectedRecord
from .http import Client, NetworkError, Response, UrllibClient
from .logging_redact import get_logger, mask_emails

CATALOG_URL = "https://haveibeenpwned.com/api/v3/breaches"
CACHE_TTL_SECONDS = 24 * 3600
MIN_INTERVAL_SECONDS = 1.6
MAX_ATTEMPTS = 3
MAX_RETRY_AFTER = 120.0
CACHE_FILE = "hibp-breaches.json"
MAX_USER_AGENT = 200
MAX_HEADER_NOTE = 80

# Dozwolone pola rekordu katalogu: nazwa API (PascalCase) -> nazwa w wyniku `hibp-monitor breaches --catalog --json`.
# Wszystko spoza tej listy (np. LogoPath, Attribution, IsSubscriptionFree) jest pomijane i nie trafia na dysk.
CATALOG_FIELDS: dict[str, str] = {
    "Name": "name",
    "Title": "title",
    "Domain": "domain",
    "BreachDate": "breach_date",
    "AddedDate": "added_date",
    "ModifiedDate": "modified_date",
    "PwnCount": "pwn_count",
    "DataClasses": "data_classes",
    "Description": "description",
    "IsVerified": "is_verified",
    "IsFabricated": "is_fabricated",
    "IsSensitive": "is_sensitive",
    "IsRetired": "is_retired",
    "IsSpamList": "is_spam_list",
    "IsMalware": "is_malware",
    "IsStealerLog": "is_stealer_log",
}
_TEXT_FIELDS = ("Title", "Description")

log = get_logger("org_intel.hibp_catalog")


class ConfigError(Exception):
    """Zla konfiguracja konektora (np. brak User-Agent)."""


@dataclass
class CatalogFetch:
    text: str  # zminimalizowany katalog (JSON); NIE surowa odpowiedz
    fetched_at: float  # epoch
    from_cache: bool
    content_hash: str | None = None  # sha256 surowej odpowiedzi (przed minimalizacja)
    etag: str | None = None
    last_modified: str | None = None
    rejected: list[dict[str, str]] = field(
        default_factory=list
    )  # [{"label", "reason"}] rekordy odrzucone przy minimalizacji


def _parse_retry_after(value: str | None, default: float) -> float:
    try:
        seconds = float(value) if value is not None else default
    except ValueError:
        seconds = default
    return max(0.0, min(seconds, MAX_RETRY_AFTER))


def _clean_header(value: str | None) -> str | None:
    """Wartosc naglowka odpowiedzi (ETag/Last-Modified) jako krotka, drukowalna notatka proweniencji."""
    if not value:
        return None
    cleaned = re.sub(r"[^\x20-\x7e]", "", value).strip()[:MAX_HEADER_NOTE]
    return cleaned or None


def minimize_catalog(data: list) -> tuple[list[dict], list[dict[str, str]]]:
    """Zostawia tylko dozwolone pola; rekord z polem kont/e-mail/sekretu albo z wartoscia wygladajaca na sekret
    jest odrzucany (z powodem). E-maile w tytule i opisie sa maskowane."""
    kept: list[dict] = []
    rejected: list[dict[str, str]] = []
    for idx, rec in enumerate(data):
        if not isinstance(rec, dict):
            rejected.append({"label": f"breaches[{idx}]", "reason": "rekord musi być obiektem"})
            continue
        label = mask_emails(str(rec.get("Name") or f"breaches[{idx}]"))[:80]
        try:
            for key in rec:
                reason = guards.catalog_forbidden_key(key)
                if reason:
                    raise RejectedRecord(reason)
            out = {key: rec[key] for key in CATALOG_FIELDS if key in rec}
            guards.check_secrets(out)
        except RejectedRecord as exc:
            rejected.append({"label": label, "reason": exc.reason})
            continue
        for key in _TEXT_FIELDS:
            if isinstance(out.get(key), str):
                out[key] = mask_emails(out[key])
        kept.append(out)
    return kept, rejected


class HibpCatalogClient:
    def __init__(
        self,
        user_agent: str,
        cache_dir: Path | str,
        *,
        client: Client | None = None,
        ttl: float = CACHE_TTL_SECONDS,
        min_interval: float = MIN_INTERVAL_SECONDS,
        clock: Callable[[], float] = time.time,
        sleep: Callable[[float], None] = time.sleep,
    ):
        if not user_agent or not user_agent.strip():
            raise ConfigError(
                "HIBP wymaga nagłówka User-Agent: podaj --user-agent (np. 'moja-firma org-intel/0.1 (kontakt)')."
            )
        agent = user_agent.strip()
        if len(agent) > MAX_USER_AGENT or re.search(r"[\x00-\x1f\x7f]", agent):
            raise ConfigError(f"Niepoprawny User-Agent (maks. {MAX_USER_AGENT} znaków, bez znaków sterujących).")
        self.user_agent = agent
        self.cache_path = Path(cache_dir) / CACHE_FILE
        self._client = client
        self.ttl = ttl
        self.min_interval = min_interval
        self._clock = clock
        self._sleep = sleep
        self._last_request: float | None = None

    # --- cache ---------------------------------------------------------------

    def _read_cache(self) -> CatalogFetch | None:
        try:
            wrapper = json.loads(self.cache_path.read_text(encoding="utf-8"))
            fetched_at = float(wrapper["fetched_at"])
            text = wrapper["body"]
            minimized = wrapper.get("minimized") is True
        except (OSError, ValueError, KeyError, TypeError, AttributeError):
            return None
        # cache sprzed minimalizacji (surowe cialo) jest ignorowany i zostanie nadpisany po nastepnym pobraniu
        if not minimized or not isinstance(text, str) or self._clock() - fetched_at > self.ttl:
            return None
        rejected = wrapper.get("rejected")
        return CatalogFetch(
            text,
            fetched_at,
            True,
            content_hash=wrapper.get("content_hash") if isinstance(wrapper.get("content_hash"), str) else None,
            etag=wrapper.get("etag") if isinstance(wrapper.get("etag"), str) else None,
            last_modified=wrapper.get("last_modified") if isinstance(wrapper.get("last_modified"), str) else None,
            rejected=[r for r in rejected if isinstance(r, dict)] if isinstance(rejected, list) else [],
        )

    def _write_cache(self, fetch: CatalogFetch) -> None:
        self.cache_path.parent.mkdir(parents=True, exist_ok=True)
        fd, tmp = tempfile.mkstemp(dir=self.cache_path.parent, suffix=".tmp")
        wrapper = {
            "fetched_at": fetch.fetched_at,
            "url": CATALOG_URL,
            "minimized": True,
            "content_hash": fetch.content_hash,
            "etag": fetch.etag,
            "last_modified": fetch.last_modified,
            "rejected": fetch.rejected,
            "body": fetch.text,
        }
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as fh:
                json.dump(wrapper, fh, ensure_ascii=False)
            os.replace(tmp, self.cache_path)
        except BaseException:
            if os.path.exists(tmp):
                os.unlink(tmp)
            raise

    # --- zapytanie -------------------------------------------------------------

    def _throttle(self) -> None:
        if self._last_request is not None:
            wait = self.min_interval - (self._clock() - self._last_request)
            if wait > 0:
                self._sleep(wait)

    def _request(self) -> Response:
        client = self._client or UrllibClient()
        headers = {"User-Agent": self.user_agent, "Accept": "application/json"}  # tylko to: zadnego klucza API
        attempt = 0
        while True:
            self._throttle()
            self._last_request = self._clock()
            resp = client.get(CATALOG_URL, headers)
            attempt += 1
            if resp.status != 429:
                return resp
            if attempt >= MAX_ATTEMPTS:
                raise NetworkError("Limit zapytań HIBP (429): spróbuj ponownie później.", 429)
            wait = _parse_retry_after(resp.header("retry-after"), default=2.0 * attempt)
            log.info("HIBP 429, ponowienie za %.1f s (próba %d/%d)", wait, attempt + 1, MAX_ATTEMPTS)
            self._sleep(wait)

    def fetch(self, *, refresh: bool = False) -> CatalogFetch:
        if not refresh:
            cached = self._read_cache()
            if cached:
                log.info("katalog HIBP z cache (TTL %d h)", int(self.ttl // 3600))
                return cached
        resp = self._request()
        if resp.status == 403:
            raise NetworkError("HIBP odrzucił zapytanie (403): brak lub niepoprawny User-Agent.", 403)
        if resp.status != 200:
            raise NetworkError(f"HIBP zwrócił błąd HTTP {resp.status}.", resp.status)
        try:
            data = json.loads(resp.text)
        except json.JSONDecodeError:
            raise NetworkError("Nieprawidłowa odpowiedź HIBP (to nie jest JSON).") from None
        if not isinstance(data, list):
            raise NetworkError("Nieoczekiwany format odpowiedzi HIBP (oczekiwano listy).")
        kept, rejected = minimize_catalog(data)
        result = CatalogFetch(
            json.dumps(kept, ensure_ascii=False),
            self._clock(),
            False,
            content_hash=hashlib.sha256(resp.text.encode("utf-8")).hexdigest(),
            etag=_clean_header(resp.header("etag")),
            last_modified=_clean_header(resp.header("last-modified")),
            rejected=rejected,
        )
        self._write_cache(result)  # do cache trafia tylko poprawna, zminimalizowana odpowiedz
        return result
