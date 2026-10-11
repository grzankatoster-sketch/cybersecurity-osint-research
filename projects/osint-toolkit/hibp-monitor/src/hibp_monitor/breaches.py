"""Wycieki HIBP: endpoint /breaches (bez klucza), katalog, stan i diff NOWYCH wyciekow."""
from __future__ import annotations

import json
import os
import re
import tempfile
import tomllib
import unicodedata
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable

from .http import Client, HibpError

BASE = "https://haveibeenpwned.com/api/v3"
DOMAIN_RE = re.compile(r"^(?=.{1,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$")
STATE_VERSION = 1


def normalize_domain(value: str) -> str:
    d = value.strip().lower().rstrip(".")
    if not DOMAIN_RE.match(d):
        raise ValueError(f"Niepoprawna domena: {value!r}")
    return d


@dataclass
class Breach:
    name: str
    title: str = ""
    domain: str = ""
    breach_date: str = ""
    added_date: str = ""
    pwn_count: int = 0
    data_classes: list[str] = field(default_factory=list)
    is_verified: bool = False
    is_sensitive: bool = False
    is_retired: bool = False
    is_spam_list: bool = False
    is_fabricated: bool = False
    is_malware: bool = False
    is_stealer_log: bool = False
    modified_date: str = ""
    description: str = ""

    @classmethod
    def from_api(cls, d: dict) -> "Breach":
        return cls(
            name=str(d.get("Name", "")),
            title=str(d.get("Title", "")),
            domain=str(d.get("Domain", "")),
            breach_date=str(d.get("BreachDate", "")),
            added_date=str(d.get("AddedDate", "")),
            pwn_count=int(d.get("PwnCount") or 0),
            data_classes=list(d.get("DataClasses") or []),
            is_verified=_flag(d.get("IsVerified")),
            is_sensitive=_flag(d.get("IsSensitive")),
            is_retired=_flag(d.get("IsRetired")),
            is_spam_list=_flag(d.get("IsSpamList")),
            is_fabricated=_flag(d.get("IsFabricated")),
            is_malware=_flag(d.get("IsMalware")),
            is_stealer_log=_flag(d.get("IsStealerLog")),
            modified_date=str(d.get("ModifiedDate", "")),
            description=str(d.get("Description", "")),
        )

    def to_dict(self, with_description: bool = False) -> dict:
        out = {
            "name": self.name, "title": self.title, "domain": self.domain,
            "breach_date": self.breach_date, "added_date": self.added_date,
            "pwn_count": self.pwn_count, "data_classes": self.data_classes,
            "is_verified": self.is_verified, "is_sensitive": self.is_sensitive,
            "is_retired": self.is_retired, "is_spam_list": self.is_spam_list,
            "is_fabricated": self.is_fabricated, "is_malware": self.is_malware,
            "is_stealer_log": self.is_stealer_log, "modified_date": self.modified_date,
        }
        if with_description:
            out["description"] = strip_html(self.description)
        return out


def _flag(value: object) -> bool:
    """Flaga jakosci z API: tylko jawna prawda (true/1/'true'); tekst 'false' nie jest prawda."""
    if isinstance(value, str):
        return value.strip().lower() in ("true", "1", "yes")
    return value is True or (isinstance(value, int) and not isinstance(value, bool) and value == 1)


_BLOCK_TAG_RE = re.compile(r"</?(?:p|br|div|li|ul|ol|tr|td|th|table|blockquote|h[1-6])(?![A-Za-z])[^>]*>", re.IGNORECASE)


def strip_html(text: str) -> str:
    """Usuwa znaczniki HTML; znaczniki blokowe (p, br, div, li...) zamienia na spacje, zeby nie sklejac slow."""
    return re.sub(r"\s+", " ", re.sub(r"<[^>]+>", "", _BLOCK_TAG_RE.sub(" ", text))).strip()


def safe_text(text: object) -> str:
    """Zamienia znaki sterujace (Unicode Cc poza \\n i \\t) na widoczne \\xNN: ochrona terminala przed danymi z API."""
    return "".join(
        f"\\x{ord(ch):02x}" if unicodedata.category(ch) == "Cc" and ch not in "\n\t" else ch for ch in str(text)
    )


def parse_breaches(text: str) -> list[Breach]:
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        raise HibpError("Nieprawidlowa odpowiedz HIBP (to nie jest JSON).") from None
    if not isinstance(data, list):
        raise HibpError("Nieoczekiwany format odpowiedzi HIBP (oczekiwano listy).")
    if not all(isinstance(x, dict) and x.get("Name") for x in data):
        raise HibpError("Nieoczekiwany format odpowiedzi HIBP (element nie jest wyciekiem z polem Name).")
    return [Breach.from_api(x) for x in data]


def _get_breaches(client: Client, url: str, not_found_empty: bool = False) -> list[Breach]:
    resp = client.get(url, {"Accept": "application/json"})
    if resp.status == 200:
        return parse_breaches(resp.text)
    if resp.status == 404 and not_found_empty:
        return []
    if resp.status == 403:
        raise HibpError("HIBP odrzucil zapytanie (403): brak/niepoprawny User-Agent.", 403)
    raise HibpError(f"HIBP zwrocil blad HTTP {resp.status}.", resp.status)


def fetch_domain_breaches(client: Client, domain: str) -> list[Breach]:
    """Wycieki, w ktorych SERWIS na danej domenie byl zrodlem (bez klucza API)."""
    return _get_breaches(client, f"{BASE}/breaches?domain={normalize_domain(domain)}", not_found_empty=True)


def fetch_catalog(client: Client) -> list[Breach]:
    """Pelny katalog wyciekow HIBP (bez klucza API)."""
    return _get_breaches(client, f"{BASE}/breaches")


# --- stan i diff ---------------------------------------------------------

def empty_state() -> dict:
    return {"version": STATE_VERSION, "domains": {}}


def load_state(path: Path) -> dict:
    if not path.exists():
        return empty_state()
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError) as exc:
        raise HibpError(f"Nie mozna odczytac pliku stanu {path}: {exc}") from None
    if not isinstance(data, dict) or not isinstance(data.get("domains"), dict):
        raise HibpError(f"Plik stanu {path} ma niepoprawny format.")
    return data


def save_state(path: Path, state: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=path.parent, suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            json.dump(state, fh, ensure_ascii=False, indent=2, sort_keys=True)
        os.replace(tmp, path)
    except BaseException:
        if os.path.exists(tmp):
            os.unlink(tmp)
        raise


def find_new(domain_state: dict | None, breaches: Iterable[Breach]) -> list[Breach]:
    """NOWE = nieznana nazwa wycieku LUB AddedDate pozniejsza niz znacznik ostatniego uruchomienia.

    Brak stanu domeny (pierwsze uruchomienie) -> wszystkie biezace wycieki (baseline).
    """
    items = sorted(breaches, key=lambda b: (b.added_date, b.name))
    if domain_state is None:
        return items
    seen = set(domain_state.get("seen", []))
    watermark = domain_state.get("last_added", "")
    return [b for b in items if b.name not in seen or (b.added_date and b.added_date > watermark)]


def update_state(state: dict, domain: str, breaches: Iterable[Breach], now: datetime | None = None) -> None:
    breaches = list(breaches)
    prev = state["domains"].get(domain) or {}
    seen = set(prev.get("seen", [])) | {b.name for b in breaches}
    watermark = max([prev.get("last_added", "")] + [b.added_date for b in breaches])
    state["domains"][domain] = {
        "seen": sorted(seen),
        "last_added": watermark,
        "last_run": (now or datetime.now(timezone.utc)).strftime("%Y-%m-%dT%H:%M:%SZ"),
    }


@dataclass
class DomainReport:
    domain: str
    first_run: bool
    total: int
    new: list[Breach]


def check_domain(client: Client, state: dict, domain: str) -> DomainReport:
    """Pobiera wycieki domeny, liczy diff wzgledem stanu i aktualizuje stan w pamieci."""
    domain = normalize_domain(domain)
    breaches = fetch_domain_breaches(client, domain)
    prev = state["domains"].get(domain)
    new = find_new(prev, breaches)
    update_state(state, domain, breaches)
    return DomainReport(domain, prev is None, len(breaches), new)


def load_config(path: Path) -> dict:
    try:
        raw = tomllib.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        raise HibpError(f"Brak pliku konfiguracji {path}. Skopiuj config.example.toml do config.toml.") from None
    except (tomllib.TOMLDecodeError, OSError) as exc:
        raise HibpError(f"Niepoprawny plik konfiguracji {path}: {exc}") from None
    domains = raw.get("domains", [])
    if not isinstance(domains, list) or not all(isinstance(d, str) for d in domains):
        raise HibpError("config.toml: 'domains' musi byc lista tekstow.")
    try:
        norm = [normalize_domain(d) for d in domains]
    except ValueError as exc:
        raise HibpError(f"config.toml: {exc}") from None
    return {
        "domains": norm,
        "user_agent": raw.get("user_agent"),
        "state_file": path.parent / raw.get("state_file", "state.json"),
    }
