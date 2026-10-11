"""Kontrola stanu bazy: każdy serwis sprawdzany na losowej nazwie (powinno być „brak”) i na znanym koncie
z bazy (powinno być „jest”). Wynik: data/health.json, z którego skan domyślnie pomija wpisy niesprawne.

Pomiar 03.10.2026: te same ~107 domen ma błąd DNS w każdym przebiegu, ~330 serwisów zawsze stoi za blokadą
anty-bot — to martwe lub niedostępne wpisy baz Maigret/WMN, które tylko wydłużają skan i zaśmiecają wynik."""
from __future__ import annotations

import asyncio
import json
from collections import Counter
from datetime import date, timedelta
from pathlib import Path
from typing import Callable

from .engine import FetcherLike, check_site, random_name
from .http import DNS_ERROR
from .models import Result, Site, Status

DEAD = "dead"              # domena nie istnieje
BLOCKED = "blocked"        # blokada anty-bot / odmowa dostępu / wymaga logowania
FALSE_POSITIVE = "false_positive"  # reguła daje „jest” dla losowej nazwy
STALE = "stale"            # znane konto daje „brak” — reguła prawdopodobnie przestarzała
UNSTABLE = "unstable"      # timeout, 5xx — może być chwilowe
OK = "ok"

SKIP_BY_DEFAULT = frozenset({DEAD, BLOCKED, FALSE_POSITIVE})
MAX_AGE_DAYS = 30          # starszych wpisów kontroli nie stosujemy: reguła mogła być naprawiona, a serwis wrócić
BLOCK_HINTS = ("anty-bot", "dostęp zabroniony", "wymaga logowania", "limit zapytań")


def judge(random_result: Result, known_result: Result | None, min_conf: float = 0.6) -> tuple[str, str]:
    """Stan serwisu z dwóch prób: losowa nazwa (powinno być „brak”) i znane konto (powinno być „jest”).
    Wykluczające stany (DEAD, BLOCKED, FALSE_POSITIVE) wynikają tylko z próby losowej; nieudana próba znanego
    konta daje co najwyżej STALE/UNSTABLE, które skan domyślnie nie pomija."""
    r = random_result
    if r.status is Status.ERROR:
        if r.reason.startswith(DNS_ERROR):
            return DEAD, r.reason
        if "niewiarygodna" in r.reason:          # reguła pasuje do losowej nazwy (kontrola na żądanie)
            return FALSE_POSITIVE, r.reason
        if _known_found(known_result, min_conf):
            # np. nieistniejące konto -> przekierowanie na logowanie, istniejące -> profil: serwis działa
            return OK, f"losowa nazwa: {r.reason}; znane konto wykrywane"
        if any(h in r.reason for h in BLOCK_HINTS):
            return BLOCKED, r.reason
        return UNSTABLE, r.reason
    if r.status is Status.FOUND and r.confidence >= min_conf:
        return FALSE_POSITIVE, f"losowa nazwa: {r.reason}"
    # losowa nazwa: NOT_FOUND, słabe FOUND (i tak ukryte) albo UNSUPPORTED (regex nie pasuje do losowej nazwy)
    # -> o stanie rozstrzyga znane konto
    if known_result is None:
        return OK, ""
    k = known_result
    if k.status is Status.FOUND:
        if k.confidence >= min_conf:
            return OK, ""
        return UNSTABLE, f"znane konto: zbyt słabe trafienie ({k.confidence:.2f}): {k.reason}"
    if k.status is Status.NOT_FOUND:
        return STALE, f"znane konto: {k.reason}"
    if k.status is Status.UNSUPPORTED:
        return UNSTABLE, f"znane konto niezgodne z regułą serwisu: {k.reason}"
    return UNSTABLE, f"znane konto nieudane: {k.reason}"      # ERROR


def _known_found(known: Result | None, min_conf: float) -> bool:
    return known is not None and known.status is Status.FOUND and known.confidence >= min_conf


async def check_health(
    sites: list[Site],
    fetcher: FetcherLike,
    concurrency: int = 50,
    on_done: Callable[[str, str], None] | None = None,
) -> dict[str, dict]:
    sem = asyncio.Semaphore(concurrency)

    async def one(site: Site) -> tuple[str, dict]:
        async with sem:
            try:
                rnd = await check_site(site, random_name(), fetcher)
                known = None
                if site.known and not rnd.reason.startswith(DNS_ERROR):
                    known = await check_site(site, site.known[0], fetcher)
                state, reason = judge(rnd, known)
            except Exception as e:
                state, reason = UNSTABLE, f"wyjątek: {type(e).__name__}"
        if on_done:
            on_done(site.name, state)
        return site.name, {"state": state, "reason": reason}

    return dict(await asyncio.gather(*(one(s) for s in sites)))


def save_health(health: dict[str, dict], path: str | Path) -> None:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    today = date.today().isoformat()
    sites = {name: {**entry, "checked": entry.get("checked", today)} for name, entry in health.items()}
    doc = {"meta": {"checked": today, "states": dict(Counter(v["state"] for v in health.values()))},
           "sites": sites}
    tmp = path.with_suffix(".tmp")
    tmp.write_text(json.dumps(doc, ensure_ascii=False, indent=1), encoding="utf-8")
    tmp.replace(path)


def _parse_day(value) -> date | None:
    try:
        return date.fromisoformat(str(value)[:10])
    except ValueError:
        return None


def load_health_ex(path: str | Path, max_age_days: int = MAX_AGE_DAYS, today: date | None = None
                   ) -> tuple[dict[str, dict], int]:
    """Stan zdrowia bez wpisów starszych niż `max_age_days` (data wpisu, a bez niej data całego pliku).
    Zwraca (aktualne wpisy, liczba odrzuconych jako przeterminowane). Wpis bez żadnej daty zostaje (wieku nie
    da się ocenić)."""
    path = Path(path)
    if not path.exists():
        return {}, 0
    doc = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(doc, dict) or not isinstance(doc.get("sites"), dict):
        return {}, 0
    limit = (today or date.today()) - timedelta(days=max_age_days)
    meta = doc.get("meta")
    file_day = _parse_day(meta.get("checked")) if isinstance(meta, dict) and meta.get("checked") else None
    kept, dropped = {}, 0
    for name, entry in doc["sites"].items():
        if not isinstance(entry, dict):
            continue
        day = _parse_day(entry["checked"]) if entry.get("checked") else file_day
        if day is not None and day < limit:
            dropped += 1
            continue
        kept[name] = entry
    return kept, dropped


def load_health(path: str | Path, max_age_days: int = MAX_AGE_DAYS, today: date | None = None) -> dict[str, dict]:
    return load_health_ex(path, max_age_days, today)[0]


def filter_healthy(sites: list[Site], health: dict[str, dict], skip=SKIP_BY_DEFAULT) -> tuple[list[Site], Counter]:
    """Zwraca (serwisy do skanu, licznik pominiętych wg stanu)."""
    kept, skipped = [], Counter()
    for s in sites:
        state = health.get(s.name, {}).get("state", OK)
        if state in skip:
            skipped[state] += 1
        else:
            kept.append(s)
    return kept, skipped
