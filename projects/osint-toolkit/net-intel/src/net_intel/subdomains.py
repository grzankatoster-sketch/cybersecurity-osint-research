"""Pasywne wyliczanie subdomen z trzech niezależnych źródeł: HackerTarget, Cert Spotter, crt.sh.

ZASADA: porażka źródła to ERROR z powodem, nigdy "0 wyników". Gdy zawiodą WSZYSTKIE źródła, wynik
mówi wprost "nie udało się sprawdzić" (to nie to samo co rzetelne "0 subdomen").
Zapytania są pasywne (cudze bazy publiczne), do badanej domeny nie wysyłamy nic.
"""

from __future__ import annotations

import ipaddress
import json
import re
import socket
import urllib.parse
from concurrent.futures import ThreadPoolExecutor, wait
from dataclasses import dataclass, field
from typing import Callable

from .http import Fetch, FetchError

_HOST_RE = re.compile(r"^(?!-)[a-z0-9_-]{1,63}(?<!-)(\.(?!-)[a-z0-9_-]{1,63}(?<!-))*$")
CERTSPOTTER_MAX_PAGES = 2  # bez klucza API limit to ok. 10 zapytań na godzinę
MAX_RESOLVE = 1000


def clean_name(raw: str, domain: str) -> str | None:
    """Nazwa z cudzego źródła -> poprawna nazwa w obrębie domeny albo None (adresy e-mail, obce domeny, śmieci)."""
    n = raw.strip().lower().rstrip(".")
    while n.startswith("*."):
        n = n[2:]
    if not n or "*" in n or "@" in n or " " in n or len(n) > 253:
        return None
    if n != domain and not n.endswith("." + domain):
        return None
    return n if _HOST_RE.match(n) else None


@dataclass
class SourceResult:
    name: str
    ok: bool
    error: str = ""
    names: set[str] = field(default_factory=set)
    ips: dict[str, set[str]] = field(default_factory=dict)  # tylko HackerTarget zwraca adresy
    note: str = ""  # np. "niepełne: ..." przy częściowym sukcesie

    @property
    def status_text(self) -> str:
        if not self.ok:
            return f"ERROR({self.error})"
        return f"OK({len(self.names)})" + (f" [{self.note}]" if self.note else "")

    def to_dict(self) -> dict:
        return {"source": self.name, "status": "OK" if self.ok else "ERROR",
                "count": len(self.names) if self.ok else None,
                "error": self.error or None, "note": self.note or None}


def _fail(name: str, error: str) -> SourceResult:
    return SourceResult(name, False, error=error)


def _http_error(resp) -> str:
    if resp.status != 429:
        return f"HTTP {resp.status}"
    wait_s = str(resp.headers.get("retry-after", "")).strip()
    return f"limit zapytań (HTTP 429" + (f", ponów za {wait_s} s)" if wait_s.isdigit() else ")")


# --- HackerTarget -----------------------------------------------------------------------------

_HT_NO_RESULTS = "no records found"


def _snippet(text: str, n: int = 70) -> str:
    one = " ".join(text.split())
    return one if len(one) <= n else one[: n - 1] + "…"


def parse_hackertarget(text: str, domain: str) -> SourceResult:
    """Tekst 'host,ip' w liniach. Komunikaty o limicie/błędzie przychodzą z HTTP 200 jako zwykły tekst."""
    names: set[str] = set()
    ips: dict[str, set[str]] = {}
    well_formed = 0
    for line in text.splitlines():
        host, sep, addr = line.partition(",")
        host, addr = host.strip().lower(), addr.strip()
        if not sep or not _HOST_RE.match(host):
            continue
        try:
            ipaddress.ip_address(addr)
        except ValueError:
            continue
        well_formed += 1
        name = clean_name(host, domain)
        if name:
            names.add(name)
            ips.setdefault(name, set()).add(addr)
    if well_formed:
        return SourceResult("hackertarget", True, names=names, ips=ips)
    body = text.strip()
    if body.lower().startswith(_HT_NO_RESULTS):
        return SourceResult("hackertarget", True)
    if not body:
        return _fail("hackertarget", "pusta odpowiedź")
    low = body.lower()
    if "exceeded" in low or "limit" in low or "quota" in low:
        return _fail("hackertarget", f"limit API: {_snippet(body)}")
    return _fail("hackertarget", f"komunikat zamiast wyników: {_snippet(body)}")


def source_hackertarget(domain: str, fetch: Fetch, timeout: float) -> SourceResult:
    url = "https://api.hackertarget.com/hostsearch/?q=" + urllib.parse.quote(domain)
    try:
        resp = fetch(url, headers={"Accept": "text/plain"}, timeout=timeout)
    except FetchError as exc:
        return _fail("hackertarget", str(exc))
    if resp.status != 200:
        return _fail("hackertarget", _http_error(resp))
    return parse_hackertarget(resp.text, domain)


# --- Cert Spotter -----------------------------------------------------------------------------

def parse_certspotter_page(text: str, domain: str) -> tuple[set[str], str | None, str]:
    """(nazwy, id ostatniej emisji, błąd). Puste id = brak kolejnej strony. Błąd niepusty = odpowiedź nie jest listą emisji."""
    try:
        data = json.loads(text)
    except ValueError:
        return set(), None, "nieprawidłowy JSON w odpowiedzi"
    if isinstance(data, dict):
        msg = data.get("message") or data.get("code") or "nieoczekiwana odpowiedź"
        return set(), None, f"API: {_snippet(str(msg))}"
    if not isinstance(data, list):
        return set(), None, "nieoczekiwany format odpowiedzi"
    names: set[str] = set()
    last_id = None
    for item in data:
        if not isinstance(item, dict):
            continue
        if item.get("id") is not None:
            last_id = str(item["id"])
        for raw in item.get("dns_names") or []:
            if isinstance(raw, str):
                n = clean_name(raw, domain)
                if n:
                    names.add(n)
    return names, last_id if data else None, ""


def source_certspotter(domain: str, fetch: Fetch, timeout: float, max_pages: int = CERTSPOTTER_MAX_PAGES) -> SourceResult:
    base = ("https://api.certspotter.com/v1/issuances?domain=" + urllib.parse.quote(domain)
            + "&include_subdomains=true&expand=dns_names")
    names: set[str] = set()
    after: str | None = None
    for page in range(1, max_pages + 1):
        url = base + (f"&after={urllib.parse.quote(after)}" if after else "")
        try:
            resp = fetch(url, headers={"Accept": "application/json"}, timeout=timeout)
            err = "" if resp.status == 200 else _http_error(resp)
        except FetchError as exc:
            resp, err = None, str(exc)
        if err or resp is None:
            if page == 1:
                return _fail("certspotter", err)
            return SourceResult("certspotter", True, names=names, note=f"niepełne: strona {page}: {err}")
        page_names, after, perr = parse_certspotter_page(resp.text, domain)
        if perr:
            if page == 1:
                return _fail("certspotter", perr)
            return SourceResult("certspotter", True, names=names, note=f"niepełne: strona {page}: {perr}")
        names |= page_names
        if after is None:
            return SourceResult("certspotter", True, names=names)
    return SourceResult("certspotter", True, names=names,
                        note=f"niepełne: pobrano tylko {max_pages} stron (limit zapytań bez klucza)")


# --- crt.sh -----------------------------------------------------------------------------------

def parse_crtsh(text: str, domain: str) -> SourceResult:
    try:
        data = json.loads(text)
    except ValueError:
        return _fail("crt.sh", "odpowiedź nie jest JSON-em (serwis przeciążony?)")
    if not isinstance(data, list):
        return _fail("crt.sh", "nieoczekiwany format odpowiedzi")
    names: set[str] = set()
    for item in data:
        if not isinstance(item, dict):
            continue
        for field_name in ("name_value", "common_name"):
            val = item.get(field_name)
            if isinstance(val, str):
                for raw in val.splitlines():
                    n = clean_name(raw, domain)
                    if n:
                        names.add(n)
    return SourceResult("crt.sh", True, names=names)


def source_crtsh(domain: str, fetch: Fetch, timeout: float) -> SourceResult:
    url = "https://crt.sh/?q=" + urllib.parse.quote("%." + domain) + "&output=json"
    try:
        resp = fetch(url, headers={"Accept": "application/json"}, timeout=timeout)
    except FetchError as exc:
        return _fail("crt.sh", str(exc))
    if resp.status != 200:
        return _fail("crt.sh", _http_error(resp))
    return parse_crtsh(resp.text, domain)


SOURCES: dict[str, Callable[..., SourceResult]] = {
    "hackertarget": source_hackertarget,
    "certspotter": source_certspotter,
    "crt.sh": source_crtsh,
}


# --- scalanie ---------------------------------------------------------------------------------

@dataclass
class Entry:
    name: str
    sources: list[str]
    passive_ips: list[str] = field(default_factory=list)
    resolved: list[str] | None = None  # None = nie sprawdzano lub błąd rozwiązywania; [] = brak A/AAAA
    resolve_error: str = ""

    def to_dict(self, with_resolve: bool) -> dict:
        d = {"name": self.name, "sources": self.sources, "passive_ips": self.passive_ips}
        if with_resolve:
            d["resolved"] = self.resolved
            d["resolve_error"] = self.resolve_error or None
        return d


@dataclass
class SubdomainResult:
    domain: str
    sources: list[SourceResult]
    entries: list[Entry]
    resolved: bool = False

    @property
    def ok_sources(self) -> list[SourceResult]:
        return [s for s in self.sources if s.ok]

    @property
    def all_failed(self) -> bool:
        return not self.ok_sources

    @property
    def status(self) -> str:
        if self.all_failed:
            return "failed"
        return "ok" if len(self.ok_sources) == len(self.sources) else "partial"

    def to_dict(self) -> dict:
        return {
            "domain": self.domain,
            "status": self.status,
            "checked": not self.all_failed,
            "complete": self.status == "ok",
            "count": None if self.all_failed else len(self.entries),
            "sources": [s.to_dict() for s in self.sources],
            "subdomains": [e.to_dict(self.resolved) for e in self.entries],
        }


def _run_source(name: str, fn: Callable[..., SourceResult], domain: str, fetch: Fetch, timeout: float) -> SourceResult:
    try:
        return fn(domain, fetch, timeout)
    except Exception as exc:  # noqa: BLE001 - nieoczekiwany błąd źródła to ERROR, nie "0 wyników"
        return _fail(name, f"błąd wewnętrzny: {type(exc).__name__}")


def enumerate_subdomains(domain: str, fetch: Fetch, timeout: float = 20.0,
                         sources: dict[str, Callable[..., SourceResult]] | None = None) -> SubdomainResult:
    sources = sources or SOURCES
    with ThreadPoolExecutor(max_workers=len(sources)) as pool:
        futures = [pool.submit(_run_source, n, fn, domain, fetch, timeout) for n, fn in sources.items()]
        results = [f.result() for f in futures]  # kolejność źródeł stała
    seen: dict[str, Entry] = {}
    ip_sets: dict[str, set[str]] = {}
    for res in results:
        if not res.ok:
            continue
        for n in res.names:
            seen.setdefault(n, Entry(n, [])).sources.append(res.name)
            ip_sets.setdefault(n, set()).update(res.ips.get(n, ()))
    entries = []
    for n in sorted(seen):
        e = seen[n]
        e.passive_ips = sorted(ip_sets[n], key=lambda a: (ipaddress.ip_address(a).version, ipaddress.ip_address(a)))
        entries.append(e)
    return SubdomainResult(domain, results, entries)


# --- opcjonalne rozwiązywanie adresów ------------------------------------------------------------

_NOT_FOUND = {getattr(socket, "EAI_NONAME", 8), getattr(socket, "EAI_NODATA", -5), 11001, 11004}


def system_resolve(name: str) -> list[str]:
    """Adresy A/AAAA przez resolver systemowy; [] gdy nazwa nie istnieje, wyjątek przy błędzie resolvera."""
    try:
        infos = socket.getaddrinfo(name, None, proto=socket.IPPROTO_TCP)
    except socket.gaierror as exc:
        if exc.errno in _NOT_FOUND:
            return []
        raise
    return sorted({i[4][0] for i in infos})


def resolve_entries(result: SubdomainResult, resolver: Callable[[str], list[str]] = system_resolve,
                    workers: int = 10, deadline: float = 60.0, limit: int = MAX_RESOLVE) -> int:
    """Uzupełnia entries[].resolved. Zwraca liczbę nazw pominiętych przez limit. Równoległość ograniczona do `workers`."""
    result.resolved = True
    todo = result.entries[:limit]
    skipped = len(result.entries) - len(todo)
    pool = ThreadPoolExecutor(max_workers=max(1, workers))
    try:
        futures = {pool.submit(resolver, e.name): e for e in todo}
        wait(list(futures), timeout=deadline)
        for fut, entry in futures.items():
            if not fut.done():
                entry.resolve_error = "przekroczono limit czasu"
                continue
            exc = fut.exception()
            if exc is not None:
                entry.resolve_error = f"błąd resolvera: {type(exc).__name__}"
            else:
                entry.resolved = list(fut.result())
    finally:
        pool.shutdown(wait=False, cancel_futures=True)
    for e in result.entries[limit:]:
        e.resolve_error = f"pominięto (limit {limit} nazw)"
    return skipped
