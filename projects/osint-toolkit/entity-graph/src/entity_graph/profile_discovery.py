"""Wyszukiwanie profili po imieniu i nazwisku (Brave Search API) i materiał operatora: kandydaci w sprawie.

Przepływ: osoba ze sprawy -> deterministyczne zapytania (konektor ``brave_search`` z osint-connectors) -> jedno
wywołanie API na zapytanie w twardym budżecie -> adresy zwalidowane i sklasyfikowane (``profile_urls``) ->
fragmenty przeanalizowane lokalnie (``profile_analyzer``) -> kandydaci w grafie sprawy. Drugie wejście: adres
i tekst dostarczony przez operatora (bez sieci). Nic tu nie pobiera stron profili, obrazków ani podglądów.

Zasady:
  * kandydat to hipoteza: krawędź ``candidate_match`` (pewność 0) tylko dla adresów, które mogą być kontem
    („prawdopodobny profil”, „nieustalony”); post, grupa i strona organizacji dostają ``mentioned_in_result``
    i nie są kontem osoby. Profil z osobą łączy wyłącznie decyzja operatora (``eg potwierdz``), której import
    nigdy nie zmienia;
  * status źródła (per zapytanie, enum Status z przyczyną), ocena dopasowania (opisowa, bez procentów) i decyzja
    operatora są osobnymi polami;
  * deduplikacja po adresie kanonicznym scala OBSERWACJE tego samego adresu (z pochodzeniem), nigdy osoby;
    ten sam materiał drugi raz niczego nie zmienia;
  * zapisujemy minimum (zakres pozytywny): adres źródła, skrót SHA-256 i długość materiału, ustalenia analizatora
    z dosłownym krótkim dowodem i pozycją. Tekstu materiału (tytułu, fragmentu wyszukiwarki, tekstu operatora) NIE
    zapisujemy: jest analizowany w pamięci. Adres z kontaktem, danymi logowania albo sekretem jest odrzucany
    z przyczyną (``profile_urls.persist_problem``), nigdy "poprawiany". Bez pełnych odpowiedzi API;
  * ocena dopasowania, ustalenia zależne od nazwiska i domyślny cel decyzji dotyczą pary osoba-adres: wspólny adres
    jest jednym źródłem, ale każda osoba ma własne obserwacje i własną kartę;
  * czas: każde wywołanie dostaje najwyżej czas pozostały do końca przebiegu (transport ma twardy termin, patrz
    ``osint_connectors.http.UrllibClient``); po upływie czasu nie startuje żadne kolejne zapytanie ani ponowienie,
    a już uzyskani kandydaci zostają w sprawie z przyczyną przerwania;
  * klucz ``BRAVE_SEARCH_API_KEY``: środowisko albo plik poza repozytorium (``~/.osint/brave.env`` albo
    ``BRAVE_SEARCH_ENV_FILE``); trafia tylko do nagłówka żądania. Kanał (fail-closed): ``BRAVE_PROXY``
    (http://host:port, tylko przez nie, bez fallbacku); ``BRAVE_REQUIRE_PROXY=1`` albo ustawiony ``OSINT_PROXY``
    (kanał Tor/proxy całego zestawu) wymagają proxy. ``OSINT_PROXY`` w postaci http://host:port jest użyty jako kanał;
    SOCKS (Tor) bez ``BRAVE_PROXY`` = odmowa (transport obsługuje tylko proxy HTTP), nigdy połączenie bezpośrednie.
    Proxy nieosiągalne przed startem = zero zapytań; błąd połączenia przez proxy w trakcie = zatrzymanie przebiegu
    bez ponowień (``proxy_down``).
"""

from __future__ import annotations

import asyncio
import hashlib
import importlib
import os
import re
import secrets
import socket
import time
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import urlsplit

from . import siblings, teczka
from .correlate import is_profile
from .model import Edge, Graph, Node, RunRecord, Status, utc_now
from .normalize import EntityType
from .profile_analyzer import (
    F_NAME,
    KIND_LABELS,
    KIND_MANUAL,
    KIND_SNIPPET,
    MAX_MATERIAL,
    STATUS_EMPTY,
    analyze,
    clean_material,
)
from .profile_urls import ACCOUNT_CLASSES, check_url

META_KEY = "profile_discovery"
SOURCE = "profile_discovery"
TRANSFORM = "profile_search_brave"
PROVIDER = "Brave Search API"
CANDIDATE = "candidate_match"
MENTION = "mentioned_in_result"
KEEP_RUNS = 20
MAX_SOURCE_URLS = 10
MAX_OBSERVATIONS = 30

KEY_ENV = "BRAVE_SEARCH_API_KEY"
FILE_ENV = "BRAVE_SEARCH_ENV_FILE"
PROXY_ENV = "BRAVE_PROXY"
REQUIRE_PROXY_ENV = "BRAVE_REQUIRE_PROXY"
OSINT_PROXY_ENV = "OSINT_PROXY"  # kanał Tor/proxy całego zestawu (panel ustawia go domyślnie): wymusza proxy
_KNOWN_SCHEMES = frozenset({"socks4", "socks4a", "socks5", "socks5h", "https", "http"})
_REQUIRE_OFF = frozenset({"", "0", "false", "no", "nie", "off"})  # jedyne wartości, które NIE wymagają proxy
PROXY_PROBE_SECONDS = 3.0  # sprawdzenie osiągalności proxy przed pierwszym zapytaniem
DEFAULT_FILE = Path.home() / ".osint" / "brave.env"
REPO_ROOT = Path(__file__).resolve().parents[3]
_PROXY = re.compile(r"^http://(?:[^@/\s:]+:[^@/\s]+@)?(?P<host>[A-Za-z0-9.\-]+|\[[0-9A-Fa-f:]+\]):(?P<port>\d{1,5})/?$")

# przyczyny (kod -> opis) dla statusów zapytań; kody trafiają do raportu i panelu
REASONS = {
    "results": "wyniki",
    "empty": "brak wyników dla tego zapytania (nie oznacza braku kont)",
    "not_configured": "brak konfiguracji",
    "unavailable": "konektor osint-connectors niedostępny",
    "auth_required": "brak autoryzacji (klucz odrzucony)",
    "rate_limited": "limit dostawcy (HTTP 429)",
    "timeout": "przekroczono limit czasu",
    "parse": "uszkodzona odpowiedź (niepoprawny JSON)",
    "schema_changed": "uszkodzona odpowiedź (nieoczekiwany format)",
    "request_rejected": "dostawca odrzucił zapytanie",
    "transport": "błąd sieci, proxy albo HTTP 5xx",
    "unexpected": "nieoczekiwany błąd konektora",
    "proxy_down": "błąd połączenia przez proxy (proxy niedostępne albo zerwane połączenie)",
}
_STATUS_OF = {
    "results": Status.FOUND,
    "empty": Status.NOT_FOUND,
    "not_configured": Status.UNKNOWN,
    "unavailable": Status.UNKNOWN,
}
MIN_CALL_SECONDS = 1.0  # mniej czasu do końca przebiegu = nie zaczynamy kolejnego wywołania
_RETRY = frozenset({"timeout", "transport"})  # jedno ponowienie, jeśli budżet pozwala (zużywa wywołanie)
_HALT = {
    "auth_required": "przerwano: brak autoryzacji (kolejne zapytania też by nie przeszły)",
    "rate_limited": "przerwano: limit dostawcy (HTTP 429), nie ponawiamy",
    "proxy_down": "przerwano: błąd połączenia przez proxy - skan zatrzymany bez ponowień i bez połączenia "
    "bezpośredniego (fail-closed)",
}


class ConfigError(Exception):
    """Brak albo błąd konfiguracji źródła: nic nie zostało wysłane. Komunikat jest bezpieczny (bez klucza)."""


@dataclass
class Limits:
    calls: int = 6  # wywołania API (ponowienie też się liczy)
    results: int = 20  # wyników na wywołanie (dostawca: 1-20)
    candidates: int = 50  # unikalnych kandydatów w przebiegu
    seconds: float = 60.0  # czas przebiegu

    HARD = {"calls": (1, 12), "results": (1, 20), "candidates": (1, 100), "seconds": (10, 120)}  # noqa: RUF012 - stała klasy, nie modyfikowana

    def validate(self) -> Limits:
        for name, (lo, hi) in self.HARD.items():
            value = getattr(self, name)
            ok_type = type(value) is int if name != "seconds" else type(value) in (int, float)
            if not ok_type or not lo <= value <= hi or value != value:  # noqa: PLR0124 - odrzuca NaN
                raise ValueError(f"limit {name}: {lo}-{hi}")
        return self


@dataclass
class BraveConfig:
    key: str | None = field(default=None, repr=False)
    proxy: str | None = field(default=None, repr=False)  # może zawierać login:hasło - nie wypisywać
    key_source: str = ""
    require_proxy: bool = False
    proxy_policy: str = ""  # skąd wymóg proxy: BRAVE_REQUIRE_PROXY albo OSINT_PROXY (do komunikatu, bez wartości)
    problems: list[str] = field(default_factory=list)

    def channel(self) -> str:
        if self.proxy:
            m = _PROXY.match(self.proxy)
            return (
                f"tylko przez BRAVE_PROXY {self.proxy.split(':', 1)[0]}://{m.group('host')}:{m.group('port')}"
                if m
                else "tylko przez BRAVE_PROXY"
            )
        return "połączenie bezpośrednie albo proxy systemowe (BRAVE_PROXY nieustawione)"

    def blocking_problem(self) -> str | None:
        """Powody (wszystkie naraz), dla których nie wolno wysłać żadnego zapytania, albo None."""
        reasons = []
        if not self.key:
            reasons.append(
                f"brak klucza {KEY_ENV}: ustaw zmienną środowiskową albo wpis {KEY_ENV}=... w pliku "
                f"{DEFAULT_FILE} (poza repozytorium). Ręczne dodanie kandydata i analiza tekstu działają bez "
                "klucza."
            )
        reasons += self.problems
        if self.require_proxy and not self.proxy and not self.problems:
            reasons.append(
                f"{self.proxy_policy or REQUIRE_PROXY_ENV} wymaga proxy, a {PROXY_ENV} nie jest ustawione: "
                "zapytania zablokowane (bez połączenia bezpośredniego)"
            )
        return "; ".join(reasons) or None


def _inside_repo(path: Path) -> bool:
    try:
        path.resolve().relative_to(REPO_ROOT)
        return True
    except (ValueError, OSError):
        return False


def load_config(environ: Mapping[str, str] | None = None) -> BraveConfig:
    """Środowisko wygrywa z plikiem; plik w repozytorium jest pomijany (sekret nie może trafić do gita)."""
    env = os.environ if environ is None else environ
    cfg = BraveConfig()
    values: dict[str, str] = {}
    origin: dict[str, str] = {}
    path = Path(env[FILE_ENV]) if env.get(FILE_ENV) else DEFAULT_FILE
    if path.is_file():
        if _inside_repo(path):
            cfg.problems.append(
                f"plik konfiguracji leży w repozytorium ({path.name}): przenieś go poza repo, np. do {DEFAULT_FILE}"
            )
        else:
            try:
                for line in path.read_text(encoding="utf-8-sig").splitlines():
                    k, sep, v = line.strip().partition("=")
                    if (
                        sep
                        and not k.startswith("#")
                        and k.strip() in (KEY_ENV, PROXY_ENV, REQUIRE_PROXY_ENV, OSINT_PROXY_ENV)
                    ):
                        values[k.strip()], origin[k.strip()] = v.strip().strip('"').strip("'"), f"plik {path}"
            except (OSError, UnicodeDecodeError) as exc:
                cfg.problems.append(f"nie można odczytać pliku konfiguracji ({type(exc).__name__})")
    elif env.get(FILE_ENV):
        cfg.problems.append(f"{FILE_ENV} wskazuje nieistniejący plik")
    for k in (KEY_ENV, PROXY_ENV, REQUIRE_PROXY_ENV, OSINT_PROXY_ENV):
        if str(env.get(k, "")).strip():
            values[k], origin[k] = str(env[k]).strip(), "środowisko"
    key = values.get(KEY_ENV)
    if key and (len(key) < 10 or any(c.isspace() for c in key) or not key.isprintable()):
        cfg.problems.append(f"{KEY_ENV}: nieprawidłowy format klucza (za krótki albo ze spacjami)")
        key = None
    cfg.key, cfg.key_source = key, origin.get(KEY_ENV, "") if key else ""
    # fail-closed także przy literówce ("on", "2", "enabled"): wymóg wyłącza tylko jawne 0/false/no/nie/off
    cfg.require_proxy = values.get(REQUIRE_PROXY_ENV, "").lower() not in _REQUIRE_OFF
    cfg.proxy_policy = REQUIRE_PROXY_ENV if cfg.require_proxy else ""
    proxy = values.get(PROXY_ENV)
    if proxy:
        m = _PROXY.match(proxy)
        if m and 1 <= int(m.group("port")) <= 65535:
            cfg.proxy = proxy
        else:
            cfg.problems.append(
                f"{PROXY_ENV}: oczekiwane http://host:port (HTTPS i SOCKS nieobsługiwane); zapytania "
                "zablokowane, bez połączenia bezpośredniego"
            )
    # Fail-closed względem kanału całego zestawu: ustawiony OSINT_PROXY (Tor) oznacza, że NIC nie może wyjść
    # bezpośrednio. Transport wyszukiwarki obsługuje tylko proxy HTTP (CONNECT), więc: OSINT_PROXY w postaci
    # http://host:port jest użyty jako kanał; SOCKS (Tor) bez BRAVE_PROXY = odmowa, nigdy połączenie bezpośrednie.
    osint_proxy = values.get(OSINT_PROXY_ENV)
    if osint_proxy:
        cfg.require_proxy, cfg.proxy_policy = True, OSINT_PROXY_ENV
        if not proxy:
            m = _PROXY.match(osint_proxy)
            if m and 1 <= int(m.group("port")) <= 65535:
                cfg.proxy = osint_proxy
            else:
                scheme = osint_proxy.split(":", 1)[0].lower() if "://" in osint_proxy else ""
                scheme = scheme if scheme in _KNOWN_SCHEMES else "?"  # nigdy fragment wartości (login:hasło@)
                cfg.problems.append(
                    f"{OSINT_PROXY_ENV} ({scheme}) wymaga ruchu przez proxy, a wyszukiwarka obsługuje tylko proxy HTTP: "
                    f"ustaw {PROXY_ENV}=http://host:port (np. Tor HTTPTunnelPort); zapytania zablokowane, bez połączenia "
                    "bezpośredniego"
                )
    return cfg


def _proxy_reachable(host: str, port: int, timeout: float = PROXY_PROBE_SECONDS) -> bool:
    """Połączenie TCP wyłącznie z samym proxy (bez żadnego zapytania do wyszukiwarki)."""
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


def load_connector():
    """(pakiet osint_connectors, moduł brave_search) z narzędzia siostrzanego; brak = SiblingUnavailable."""
    pkg = siblings.import_sibling("osint-connectors", siblings.tools_root())
    try:
        return pkg, importlib.import_module("osint_connectors.connectors.brave_search")
    except ImportError as exc:
        raise siblings.SiblingUnavailable(f"konektor brave_search niedostępny: {exc}") from exc


# --- dane sprawy ---------------------------------------------------------------------------------------------


def state(graph: Graph, create: bool = False) -> dict:
    """meta.profile_discovery: {"runs": [...], "items": {klucz URL: kandydat}}. Odczyt nie zmienia starych spraw;
    create=True przypina stan do grafu (zapis)."""
    raw = graph.meta.get(META_KEY)
    if raw is None:
        raw = {"runs": [], "items": {}}
        if create:
            graph.meta[META_KEY] = raw
    if (
        not isinstance(raw, dict)
        or not isinstance(raw.get("runs", []), list)
        or not isinstance(raw.get("items", {}), dict)
    ):
        raise ValueError(f"uszkodzone meta.{META_KEY} w sprawie")  # noqa: TRY004 - wywołujący łapią ValueError
    raw.setdefault("runs", [])
    raw.setdefault("items", {})
    return raw


def _host_only(raw: object) -> str:
    try:
        return (urlsplit(str(raw)).hostname or "?")[:253]
    except ValueError:
        return "?"


def _sha(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def resolve_person(graph: Graph, name: str, add: bool) -> tuple[Node, bool]:
    """Osoba z grafu; nieobecną dopisujemy tylko jawnie (--dodaj)."""
    try:
        return teczka.find_person(graph, name), False
    except ValueError:
        if not add:
            raise
    node = Node.make(EntityType.PERSON, name, source="operator")
    return graph.add_node(node), True


def add_observation(graph: Graph, person: Node, purl, obs: dict, now: str) -> tuple[bool, bool]:
    """Dopisuje obserwację adresu do sprawy. -> (zmieniono, nowy kandydat). Idempotentne: ta sama obserwacja
    (rodzaj, dostawca, zapytanie, adres źródłowy, skrót tekstu) drugi raz nic nie zmienia. Decyzji nie dotyka."""
    st = state(graph, create=True)
    node = Node.make(
        EntityType.URL,
        purl.canonical,
        {
            "kind": "profile" if purl.is_account else "search_result",
            "site": purl.platform,
            "url_class": purl.url_class,
            "discovery": True,
        },
        SOURCE,
    )
    item = st["items"].get(node.key)
    new = item is None
    if new:
        item = st["items"][node.key] = {
            "url": purl.canonical,
            "platform": purl.platform,
            "url_class": purl.url_class,
            "identifier": purl.identifier,
            "person": person.value,
            "source_urls": [],
            "people": [person.value],
            "observations": [],
            "first_seen": now,
        }
    changed = new
    people = item.setdefault("people", [item.get("person")] if item.get("person") else [])
    if person.value not in people:
        people.append(person.value)
        changed = True
    if purl.source not in item["source_urls"] and len(item["source_urls"]) < MAX_SOURCE_URLS:
        item["source_urls"].append(purl.source)
        changed = True
    obs = {"person": person.value, **obs}
    obs_id = _sha(
        "|".join(
            str(x)
            for x in (person.id, *(obs.get(k, "") for k in ("kind", "provider", "query", "source_url", "text_sha256")))
        )
    )[:16]
    if all(o.get("id") != obs_id for o in item["observations"]) and len(item["observations"]) < MAX_OBSERVATIONS:
        item["observations"].append({"id": obs_id, **obs})
        changed = True
    if node.id not in graph.nodes or person.id not in {
        e.src for e in graph.edges.values() if e.dst == node.id and e.source == SOURCE
    }:
        graph.add_node(node, now)
        canon = graph.nodes[node.id]
        relation = CANDIDATE if is_profile(canon) and purl.is_account else MENTION
        evidence = (
            f"wyszukiwanie profili: {purl.platform}, {purl.url_class}. Hipoteza: łączy z osobą tylko decyzja operatora"
            if relation == CANDIDATE
            else f"wyszukiwanie profili: {purl.platform}, {purl.url_class}. Wzmianka w wyniku, nie konto osoby"
        )
        graph.add_edge(Edge(person.id, canon.id, relation, SOURCE, 0.0, evidence, now))
        changed = True
    return changed, new


STORED = "ustalenia z dowodem; tekst materiału nie jest zapisywany (tylko skrót SHA-256 i długość)"


def _material_obs(kind: str, text: str, person: Node, source_url: str, now: str, **extra) -> dict:
    """Obserwacja do zapisu: pochodzenie, skrót i ustalenia. Tekst materiału zostaje w pamięci."""
    result = analyze(text, kind, person.value, now, source_url)
    clean = clean_material(text)
    return {
        "kind": kind,
        "acquired_at": now,
        "source_url": source_url,
        "text_sha256": _sha(clean),
        "text_chars": len(clean),
        "stored": STORED,
        "analysis_status": result["status"],
        "findings": result["findings"],
        "skipped": result["skipped"],
        **extra,
    }


def add_material(graph: Graph, person: Node, url: str, text: str, now: str | None = None) -> dict:
    """Ręczny kandydat z materiałem operatora (adres + tekst do 20 000 znaków). Bez sieci, bez czytania plików."""
    now = now or utc_now()
    purl = check_url(url, require_platform=False)
    if text is not None and not isinstance(text, str):
        raise ValueError("materiał: oczekiwano tekstu")
    if text and len(text) > MAX_MATERIAL:
        raise ValueError(f"materiał: najwyżej {MAX_MATERIAL} znaków (podano {len(text)})")
    obs = _material_obs(KIND_MANUAL, text or "", person, purl.source, now, provider="operator", query="")
    changed, new = add_observation(graph, person, purl, obs, now)
    return {
        "changed": changed,
        "new": new,
        "url": purl.canonical,
        "url_class": purl.url_class,
        "account": purl.is_account,
        "analysis_status": obs["analysis_status"],
        "findings": len(obs["findings"]),
        "text_sha256": obs["text_sha256"],
        "text_chars": obs["text_chars"],
    }


# --- wyszukiwanie --------------------------------------------------------------------------------------------


def plan(person_name: str, context: str = "") -> list:
    _, brave = load_connector()
    return brave.build_queries(person_name, context)


def _call(pkg, brave, conn, name: str, query, cfg: BraveConfig, http, limits: Limits, timeout: float):
    subject = pkg.Subject(pkg.InputKind.PERSON_NAME, name)
    ctx = pkg.Context(
        salt=secrets.token_hex(16),
        timeout=timeout,
        http=http,
        extra={"query": query, "api_key": cfg.key, "count": limits.results},
    )
    return asyncio.run(pkg.run([conn], subject, ctx))[0]


def search(
    graph: Graph,
    person: Node,
    context: str,
    limits: Limits,
    cfg: BraveConfig,
    http=None,
    clock: Callable[[], float] = time.monotonic,
    now: str | None = None,
    loader=load_connector,
    probe: Callable[[str, int], bool] | None = None,
) -> dict:
    """Jeden przebieg w budżecie. Wyniki częściowe zostają w sprawie razem z przyczyną przerwania.

    Fail-closed: brak wymaganego proxy albo proxy nieosiągalne przed startem = ConfigError i zero zapytań; błąd
    połączenia przez proxy w trakcie = zatrzymanie przebiegu bez ponowień (nigdy połączenie bezpośrednie)."""
    limits.validate()
    problem = cfg.blocking_problem()
    if problem:
        raise ConfigError(problem)
    if cfg.proxy and (http is None or probe is not None):
        m = _PROXY.match(cfg.proxy)
        if not m or not 1 <= int(m.group("port")) <= 65535:  # konfiguracja zbudowana poza load_config
            raise ConfigError(
                f"{PROXY_ENV}: oczekiwane http://host:port: zapytania zablokowane, bez połączenia bezpośredniego"
            )
        host, port = m.group("host").strip("[]"), int(m.group("port"))
        if not (probe or _proxy_reachable)(host, port):
            raise ConfigError(
                f"proxy {host}:{port} jest nieosiągalne: zapytania zablokowane (fail-closed, bez "
                "połączenia bezpośredniego)"
            )
    now = now or utc_now()
    st = state(graph, create=True)
    try:
        pkg, brave = loader()
        queries = brave.build_queries(person.value, context)
    except siblings.SiblingUnavailable as exc:
        raise ConfigError(f"{REASONS['unavailable']}: {exc}") from None
    if http is None:
        try:
            http = pkg.UrllibClient(proxy=cfg.proxy)  # stały User-Agent klienta; jedno proxy na cały przebieg
        except ValueError:  # komunikat transportu pomijamy: adres proxy może zawierać login:hasło
            raise ConfigError(
                f"{PROXY_ENV}: adres proxy odrzucony przez transport (oczekiwane http://host:port): "
                "zapytania zablokowane, bez połączenia bezpośredniego"
            ) from None
    conn = pkg.registry.get("brave_search")
    started = clock()
    number = max((int(r.get("number", 0)) for r in st["runs"] if isinstance(r, dict)), default=0) + 1
    report = {
        "number": number,
        "started": now,
        "person": person.value,
        "context": context,
        "provider": PROVIDER,
        "channel": cfg.channel(),
        "limits": {k: getattr(limits, k) for k in Limits.HARD},
        "queries": [],
        "skipped": [],
        "discarded": [],
        "stop_reason": "",
        "partial": False,
    }
    calls, new_candidates, halted = 0, 0, ""
    seen_keys: set[str] = set()
    for i, query in enumerate(queries):
        elapsed = clock() - started
        why = halted or (
            "budżet wywołań wyczerpany"
            if calls >= limits.calls
            else "limit czasu przebiegu"
            if limits.seconds - elapsed < MIN_CALL_SECONDS
            else "limit kandydatów osiągnięty"
            if len(seen_keys) >= limits.candidates
            else ""
        )
        if why:
            report["skipped"] += [{"query": q.text, "variant": q.variant, "why": why} for q in queries[i:]]
            report["stop_reason"] = why
            break
        attempts, finding = 0, None
        while True:
            attempts += 1
            calls += 1
            remaining = limits.seconds - (clock() - started)
            finding = _call(pkg, brave, conn, person.value, query, cfg, http, limits, min(15.0, remaining))
            kind = (
                "results"
                if finding.status.name == "FOUND"
                else "empty"
                if finding.status.name == "NOT_FOUND"
                else (finding.error_kind or "unexpected")
            )
            if cfg.proxy and kind in _RETRY:  # błąd sieci przez proxy: zatrzymanie, nie ponowienie (fail-closed)
                kind = "proxy_down"
            if (
                kind in _RETRY
                and calls < limits.calls
                and attempts < 2
                and limits.seconds - (clock() - started) >= MIN_CALL_SECONDS
            ):
                continue
            break
        status = _STATUS_OF.get(kind, Status.ERROR)
        results = list((finding.extra or {}).get("results") or []) if kind == "results" else []
        row = {
            "query": query.text,
            "variant": query.variant,
            "site": query.site,
            "status": status.value,
            "reason": REASONS.get(kind, kind),
            "reason_code": kind,
            "results": len(results),
            "attempts": attempts,
            "accepted": 0,
        }
        broken = int((finding.extra or {}).get("skipped_records") or 0)
        if broken:  # lista mieszana: poprawne rekordy przyjęte, uszkodzone policzone (nie "brak wyników")
            row["broken_records"] = broken
        for res in results:
            try:
                purl = check_url(res.get("url"), require_platform=True)
            except ValueError as exc:  # zapisujemy tylko host (adres mógł zawierać dane logowania)
                report["discarded"].append({"host": _host_only(res.get("url")), "why": str(exc)})
                continue
            key = Node.make(EntityType.URL, purl.canonical).key
            if key not in seen_keys and len(seen_keys) >= limits.candidates:
                report["discarded"].append({"host": _host_only(purl.canonical), "why": "limit kandydatów przebiegu"})
                continue
            seen_keys.add(key)
            # tytuł i fragment wyszukiwarki: analiza w pamięci, do sprawy trafiają tylko ustalenia z dowodem
            material = "\n".join(str(res.get(k)) for k in ("title", "snippet") if res.get(k))
            obs = _material_obs(
                KIND_SNIPPET,
                material,
                person,
                purl.source,
                now,
                provider=PROVIDER,
                query=query.text,
                variant=query.variant,
            )
            _, new = add_observation(graph, person, purl, obs, now)
            new_candidates += int(new)
            row["accepted"] += 1
        report["queries"].append(row)
        graph.runs.append(
            RunRecord(
                TRANSFORM,
                person.id,
                status,
                now,
                note=f"przebieg {number}, {query.variant}, {query.site}: {row['reason']}",
                error="" if status in (Status.FOUND, Status.NOT_FOUND) else row["reason"],
                stats={"results": len(results), "accepted": row["accepted"], "attempts": attempts},
            )
        )
        if kind in _HALT:
            halted = _HALT[kind]
    if halted and not report["stop_reason"]:
        report["stop_reason"] = halted
    statuses = {
        s: sum(1 for q in report["queries"] if q["status"] == s) for s in ("FOUND", "NOT_FOUND", "UNKNOWN", "ERROR")
    }
    report["partial"] = bool(report["skipped"]) or statuses["ERROR"] > 0
    report["stop_reason"] = report["stop_reason"] or "wykonano wszystkie zapytania planu"
    report["totals"] = {
        "calls": calls,
        "planned": len(queries),
        "new_candidates": new_candidates,
        "candidates_seen": len(seen_keys),
        "discarded": len(report["discarded"]),
        "seconds": round(clock() - started, 1),
        "statuses": statuses,
    }
    report["discarded"] = report["discarded"][:50]
    st["runs"] = (st["runs"] + [report])[-KEEP_RUNS:]
    graph.meta[META_KEY] = st
    return report


# --- widok (panel, raport) -----------------------------------------------------------------------------------


def _assessment(item: dict, observations: list[dict] | None = None) -> str:
    """Ocena dopasowania: opis, nie procent i nie decyzja."""
    if item.get("url_class") not in ACCOUNT_CLASSES:
        return f"nie dotyczy: {item.get('url_class')}, nie konto osoby"
    obs = observations if observations is not None else item.get("observations") or []
    if any(f.get("kind") == F_NAME for o in obs for f in o.get("findings") or []):
        return "zgodność nazwy w materiale: wymaga przeglądu (zgodność nazwy nie potwierdza tożsamości)"
    if any(o.get("text_chars") for o in obs):
        return "brak zgodności nazwy w dostępnym materiale"
    return "brak materiału do oceny"


def _analysis_status(item: dict, observations: list[dict] | None = None) -> str:
    obs = observations if observations is not None else item.get("observations") or []
    if any(o.get("kind") == KIND_MANUAL and o.get("text_chars") for o in obs):
        return "przeanalizowano materiał operatora"
    if any(o.get("text_chars") for o in obs):
        return "przeanalizowano tylko fragment wyszukiwarki (nie cały profil)"
    return STATUS_EMPTY


def summary(graph: Graph) -> dict:
    """Karty kandydatów i przebiegi dla panelu (`eg sprawa`) i raportu. Stare sprawy: puste listy."""
    try:
        st = state(graph)
    except ValueError:
        return {"items": [], "runs": [], "limits": _limits_view(), "error": f"uszkodzone meta.{META_KEY}"}
    people = graph.nodes_of_type(EntityType.PERSON)
    cards = []
    for key, item in st["items"].items():
        node = graph.nodes.get(f"{EntityType.URL.value}:{key}")
        linked_people = [
            p
            for p in people
            if node is not None
            and any(
                e.src == p.id and e.dst == node.id and e.source == SOURCE and e.relation in (CANDIDATE, MENTION)
                for e in graph.edges.values()
            )
        ]
        if not linked_people and item.get("person"):
            linked_people = [p for p in people if p.value == item.get("person")]
        for person in linked_people:
            observations = [
                o for o in item.get("observations") or [] if (o.get("person") or item.get("person")) == person.value
            ]
            decisions = []
            if node is not None:
                d = teczka.decision_of(graph, person, node)
                if d:
                    edge = graph.edges.get((person.id, node.id, d, teczka.OPERATOR))
                    decisions.append(
                        {
                            "person": person.value,
                            "decision": "potwierdzony" if d == teczka.CONFIRMED else "odrzucony",
                            "evidence": edge.evidence if edge else "",
                        }
                    )
            account = bool(node is not None and is_profile(node) and item.get("url_class") in ACCOUNT_CLASSES)
            cards.append(
                {
                    "url": item.get("url"),
                    "platform": item.get("platform"),
                    "url_class": item.get("url_class"),
                    "identifier": item.get("identifier") or {},
                    "person": person.value,
                    "account": account,
                    "source_urls": sorted({o.get("source_url") for o in observations if o.get("source_url")}),
                    "first_seen": item.get("first_seen", ""),
                    # title/excerpt/redacted_contacts występują tylko w sprawach sprzed R5A: pokazujemy, nie dopisujemy
                    "observations": [
                        {
                            **{
                                k: o.get(k)
                                for k in (
                                    "kind",
                                    "provider",
                                    "query",
                                    "variant",
                                    "acquired_at",
                                    "title",
                                    "excerpt",
                                    "source_url",
                                    "analysis_status",
                                    "text_chars",
                                    "redacted_contacts",
                                    "findings",
                                    "skipped",
                                    "stored",
                                )
                            },
                            "kind_label": KIND_LABELS.get(o.get("kind"), o.get("kind")),
                        }
                        for o in observations
                    ],
                    "analysis_status": _analysis_status(item, observations),
                    "assessment": _assessment(item, observations),
                    "source_status": "kandydat z wyszukiwarki"
                    if any(o.get("kind") == KIND_SNIPPET for o in observations)
                    else "dodany przez operatora",
                    "decisions": decisions,
                    "decision": "; ".join(f"{d['person']}: {d['decision']}" for d in decisions)
                    or ("wymaga decyzji operatora" if account else "nie dotyczy (to nie konto osoby)"),
                }
            )
    order = {True: 0, False: 1}
    cards.sort(
        key=lambda c: (bool(c["decisions"]), order[c["account"]], c["person"], c["platform"] or "", c["url"] or "")
    )
    return {"items": cards, "runs": [r for r in st["runs"] if isinstance(r, dict)][-5:], "limits": _limits_view()}


def _limits_view() -> dict:
    d = Limits()
    return {
        "defaults": {k: getattr(d, k) for k in Limits.HARD},
        "max": {k: v[1] for k, v in Limits.HARD.items()},
        "provider": PROVIDER,
    }
