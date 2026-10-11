"""Panel OSINT: lokalny widok webowy nad narzedziami z repo: username-engine, theHarvester, HIBP,
dns-audit, phone-check, exif-map, meta-search (Threads API, Instagram Business Discovery, Strony Facebooka).

Tylko stdlib. Serwer slucha wylacznie na 127.0.0.1, kazde POST wymaga tokenu sesji (ochrona przed
wywolaniem z obcej strony / DNS rebinding). Narzedzia uruchamiane sa jako podprocesy z ich wlasnych .venv,
argumenty jako lista (bez powloki).
"""
from __future__ import annotations

import hashlib
import html
import json
import os
import re
import secrets
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
import time
import urllib.parse
import webbrowser
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path, PureWindowsPath

ROOT = Path(__file__).resolve().parent.parent
PANEL = Path(__file__).resolve().parent
OUT = PANEL / "wyniki"
SPRAWY = OUT / "sprawy"   # sprawy entity-graph: panel nie przyjmuje innych sciezek
TIMEOUT = 180
TIMEOUTS = {"username": 900, "harvester": 300, "meta": 90, "sprawa_kandydaci": 1900,
            "sprawa_profile": 150}  # sekundy; pozostale: TIMEOUT (szukaj-profili: backend najwyzej 120 s)
LONG_TOOLS = {"username", "sprawa_kandydaci"}  # dlugie skany (username-engine): naraz tylko jeden
# Kanal Tor dla username-engine: OSINT_PROXY albo SOCKS Tor Browsera. Zapas (np. Mullvad) silnik czyta sam
# z OSINT_PROXY_FALLBACK. meta-search ma osobne META_PROXY i nie korzysta z tego kanalu.
PANEL_PROXY = os.environ.get("OSINT_PROXY") or "socks5h://127.0.0.1:9150"
# Limity skanu nazwy wg poziomu i kanalu (pomiar 04.10.2026: Tor ~1 s/serwis, bezposrednio ~0,2 s/serwis;
# standard ~806 serwisow, full ~5140; quick = tylko archiwum Wayback, ograniczane tempem archive.org)
USERNAME_TIMEOUTS = {
    "quick": {"proxy": 600, "direct": 600},
    "standard": {"proxy": 2700, "direct": 900},
    "full": {"proxy": 7200, "direct": 1800},
}
TOKEN = secrets.token_urlsafe(24)
HOST = "127.0.0.1"
PORT = int(os.environ.get("OSINT_PANEL_PORT", "8765"))

TOOLS = {
    "dns": ("dns-audit", "dns_audit"),
    "phone": ("phone-check", "phone_check"),
    "hibp": ("hibp-monitor", "hibp_monitor"),
    "exif": ("exif-map", "exif_map"),
    "username": ("username-engine", "username_engine"),
    "meta": ("meta-search", "meta_search"),
    "sprawa": ("entity-graph", "entity_graph"),            # widok i zmiany sprawy (logika w entity-graph)
    "sprawa_kandydaci": ("entity-graph", "entity_graph"),  # runda kandydatow profili (username-engine)
    "sprawa_profile": ("entity-graph", "entity_graph"),    # szukaj-profili: JEDYNE narzedzie z kluczem Brave
}
BRAVE_KEY_ENV = "BRAVE_SEARCH_API_KEY"   # dopuszczany tylko w srodowisku narzedzia sprawa_profile
MAX_MATERIAL = 20_000                    # znakow tekstu operatora (tez limit w entity-graph)
MAX_BODY = 20_000                        # bajtow zapytania POST
MAX_BODY_MATERIAL = 130_000              # sprawa_profile_material: 20 000 znakow nawet jako \uXXXX w JSON

META_OPS = ("threads_profile", "threads_search", "instagram_profile", "facebook_page", "links", "config")

# Krotki, bezpieczny status laboratorium widoczny wyłącznie lokalnie w panelu.
# Szczegółowe dowody pozostają w raportach audytowych; tutaj nie umieszczamy sekretów,
# adresów spraw ani danych osób.
LAB_STATUS = {
    "updated": "2026-10-05",
    "ready": [
        "Sprawy, graf dowodów i decyzje operatora są dostępne w zakładce Sprawa.",
        "Skan nazwy ma tryb Tor fail-closed, raport częściowy i listę ręcznej weryfikacji.",
        "DNS może działać przez DoH w kanale Tor; raporty HTML mają CSP bez ruchu zewnętrznego.",
    ],
    "findings": [
        "Wayback jest użyteczny jako ślad historyczny, ale nie jako dowód istnienia konta.",
        "Błędy proxy i blokady anty-bot są rozdzielane od braku wyniku.",
        "Ta sama nazwa użytkownika, zdjęcie lub domena nie łączą automatycznie osób.",
        "Materiał profilu jest minimalizowany: zapisujemy skrót i ustalenia z dowodem.",
    ],
    "blockers": [
        "Pełny skan nazwy nadal wymaga otwartej karty; zadanie w tle i wznowienie są do zrobienia.",
        "Równoległe zapisy do jednej sprawy wymagają blokady per sprawa, aby nie przerwać łańcucha audytu.",
        "Import dostarczonego eksportu konta social media (archiwum danych) nie jest jeszcze zbudowany.",
        "Lokalne AI zależy od działającej Ollamy; jakość porządkowania nie ma jeszcze zestawu testowego.",
    ],
    "decisions": [
        "Które błędy wolno ponawiać po zmianie obwodu Tor i ile razy.",
        "Czy i w jakim zakresie włączyć lokalny model AI do porządkowania materiału operatora.",
    ],
    # Cztery rodzaje wyniku; panel i raporty nie moga zamieniac jednego w drugi (np. bledu proxy w brak wyniku).
    "statuses": [
        {"key": "found", "label": "znaleziono", "tone": "ok",
         "text": "Źródło odpowiedziało i zwróciło dane. To trop ze źródłem, nie potwierdzenie tożsamości."},
        {"key": "error", "label": "błąd", "tone": "bad",
         "text": "Narzędzie, proxy lub źródło zawiodło. Wynik jest nieznany; to nie jest brak wyniku."},
        {"key": "no_result", "label": "brak wyniku", "tone": "",
         "text": "Źródło odpowiedziało poprawnie i nic nie znalazło. To nie dowód, że czegoś nie ma."},
        {"key": "blocked", "label": "blokada źródła", "tone": "warn",
         "text": "Limit, CAPTCHA, anty-bot, wymagane logowanie albo brak klucza. Nie obchodzimy blokad."},
        {"key": "partial", "label": "wynik częściowy", "tone": "warn",
         "text": "Część sprawdzeń skończona, reszta przerwana. Raport zachowuje wyniki i listę niesprawdzonych."},
    ],
    # Stan przeplywow panelu: gotowe / czesciowo / do zrobienia (bez obietnic ponad to, co dziala).
    "modules": [
        {"name": "Nazwa użytkownika (username-engine, WhatsMyName)", "state": "gotowe",
         "note": "Tor fail-closed, raport częściowy, lista do ręcznej weryfikacji."},
        {"name": "Wayback", "state": "gotowe", "note": "Tylko ślad historyczny, nie dowód istnienia konta."},
        {"name": "E-mail i domena (theHarvester)", "state": "gotowe", "note": "Źródła bez kluczy API; status każdego źródła."},
        {"name": "DNS: MX, SPF, DKIM, DMARC, DNSSEC", "state": "gotowe", "note": "Opcjonalnie DoH przez Tor."},
        {"name": "HIBP", "state": "częściowo",
         "note": "Domeny, katalog i hasła (k-anonimowość) gotowe; własny adres e-mail wymaga płatnego klucza HIBP."},
        {"name": "Telefon", "state": "gotowe",
         "note": "Tylko format, kraj, typ linii i plan numeracyjny; bez wyszukiwania i lokalizacji."},
        {"name": "Zdjęcia: EXIF i GPS", "state": "gotowe",
         "note": "Analiza lokalna; ręczne linki TinEye, Google Lens, Bing, Yandex i Copernicus."},
        {"name": "Sprawy, osoby, źródła, dowody, graf", "state": "gotowe",
         "note": "entity-graph: decyzje operatora i dziennik audytu ze skrótami."},
        {"name": "Eksport GraphML / Maltego", "state": "gotowe",
         "note": "Pobieranie ze sprawy: GraphML oraz CSV do importu tabeli w Maltego."},
        {"name": "Dziennik audytu sprawy", "state": "gotowe",
         "note": "Wpisy przed i po każdej zmianie, łańcuch skrótów sprawdzany przy odczycie."},
        {"name": "Materiał operatora", "state": "gotowe", "note": "Ręczne dodanie tekstu do sprawy, zapis skrótu i ustaleń."},
        {"name": "Audyt materiału social media", "state": "częściowo",
         "note": "Adapter Meta/Threads jest opcjonalny i niezweryfikowany produkcyjnie; podstawowy przepływ działa bez niego przez publiczny indeks i materiał operatora."},
        {"name": "Asystent sprawy i lokalne AI", "state": "częściowo",
         "note": "Reguły: porządek, sprzeczności, dozwolone kroki. Ollama tylko na 127.0.0.1, odpowiedź filtrowana; "
                 "bez potwierdzania tożsamości."},
        {"name": "Metryczka wyniku", "state": "gotowe",
         "note": "Źródło, identyfikator, czas UTC, status, kanał, ograniczenia, SHA-256 i decyzja: przy wyniku "
                 "narzędzia, haśle HIBP i w raporcie zbiorczym skanu."},
        {"name": "Skany w tle ze wznowieniem", "state": "do zrobienia", "note": "Dziś skan trwa przy otwartej karcie."},
    ],
    "guardrails": [
        "Nie budujemy wabików IP, obchodzenia resetów, odsłaniania ukrytych wyników ani lokalizacji telefonu.",
        "Nie integrujemy automatycznego wyszukiwania cudzych twarzy ani surowych baz wycieków.",
        "AI może porządkować dostarczony materiał i wskazywać sprzeczności; nie potwierdza tożsamości.",
        "Nazwa, zdjęcie, telefon lub adres same nie wystarczają do twierdzenia „ta sama osoba”.",
        "Bez pobierania prywatnych profili, omijania logowania, CAPTCHA, paywalli i limitów.",
    ],
}

# Konfiguracja widoczna w Laboratorium: tylko czy zmienna jest ustawiona, nigdy jej wartosc.
CONFIG_VARS = (
    ("OSINT_PROXY", "kanał Tor/proxy (bez niej: SOCKS Tor Browsera 127.0.0.1:9150)"),
    ("HIBP_API_KEY", "HIBP: sprawdzanie własnego adresu e-mail (płatny klucz)"),
    ("BRAVE_SEARCH_API_KEY", "wyszukiwanie profili w sprawie (Brave Search API)"),
    ("THREADS_ACCESS_TOKEN", "Meta: Threads API"),
    ("INSTAGRAM_ACCESS_TOKEN", "Meta: Instagram Business Discovery"),
    ("FACEBOOK_ACCESS_TOKEN", "Meta: publiczne strony Facebooka"),
    ("META_PROXY", "Meta: kanał proxy"),
)
OLLAMA_ADDR = ("127.0.0.1", 11434)   # lokalne AI asystenta sprawy (entity-graph asystent --ai)

NARZEDZIA = ROOT / "narzedzia"
UE_PY = Path(os.path.expandvars(r"%LOCALAPPDATA%\Python\pythoncore-3.14-64\python.exe"))
HARVESTER_PY = NARZEDZIA / "theharvester-venv" / "Scripts" / "python.exe"

# theHarvester na Windowsie (aiodns nie widzi serwerow DNS): bez poprawki kazde zrodlo konczy sie "transport-error" i raport pokazuje
# "No hosts found" (pomiar 03.10.2026, mozilla.org: 0 hostow, z poprawka 272). -v wypisuje status kazdego
# zrodla, wiec awaria (np. crt.sh http-502) jest widoczna zamiast udawac brak wynikow.
_HARVESTER_SCRIPT = (
    "import sys, aiohttp.resolver as r, aiohttp.connector as c\n"
    "r.DefaultResolver = r.ThreadedResolver; c.DefaultResolver = r.ThreadedResolver\n"
    "from theHarvester.theHarvester import main\n"
    "sys.argv = ['theHarvester'] + sys.argv[1:]\n"
    "main()\n"
)

# Zrodla theHarvestera dzialajace bez klucza API (pozostale wymagaja api-keys.yaml).
HARVESTER_SOURCES = ("crtsh", "certspotter", "rapiddns", "otx", "urlscan", "hackertarget", "subdomaincenter",
                     "thc", "duckduckgo", "yahoo", "waybackarchive", "hudsonrock", "commoncrawl")

_LONG_LOCK = threading.Lock()

# Podglad na zywo dlugiego skanu: wyjscie narzedzia trafia do plikow tymczasowych (poza OUT), GET /api/postep
# czyta je w trakcie. Naraz trwa najwyzej jeden dlugi skan (_LONG_LOCK), wiec wystarcza jeden wpis.
_LIVE: dict = {}
LIVE_MAX = 100_000  # znakow konca wyjscia zwracanych w podgladzie

MAX_PROCS = 4  # globalny limit rownoczesnych podprocesow narzedzi
_PROC_SLOTS = threading.BoundedSemaphore(MAX_PROCS)


class Busy(Exception):
    """Inny dlugi skan nazwy uzytkownika juz trwa."""


class Overloaded(Exception):
    """Osiagnieto globalny limit rownoczesnych podprocesow narzedzi."""


class BadField(ValueError):
    """Pole dokumentu ma zly typ (np. obiekt zamiast tekstu): HTTP 422, narzedzie nie startuje."""


_SAFE_NAME = re.compile(r"^[A-Za-z0-9._-]{1,120}$")

_CSP_API = "default-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'"


def tool_python(tool: str) -> list[str]:
    """Python narzedzia: jego .venv, a gdy brak - biezacy interpreter (zaleznosci musza byc wtedy zainstalowane)."""
    if tool == "username":
        return [str(UE_PY) if UE_PY.exists() else sys.executable]
    folder = ROOT / TOOLS[tool][0]
    for cand in (folder / ".venv" / "Scripts" / "python.exe", folder / ".venv" / "bin" / "python"):
        if cand.exists():
            return [str(cand)]
    return [sys.executable]


_SECRET_ENV = re.compile(r"(KEY|TOKEN|SECRET|PASSWORD|PASSWD|CREDENTIAL)", re.IGNORECASE)


def tool_env(tool: str) -> dict[str, str]:
    env = dict(os.environ, PYTHONUTF8="1", PYTHONIOENCODING="utf-8")
    # username-engine uruchamiany posrednio (entity-graph: runda kandydatow) tez idzie przez Tora;
    # jawne --direct w akcji "username" ma pierwszenstwo przed zmienna
    env.setdefault("OSINT_PROXY", PANEL_PROXY)
    if tool == "meta":
        # Meta ma token powiązany z aplikacją/kontem: panel nie może bez ostrzeżenia wyjść bezpośrednio.
        # Brak META_PROXY kończy się notą fail-closed w meta-search, bez fallbacku na połączenie bezpośrednie.
        env["META_REQUIRE_PROXY"] = "1"
    if tool.startswith("sprawa"):   # entity-graph nie potrzebuje sekretow (te same zasady co jego podprocesy)
        keep = {BRAVE_KEY_ENV} if tool == "sprawa_profile" else set()   # wyjatek: klucz wyszukiwarki
        env = {k: v for k, v in env.items() if k in keep or not _SECRET_ENV.search(k)}
    else:
        env.pop(BRAVE_KEY_ENV, None)
    if tool != "sprawa_profile":
        env = {k: v for k, v in env.items() if not k.startswith("BRAVE_")}
    src = str(ROOT / TOOLS[tool][0] / "src")
    env["PYTHONPATH"] = src + os.pathsep + env.get("PYTHONPATH", "")
    return env


def _channel_args(params: dict) -> list[str]:
    """Kanal sieciowy narzedzia: domyslnie Tor (fail-closed w narzedziu: bez Tora nic nie wychodzi),
    bezposrednio tylko jawnie."""
    channel = _text(params, "channel", "tor").strip() or "tor"
    if channel == "tor":
        return ["--proxy", PANEL_PROXY]
    if channel == "direct":
        return ["--direct"]
    raise ValueError("kanal: tor albo direct")


def slug(text: str) -> str:
    return re.sub(r"[^A-Za-z0-9.-]+", "_", text)[:60].strip("_") or "x"


def _text(params: dict, key: str, default: str = "") -> str:
    """Pole tekstowe: brak/null = default, tekst = tekst, inny typ = BadField (bez str() na obiektach i listach)."""
    raw = params.get(key)
    if raw is None:
        return default
    if not isinstance(raw, str):
        raise BadField(f"pole {key}: oczekiwano tekstu")
    return raw


def _flag(params: dict, key: str) -> bool:
    """Pole wyboru: true/false (brak/null = false). Tekst "false" nie moze wlaczyc opcji."""
    raw = params.get(key)
    if raw is None:
        return False
    if not isinstance(raw, bool):
        raise BadField(f"pole {key}: oczekiwano true/false")
    return raw


def _req(params: dict, key: str, maxlen: int = 300) -> str:
    val = _text(params, key).strip()
    if not val:
        raise ValueError(f"brak pola: {key}")
    if len(val) > maxlen or "\n" in val or "\r" in val:
        raise ValueError(f"nieprawidlowe pole: {key}")
    if val.startswith("-"):
        raise ValueError(f"pole {key} nie moze zaczynac sie od '-'")
    return val


def _opt_int(params: dict, key: str, lo: int, hi: int) -> int | None:
    """Opcjonalna liczba calkowita w zakresie lo..hi; puste pole = None, poza zakresem = blad."""
    raw = params.get(key)
    if raw is None or (isinstance(raw, str) and not raw.strip()):
        return None
    if isinstance(raw, bool) or not isinstance(raw, (int, str)):
        raise BadField(f"pole {key}: oczekiwano liczby calkowitej")
    try:
        val = int(str(raw).strip())
    except ValueError:
        raise ValueError(f"{key}: liczba calkowita") from None
    if not lo <= val <= hi:
        raise ValueError(f"{key}: zakres {lo}-{hi}")
    return val


def build_command(action: str, params: dict) -> tuple[str, list[str], str | None]:
    """Zwraca (narzedzie, argumenty po `-m modul`, nazwa pliku raportu w wyniki/ albo None)."""
    stamp = time.strftime("%Y%m%d-%H%M%S") + "-" + secrets.token_hex(4)
    if action in CASE_ACTIONS:
        return build_case(action, params)
    if action == "dns":
        domain = _req(params, "domain", 253)
        report = f"dns_{slug(domain)}_{stamp}.html"
        args = [domain, "--html", str(OUT / report)]
        sel = _text(params, "selectors").strip()
        if sel:
            if not re.fullmatch(r"[A-Za-z0-9._,-]{1,200}", sel):
                raise ValueError("nieprawidlowe selektory DKIM")
            args += ["--selectors", sel]
        args += _channel_args(params)   # tor: DNS-over-HTTPS przez Tora, dostawca internetu nie widzi domeny
        return "dns", args, report
    if action == "phone":
        number = _req(params, "number", 40)
        region = _text(params, "region", "PL").strip().upper() or "PL"
        if not re.fullmatch(r"[A-Z]{2}", region):
            raise ValueError("region: dwuliterowy kod ISO, np. PL")
        args = [number, "--region", region]
        if _flag(params, "dorks"):  # panel: telefon tylko jako format, kraj, typ linii i plan numeracyjny
            raise ValueError("warianty numeru do wyszukiwania sa w panelu wylaczone (tylko plan numeracyjny)")
        return "phone", args, None
    if action == "hibp_domain":
        domain = _req(params, "domain", 253)
        return "hibp", ["breaches", "--domain", domain, "--no-save"], None
    if action == "hibp_catalog":
        limit = _opt_int(params, "limit", -10**9, 10**9)
        limit = 20 if limit is None else max(1, min(limit, 500))
        return "hibp", ["breaches", "--catalog", "--limit", str(limit)], None
    if action == "username":
        name = _req(params, "username", 100)
        if not re.fullmatch(r"[\w .\-]+", name):
            raise ValueError("nazwa: litery, cyfry, spacja, '.', '_' i '-'")
        report = f"un_{slug(name)}_{stamp}.html"
        # username-engine trzyma raport w OUT/<id skanu>/ i kasuje go po 12 h (retencja); przyjmuje sama nazwe pliku
        args = [name, "--report", report, "--results-dir", str(OUT)]
        args += _channel_args(params)
        level = _text(params, "level", "standard").strip() or "standard"
        if level not in USERNAME_TIMEOUTS:
            raise ValueError("poziom: quick, standard albo full")
        args += ["--level", level]
        tags = _text(params, "tags").strip()
        if tags:
            if not re.fullmatch(r"[A-Za-z0-9_,][A-Za-z0-9_,-]{0,99}", tags):
                raise ValueError("nieprawidlowe tagi (np. social,pl)")
            args += ["--tags", tags]
        if _flag(params, "only"):
            args.append("--no-variants")
        if _flag(params, "wayback"):
            args.append("--wayback")
        years = _text(params, "years").strip()
        if years:
            if not re.fullmatch(r"[0-9][0-9,]{0,49}", years):
                raise ValueError("rok: cyfry i przecinki, np. 1990,90")
            args += ["--years", years]
        limit = _opt_int(params, "limit", 1, 10000)
        if limit is not None:
            args += ["--limit", str(limit)]
        return "username", args, report
    if action == "harvester":
        domain = _req(params, "domain", 253)
        if not re.fullmatch(r"[A-Za-z0-9]([A-Za-z0-9.-]*[A-Za-z0-9])?", domain) or ".." in domain:
            raise ValueError("nieprawidlowa domena")
        raw = params.get("source") or "crtsh,certspotter,hackertarget"  # samo crt.sh czesto zwraca 502/503
        if isinstance(raw, list) and all(isinstance(x, str) for x in raw):
            sources = raw
        elif isinstance(raw, str):
            sources = raw.split(",")
        else:
            raise BadField("pole source: tekst albo lista tekstow")
        sources = [x.strip() for x in sources if x.strip()]
        bad = [x for x in sources if x not in HARVESTER_SOURCES]
        if not sources or bad:
            raise ValueError(f"nieznane zrodlo: {', '.join(bad) or '-'} (dozwolone bez klucza: "
                             f"{', '.join(HARVESTER_SOURCES)})")
        limit = _opt_int(params, "limit", 1, 2000)
        return "harvester", ["-d", domain, "-b", ",".join(sources), "-l", str(limit or 100)], None
    if action == "meta":
        return build_meta(params, stamp)
    if action == "exif":
        path = _req(params, "path", 1000)
        if not Path(path).exists():
            raise ValueError(f"nie istnieje: {path}")
        report = f"mapa_{stamp}.html"
        return "exif", [path, "--map", str(OUT / report), "--reverse"], report
    raise ValueError(f"nieznana akcja: {action}")


# --- Sprawa (entity-graph): panel tylko sprawdza ksztalt pol i wybiera katalog z wyniki/sprawy; regule (cel,
# zrodla, decyzje, limity, audyt) egzekwuje entity-graph, uruchamiany jako podproces `python -m entity_graph`.

CASE_ACTIONS = ("sprawa", "sprawa_nowa", "sprawa_relacja", "sprawa_relacja_decyzja", "sprawa_profil_decyzja",
                "sprawa_telefon", "sprawa_telefon_reczny", "sprawa_kandydaci", "sprawa_profile_szukaj",
                "sprawa_profile_material", "sprawa_asystent", "sprawa_dziennik")
_HTTP_URL = re.compile(r"https?://[^\s\x00-\x1f\x7f]{1,2040}")
RELATION_TYPES = ("rodzic", "dziecko", "rodzenstwo", "partner", "inna")
_CASE_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}")
_SOURCE_REF = re.compile(r"https?://[^\s\x00-\x1f\x7f]{1,490}|dokument:[A-Za-z0-9._ /-]{1,200}")


def case_dir(params: dict, must_exist: bool = True) -> tuple[str, Path]:
    """Katalog sprawy: tylko bezposredni podkatalog wyniki/sprawy o bezpiecznej nazwie (bez sciezek, '..',
    dowiazan i junction: po rozwiazaniu musi lezec dokladnie w wyniki/sprawy)."""
    name = _req(params, "sprawa", 64)
    if not _CASE_NAME.fullmatch(name) or ".." in name:
        raise ValueError("sprawa: nazwa katalogu z panel/wyniki/sprawy (litery, cyfry, '.', '_', '-')")
    folder = SPRAWY / name
    try:
        inside = folder.resolve().parent == SPRAWY.resolve()
    except OSError:
        inside = False
    if not inside or folder.is_symlink():
        raise ValueError("sprawa: katalog poza panel/wyniki/sprawy")
    if must_exist and not ((folder / "graph.json").is_file() and (folder / "audit.jsonl").is_file()):
        raise ValueError(f"nie ma sprawy '{name}' w panel/wyniki/sprawy")
    if not must_exist and folder.exists():
        raise ValueError(f"sprawa '{name}' juz istnieje")
    return name, folder


def _opt_text(params: dict, key: str, maxlen: int) -> str:
    """Opcjonalne pole tekstowe w jednej linii; niepuste nie moze zaczynac sie od '-'."""
    return _req(params, key, maxlen) if _text(params, key).strip() else ""


def _source_ref(params: dict, key: str = "zrodlo") -> str:
    ref = _req(params, key, 500)
    if not _SOURCE_REF.fullmatch(ref) or ".." in ref.split(":", 1)[1].replace("\\", "/").split("/"):
        raise ValueError("zrodlo: publiczny adres http(s) albo dokument:SCIEZKA pliku w katalogu sprawy")
    return ref


def _case_int(params: dict, key: str, lo: int, hi: int, default: int) -> str:
    val = _opt_int(params, key, lo, hi)
    return str(default if val is None else val)


def build_case(action: str, params: dict) -> tuple[str, list[str], str | None]:
    """Polecenie entity-graph dla akcji sprawy: (narzedzie, argumenty, raport sprawy w wyniki/)."""
    if action == "sprawa_nowa":
        name, folder = case_dir(params, must_exist=False)
        purpose, person = _req(params, "cel", 300), _req(params, "osoba", 120)
        return "sprawa", ["run", "--purpose", purpose, "--person", person, "--offline", "--no-evidence",
                          "--out", str(folder)], f"sprawy/{name}/report.html"
    name, folder = case_dir(params)
    report = f"sprawy/{name}/report.html"
    if action == "sprawa":
        return "sprawa", ["sprawa", str(folder)], report
    if action == "sprawa_asystent":   # reguly zawsze; lokalne AI (Ollama na 127.0.0.1) tylko na wyrazne zyczenie
        return "sprawa", ["asystent", str(folder)] + (["--ai"] if _flag(params, "ai") else []), report
    if action == "sprawa_dziennik":
        return "sprawa", ["dziennik", str(folder), "--limit", _case_int(params, "limit", 1, 1000, 200)], report
    if action == "sprawa_relacja":
        typ = _req(params, "typ", 20)
        if typ not in RELATION_TYPES:
            raise ValueError(f"typ relacji: {', '.join(RELATION_TYPES)}")
        args = ["relacja", str(folder), "--person", _req(params, "osoba", 120), "--typ", typ,
                "--druga-osoba", _req(params, "druga_osoba", 120), "--zrodlo", _source_ref(params),
                "--dowod", _req(params, "dowod", 500)]
        for key, flag, size in (("fragment", "--fragment", 300), ("opis", "--opis", 80)):
            value = _opt_text(params, key, size)
            if value:
                args += [flag, value]
        if _flag(params, "dodaj"):
            args.append("--dodaj")
        return "sprawa", args, report
    if action in ("sprawa_relacja_decyzja", "sprawa_profil_decyzja"):
        decision = _req(params, "decyzja", 20)
        if decision not in ("potwierdz", "odrzuc"):
            raise ValueError("decyzja: potwierdz albo odrzuc")
        if action == "sprawa_relacja_decyzja":
            claim = _req(params, "id", 20)
            if not re.fullmatch(r"r-[0-9a-f]{10}", claim):
                raise ValueError("id twierdzenia: r- i 10 znakow szesnastkowych")
            args = ["relacja-potwierdz", str(folder), "--id", claim, "--dowod", _req(params, "dowod", 500)]
        else:
            profile = _req(params, "profil", 500)
            if not re.fullmatch(r"https?://[^\s\x00-\x1f\x7f]{1,490}", profile):
                raise ValueError("profil: adres http(s)")
            args = ["potwierdz", str(folder), "--person", _req(params, "osoba", 120), "--profil", profile,
                    "--dowod", _req(params, "dowod", 500)]
        return "sprawa", args + (["--odrzuc"] if decision == "odrzuc" else []), report
    if action in ("sprawa_telefon", "sprawa_telefon_reczny"):
        number = _req(params, "numer", 40)
        if not re.fullmatch(r"\+?[0-9 ()./-]{3,40}", number):
            raise ValueError("numer: cyfry, spacje, + ( ) . / -")
        region = _text(params, "region", "PL").strip().upper() or "PL"
        if not re.fullmatch(r"[A-Z]{2}", region):
            raise ValueError("region: dwuliterowy kod ISO, np. PL")
        args = ["telefon", str(folder), "--numer", number, "--region", region]
        if action == "sprawa_telefon_reczny":
            day = _req(params, "data", 10)
            if not re.fullmatch(r"\d{4}-\d{2}-\d{2}", day):
                raise ValueError("data: RRRR-MM-DD")
            args += ["--operator-aktualny", _req(params, "operator_aktualny", 80), "--zrodlo", _source_ref(params),
                     "--data", day]
        return "sprawa", args, report
    if action == "sprawa_profile_szukaj":
        # Brave Search API: klucz czyta entity-graph ze srodowiska / pliku poza repo (nigdy z formularza)
        args = ["szukaj-profili", str(folder), "--person", _req(params, "osoba", 120)]
        context = _opt_text(params, "kontekst", 100)
        if context:
            args += ["--kontekst", context]
        args += ["--max-calls", _case_int(params, "max_wywolan", 1, 12, 6),
                 "--max-results", _case_int(params, "max_wynikow", 1, 20, 20),
                 "--max-candidates", _case_int(params, "max_kandydatow", 1, 100, 50),
                 "--max-seconds", _case_int(params, "max_sekund", 10, 120, 60)]
        if _flag(params, "dodaj"):
            args.append("--dodaj")
        return "sprawa_profile", args, report
    if action == "sprawa_profile_material":
        url = _req(params, "url", 2048)
        if not _HTTP_URL.fullmatch(url):
            raise ValueError("adres: http(s) bez spacji")
        material_text(action, params)   # walidacja typu i dlugosci przed startem
        args = ["material-profilu", str(folder), "--person", _req(params, "osoba", 120), "--url", url,
                "--tekst-stdin"]
        if _flag(params, "dodaj"):
            args.append("--dodaj")
        return "sprawa", args, report
    # sprawa_kandydaci: jedna runda, budzet jawny w formularzu, twarde limity tutaj i w entity-graph
    person, username = _opt_text(params, "osoba", 120), _opt_text(params, "nazwa", 100)
    if bool(person) == bool(username):
        raise ValueError("podaj osobe albo nazwe uzytkownika (dokladnie jedno)")
    args = ["kandydaci", str(folder)] + (["--person", person] if person else ["--username", username])
    names = _opt_text(params, "nazwy", 300)
    if names:
        if not re.fullmatch(r"[A-Za-z0-9._,-]{1,300}", names):
            raise ValueError("nazwy: po przecinku, litery, cyfry, '.', '_', '-'")
        args += ["--nazwy", names]
    args += ["--max-nazw", _case_int(params, "max_nazw", 1, 12, 3),
             "--max-queries", _case_int(params, "max_zapytan", 1, 10, 3),
             "--max-cost", _case_int(params, "max_koszt", 1, 50, 15),
             "--max-seconds", _case_int(params, "max_sekund", 30, 1800, 600),
             "--max-rounds", _case_int(params, "max_rund", 1, 10, 3)]
    tags = _text(params, "tags").strip()
    if tags:
        if not re.fullmatch(r"[A-Za-z0-9_,][A-Za-z0-9_,-]{0,99}", tags):
            raise ValueError("nieprawidlowe tagi (np. social,pl)")
        args += ["--ue-tags", tags]
    limit = _opt_int(params, "limit", 1, 10000)
    if limit is not None:
        args += ["--ue-limit", str(limit)]
    return "sprawa_kandydaci", args, report


def material_text(action: str, params: dict) -> str | None:
    """Tekst dla stdin podprocesu (tylko sprawa_profile_material): nie w argumentach, nie w logach, bez sciezek."""
    if action != "sprawa_profile_material":
        return None
    text = _text(params, "tekst")
    if len(text) > MAX_MATERIAL:
        raise ValueError(f"tekst: najwyzej {MAX_MATERIAL} znakow")
    return text


def list_cases() -> list[dict]:
    """Sprawy w wyniki/sprawy (tylko nazwy katalogow z graph.json i audit.jsonl; bez dowiazan)."""
    if not SPRAWY.is_dir():
        return []
    out = []
    for d in SPRAWY.iterdir():
        try:
            case_dir({"sprawa": d.name})   # ta sama kontrola co przy otwieraniu (junction poza katalogiem odpada)
        except ValueError:
            continue
        if d.is_dir():
            out.append({"nazwa": d.name, "zmieniono": time.strftime(
                "%Y-%m-%d %H:%M:%S", time.localtime((d / "graph.json").stat().st_mtime))})
    return sorted(out, key=lambda x: x["zmieniono"], reverse=True)


def _meta_nick(params: dict) -> str:
    name = _req(params, "username", 31).lstrip("@")
    if not re.fullmatch(r"[A-Za-z0-9._]{1,30}", name):
        raise ValueError("nick: 1-30 znakow, litery, cyfry, '.', '_'")
    return name


def build_meta(params: dict, stamp: str) -> tuple[str, list[str], str | None]:
    """Zakladka Meta. Tokeny API czyta podproces meta-search ze srodowiska / pliku poza repo - panel ich nie widzi
    w parametrach, nie zapisuje i nie przekazuje w argumentach."""
    op = _text(params, "op").strip()
    if op not in META_OPS:
        raise ValueError(f"nieznana operacja Meta: {op or '-'}")
    if op == "config":
        return "meta", ["config"], None
    if op == "facebook_page":
        page = _req(params, "page", 100).lstrip("@")
        if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9.\-]{0,99}", page):
            raise ValueError("Strona: identyfikator liczbowy albo nazwa (litery, cyfry, '.', '-')")
        base = f"meta_facebook_page_{slug(page)}_{stamp}"
        return "meta", ["facebook-page", "--json", str(OUT / f"{base}.json"), "--html", str(OUT / f"{base}.html"),
                        "--", page], f"{base}.html"
    if op == "threads_search":
        query = _req(params, "query", 200)
        stype = (_text(params, "search_type") or "TOP").upper()
        if stype not in ("TOP", "RECENT"):
            raise ValueError("typ: TOP albo RECENT")
        limit = _opt_int(params, "limit", 1, 100) or 25
        base = f"meta_search_{slug(query)}_{stamp}"
        args = ["threads-search", "--type", stype, "--limit", str(limit)]
        author = _text(params, "author").strip().lstrip("@")
        if author:
            if not re.fullmatch(r"[A-Za-z0-9._]{1,30}", author):
                raise ValueError("autor: nick Threads")
            args += ["--author", author]
        args += ["--json", str(OUT / f"{base}.json"), "--html", str(OUT / f"{base}.html"), "--", query]
        return "meta", args, f"{base}.html"
    name = _meta_nick(params)
    base = f"meta_{op}_{slug(name)}_{stamp}"
    sub = {"threads_profile": ["threads-profile"], "links": ["links"],
           "instagram_profile": ["instagram-profile", "--media", str(_opt_int(params, "media", 0, 50) or 0)]}[op]
    return "meta", [*sub, "--json", str(OUT / f"{base}.json"), "--html", str(OUT / f"{base}.html"), "--", name], f"{base}.html"


def meta_summary(report: str | None) -> dict | None:
    """Status z pliku JSON meta-search (obok raportu HTML): panel pokazuje wynik/brak/konfiguracje/uprawnienia."""
    if not report:
        return None
    f = OUT / (report[:-5] + ".json")
    try:
        data = json.loads(f.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    if not isinstance(data, dict) or data.get("tool") != "meta-search":
        return None
    if not isinstance(data.get("source"), dict) or not isinstance(data.get("items"), list):
        return None
    return {"status": str(data.get("status", "")), "label": str(data.get("status_label", "")),
            "source": str((data.get("source") or {}).get("kind", "")), "items": len(data.get("items") or [])}


MAX_PIVOTS = 25  # najwiecej podpowiedzi "Nastepny krok" w jednej odpowiedzi
DOMAIN_ACTIONS = ("dns", "harvester", "hibp_domain")
_PIVOT_LABELS = {"dns": "Audyt DNS", "harvester": "theHarvester", "hibp_domain": "HIBP"}
_HOSTNAME = re.compile(r"(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}")
_NICK = re.compile(r"[A-Za-z0-9._]{1,30}")


def _harvester_names(stdout: str) -> list[str]:
    """Hosty i domeny e-mail tylko z sekcji '[*] Hosts found' / '[*] Emails found' (do nastepnej linii '[*]').
    Linie bledow zrodel i adresy IP nie trafiaja do wyniku; z e-maila zostaje sama domena."""
    names, section = [], None
    for line in (stdout or "").splitlines():
        line = line.strip()
        if line.startswith("[*]"):
            section = ("hosts" if line.startswith("[*] Hosts found") else
                       "emails" if line.startswith("[*] Emails found") else None)
            continue
        if section == "emails":
            if "@" not in line:
                continue
            name = line.rsplit("@", 1)[1]
        elif section == "hosts":
            name = line.split(":", 1)[0]
        else:
            continue
        name = name.strip().lower().rstrip(".")
        if _HOSTNAME.fullmatch(name):
            names.append(name)
    return names


def pivots(action: str, params: dict, stdout: str) -> dict:
    """'Nastepny krok': kolejne sprawdzenia w zakresie celu. Telefon, zdjecia i pozostale akcje: brak podpowiedzi
    (bez wiazania numeru ani zdjecia z osoba). Hosty i domeny spoza celu trafiaja do poza_zakresem, bez przyciskow."""
    empty = {"pivots": [], "poza_zakresem": [], "obciete": 0}
    try:
        build_command(action, params)
        cands, outside = [], set()
        if action in DOMAIN_ACTIONS:
            domain = _text(params, "domain").strip().lower()
            cands = [(a, domain) for a in DOMAIN_ACTIONS if a != action]
            hosts = set()
            if action == "harvester":
                for name in _harvester_names(stdout):
                    if name == domain or name.endswith("." + domain):
                        hosts.add(name)
                    else:
                        outside.add(name)
            cands += [("dns", h) for h in sorted(hosts)]
            items = [{"action": a, "params": {"domain": d}, "label": f"{_PIVOT_LABELS[a]}: {d}"} for a, d in cands]
        elif action == "username":
            nick = _text(params, "username").strip()
            if not _NICK.fullmatch(nick):
                return empty
            items = [{"action": "meta", "params": {"op": "links", "username": nick},
                      "label": f"Meta: linki dla {nick}"}]
        else:
            return empty
        seen, result = set(), []
        for p in items:
            key = json.dumps([p["action"], p["params"]], sort_keys=True)
            if key in seen:
                continue
            build_command(p["action"], p["params"])
            seen.add(key)
            result.append(p)
    except ValueError:
        return empty
    return {"pivots": result[:MAX_PIVOTS], "poza_zakresem": sorted(outside),
            "obciete": max(0, len(result) - MAX_PIVOTS)}


def launch(tool: str, args: list[str]) -> tuple[list[str], dict[str, str]]:
    """Pelne polecenie (lista, bez powloki) i srodowisko podprocesu dla narzedzia."""
    if tool == "harvester":
        env = dict(os.environ, PYTHONUTF8="1", PYTHONIOENCODING="utf-8")
        env.pop("PYTHONPATH", None)
        env.pop(BRAVE_KEY_ENV, None)
        return [str(HARVESTER_PY), "-c", _HARVESTER_SCRIPT, *args, "-v"], env
    return tool_python(tool) + ["-m", TOOLS[tool][1], *args], tool_env(tool)


def find_scan_report(report: str) -> str:
    """Raport username-engine lezy w OUT/<id skanu>/<plik> (nazwa pliku ma znacznik czasu, wiec jest unikalna)."""
    hits = [f for f in OUT.glob(f"*/{report}") if f.is_file()]
    return f"{hits[0].parent.name}/{report}" if hits else report


def safe_report_path(name: str) -> Path | None:
    """Plik raportu w OUT: '<plik>.html' albo '<id skanu>/<plik>.html', bez '.', '..' i innych separatorow."""
    parts = name.split("/")
    if len(parts) == 3 and (parts[0], parts[2]) != ("sprawy", "report.html"):   # tylko raport sprawy
        return None
    if not 1 <= len(parts) <= 3 or not name.endswith(".html"):
        return None
    if any(not _SAFE_NAME.match(x) or x in (".", "..") for x in parts):
        return None
    f = OUT.joinpath(*parts)
    try:
        f.resolve().relative_to(OUT.resolve())
    except (ValueError, OSError):
        return None
    return f if f.is_file() else None


# Prefiksy nazw raportow od najdluzszego; mapa_ (exif) nie ma celu w nazwie.
_REPORT_PREFIXES = (("meta_threads_profile_", "meta"), ("meta_instagram_profile_", "meta"),
                    ("meta_facebook_page_", "meta"), ("meta_links_", "meta"), ("meta_search_", "meta"),
                    ("dns_", "dns"), ("un_", "username"))
_REPORT_STAMP = re.compile(r"^(?P<head>.*)_(?P<d>\d{8})-(?P<t>\d{6})(?:-[0-9a-f]{8})?\.html$")


def _stamp_date(d: str, t: str) -> str | None:
    try:
        return time.strftime("%Y-%m-%d %H:%M:%S", time.strptime(d + t, "%Y%m%d%H%M%S"))
    except ValueError:
        return None


def _parse_report_name(rel: str) -> tuple[str, str | None, str | None]:
    """(narzedzie, cel, data) z nazwy raportu '<prefiks><cel>_<YYYYMMDD-HHMMSS>[-<8 hex>].html'.
    Gdy nazwa nie ma znacznika czasu, data pochodzi z mtime pliku (None, gdy pliku nie ma)."""
    name = rel.rsplit("/", 1)[-1]
    tool, cel, date = "inne", None, None
    m = _REPORT_STAMP.match(name)
    if m:
        head, date = m.group("head"), _stamp_date(m.group("d"), m.group("t"))
        if date is not None:
            if head == "mapa":
                tool = "exif"
            else:
                for prefix, t in _REPORT_PREFIXES:
                    if head.startswith(prefix) and len(head) > len(prefix):
                        tool, cel = t, head[len(prefix):]
                        break
    if tool == "inne":
        cel = None
    if date is None:
        try:
            date = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(OUT.joinpath(*rel.split("/")).stat().st_mtime))
        except OSError:
            date = None
    return tool, cel, date


def list_reports(cel: str | None = None) -> dict:
    """Archiwum raportow w OUT (tez w podkatalogach skanow) i teczki celow. Filtr cel zaweza tylko 'raporty'."""
    out = OUT
    if not out.is_dir():
        return {"raporty": [], "cele": []}
    raporty = []
    for f in [*out.glob("*.html"), *out.glob("*/*.html")]:
        rel = f.relative_to(out).as_posix()
        path = safe_report_path(rel)
        if path is None:
            continue
        try:
            size = path.stat().st_size
        except OSError:
            continue
        tool, target, date = _parse_report_name(rel)
        raporty.append({"plik": f"/wyniki/{rel}", "narzedzie": tool, "cel": target, "data": date or "",
                        "rozmiar": size, "meta": meta_summary(rel) if tool == "meta" else None})
    raporty.sort(key=lambda x: x["plik"])
    raporty.sort(key=lambda x: x["data"], reverse=True)
    teczki: dict[str, dict] = {}
    for x in raporty:
        if x["cel"] is None:
            continue
        t = teczki.setdefault(x["cel"].lower(), {"cel": x["cel"].lower(), "narzedzia": set(), "liczba": 0,
                                                 "ostatni": ""})
        t["narzedzia"].add(x["narzedzie"])
        t["liczba"] += 1
        t["ostatni"] = max(t["ostatni"], x["data"])
    cele = sorted(({**t, "narzedzia": sorted(t["narzedzia"])} for t in teczki.values()),
                  key=lambda t: t["ostatni"], reverse=True)
    if cel:
        key = cel.strip().lower()
        raporty = [x for x in raporty if x["cel"] is not None and x["cel"].lower() == key]
    return {"raporty": raporty, "cele": cele}


def _read_live(path: Path) -> str:
    try:
        data = path.read_bytes()
    except OSError:
        return ""
    return data.decode("utf-8", "replace").replace("\r\n", "\n").strip()


def live_progress() -> dict:
    """Stan trwajacego dlugiego skanu: wyjscie dotad (trafienia) i ostatnia linia licznika postepu."""
    live = dict(_LIVE)
    if not live:
        return {"aktywny": False}
    err_lines = _read_live(live["err"]).splitlines()
    return {"aktywny": True, "narzedzie": live["tool"], "seconds": round(time.monotonic() - live["t0"]),
            "stdout": _read_live(live["out"])[-LIVE_MAX:], "postep": err_lines[-1].strip() if err_lines else ""}


# --- Metryczka wyniku: zrodlo, identyfikator, czas UTC, status, kanal, ograniczenia, skrot, decyzja operatora.
# Statusy (jak w zakladce Laboratorium): blad, blokada zrodla i wynik czesciowy NIGDY nie sa brakiem wyniku.

RESULT_STATUS = {"found": "znaleziono", "no_result": "brak wyniku", "error": "błąd",
                 "blocked": "blokada źródła", "partial": "wynik częściowy"}
SOURCE_INFO = {   # narzedzie -> (zrodlo, pole identyfikatora, ograniczenia interpretacji)
    "dns": ("dns-audit: rekordy DNS, MX, SPF, DKIM, DMARC, DNSSEC", "domain",
            "Stan rekordów w chwili zapytania; DKIM tylko dla podanych lub typowych selektorów."),
    "phone": ("phone-check: plan numeracyjny (offline)", "number",
              "Operator to pierwotny przydział (numer mógł być przeniesiony); bez lokalizacji i właściciela."),
    "hibp": ("Have I Been Pwned: publiczny katalog wycieków", "domain",
             "Tylko wycieki znane HIBP; brak wpisu nie dowodzi, że domena nie wyciekła."),
    "exif": ("exif-map: metadane plików operatora (lokalnie)", "path",
             "Metadane można zmienić lub usunąć; GPS to zapis aparatu, nie dowód obecności osoby."),
    "username": ("username-engine: WhatsMyName i archiwum Wayback", "username",
                 "Ta sama nazwa nie oznacza tej samej osoby; Wayback to ślad historyczny, nie dowód konta."),
    "harvester": ("theHarvester: źródła bez kluczy API", "domain",
                  "Źródła pasywne i niekompletne; nieudane źródło to wynik nieznany, nie brak."),
    "meta": ("meta-search: oficjalne API Meta lub link ręczny", "username",
             "Tylko dane publiczne zwracane przez API; brak w API nie dowodzi braku konta."),
}
ID_FIELDS = {"meta": ("username", "query", "page"), "exif": ("path",)}   # reszta: pole z SOURCE_INFO
_UE_SUMMARY = re.compile(r"znaleziono (\d+).*?brak (\d+), błędy (\d+)")
_UE_ARCHIVE = re.compile(r"Archiwum: (\d+) profili z zrzutami, (\d+) błędów archiwum")
_HARVEST_SOURCE = re.compile(r"status=(failed|rate-limited|partial|skipped)")
_HIBP_COUNT = re.compile(r"(?:lacznie|wyciekow zrodlowych:|Katalog HIBP:) (\d+)")


def classify(tool: str, code: int, out: str, err: str, meta: dict | None) -> tuple[str, str]:
    """Status wyniku z kodu wyjscia i znacznikow narzedzia -> (klucz statusu, uwaga)."""
    if code == -1:   # limit czasu panelu albo brak narzedzia: zachowane dotad wyjscie = wynik czesciowy
        return ("partial", "przerwano po limicie czasu; zachowano dotychczasowe wyniki") if out.strip() \
            else ("error", (err.strip().splitlines() or ["narzędzie nie odpowiedziało"])[-1])
    if tool == "username":
        if code == 3:
            return ("partial", "proxy przestało działać w trakcie skanu; raport częściowy, nie brak wyniku") \
                if "częściowy" in err else ("error", "proxy lub Tor niedostępne; skan nie wystartował (fail-closed)")
        if code == 2:
            return "error", "błąd konfiguracji skanu"
        if code not in (0, 1):
            return "error", f"narzędzie zakończyło się kodem {code}"
        totals = [tuple(int(x) for x in m) for m in _UE_SUMMARY.findall(out)]
        archive = [tuple(int(x) for x in m) for m in _UE_ARCHIVE.findall(out)]
        if not totals and not archive:
            return "error", "brak podsumowania skanu: wynik nieznany, nie brak wyniku"
        found, errors = sum(t[0] for t in totals), sum(t[2] for t in totals)
        hits, arch_err = sum(a[0] for a in archive), sum(a[1] for a in archive)
        note = "eksport raportu nie powiódł się" if code == 1 else ""
        if errors or arch_err:
            return "partial", f"{errors + arch_err} sprawdzeń z błędem lub blokadą (nie liczą się jako brak)"
        if found:
            return "found", note
        if hits:
            return "found", "tylko ślad historyczny w Wayback, nie dowód istnienia konta"
        return "no_result", note
    if tool == "dns":
        if code == 3:
            return "error", "proxy lub DoH niedostępne; audyt przerwany bez zapytań bezpośrednich"
        if code not in (0, 1):
            return "error", "błąd danych wejściowych lub resolvera"
        if "nie udało się sprawdzić" in out:
            return "partial", "część rekordów lub selektorów nie odpowiedziała (to nie brak rekordu)"
        return "found", "nie zapisano raportu HTML" if code == 1 else ""
    if tool == "phone":
        return {0: ("found", ""), 1: ("no_result", "numer niepoprawny w planie numeracyjnym")}.get(
            code, ("error", "błąd danych wejściowych"))
    if tool == "hibp":
        if code == 3:
            return ("blocked", "limit zapytań HIBP (429)") if "429" in err else ("error", "błąd sieci lub HTTP")
        if code != 0:
            return "error", "błąd konfiguracji lub danych"
        counts = [int(x) for x in _HIBP_COUNT.findall(out)]
        if not counts:
            return "error", "nieczytelny wynik HIBP: wynik nieznany"
        return ("found", "") if any(counts) else ("no_result", "")
    if tool == "exif":
        if code == 0:
            m = re.search(r"z bledem: (\d+)", out)
            return ("partial", f"{m.group(1)} plików z błędem odczytu") if m and m.group(1) != "0" else ("found", "")
        return {1: ("no_result", "brak obsługiwanych plików")}.get(code, ("error", "błąd odczytu lub --strip"))
    if tool == "harvester":
        if code != 0:
            return "error", "theHarvester zakończył się błędem"
        states = _HARVEST_SOURCE.findall(out + "\n" + err)
        has = bool(_harvester_names(out))
        if states and not has and set(states) == {"rate-limited"}:
            return "blocked", f"{len(states)} źródeł z limitem zapytań"
        if states:
            return "partial", f"{len(states)} źródeł nie odpowiedziało w pełni (to nie brak wyniku)"
        return ("found" if has else "no_result"), ""
    if tool == "meta":
        status = (meta or {}).get("status")
        mapping = {"found": "found", "no_result": "no_result", "not_configured": "blocked",
                   "rate_limited": "blocked", "manual": "partial"}
        return (mapping[status], "") if status in mapping else ("error", "brak czytelnego wyniku meta-search")
    return ("found", "") if code == 0 else ("error", f"kod {code}")


def envelope(tool: str, args: list[str], params: dict, code: int, out: str, err: str,
             report: str | None, meta: dict | None) -> dict:
    """Metryczka pokazywana przy wyniku. Skrot SHA-256 obejmuje wyjscie narzedzia i plik raportu."""
    source, field, limits = SOURCE_INFO[tool]
    status, note = classify(tool, code, out, err, meta)
    digest = hashlib.sha256(out.encode("utf-8", "replace"))
    if report and (OUT / report).is_file():
        digest.update((OUT / report).read_bytes())
    target = next((v for f in ID_FIELDS.get(tool, (field,)) if (v := _text(params, f).strip())), "")
    if tool == "hibp" and not target:
        target = "katalog HIBP"
    channel = ("Tor/proxy (fail-closed)" if "--proxy" in args else "bezpośrednio" if "--direct" in args or tool in
               ("hibp", "harvester", "meta") else "offline (bez sieci)")
    return {"zrodlo": source, "identyfikator": PureWindowsPath(target).name if tool == "exif" else target,
            "url": f"/wyniki/{report}" if report and (OUT / report).is_file() else "",
            "czas_utc": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "status": status, "status_label": RESULT_STATUS[status], "uwaga": note, "kanal": channel,
            "ograniczenia": limits, "sha256": digest.hexdigest(),
            "dowod": "raport HTML i wyjście narzędzia" if report else "wyjście narzędzia (tekst)",
            "decyzja": "brak — decyzję zapisuje operator w zakładce Sprawa"}


def run_tool(action: str, params: dict) -> dict:
    tool, args, report = build_command(action, params)
    stdin_text = material_text(action, params)
    OUT.mkdir(exist_ok=True)
    cmd, env = launch(tool, args)
    timeout = TIMEOUTS.get(tool, TIMEOUT)
    if tool == "username" and "--level" in args:
        timeout = USERNAME_TIMEOUTS[args[args.index("--level") + 1]]["proxy" if "--proxy" in args else "direct"]
    long = tool in LONG_TOOLS
    if not _PROC_SLOTS.acquire(blocking=False):
        raise Overloaded(f"Za duzo rownoczesnych zadan (limit {MAX_PROCS}). Sprobuj za chwile.")
    try:
        if long and not _LONG_LOCK.acquire(blocking=False):
            raise Busy("Trwa juz inny dlugi skan nazwy uzytkownika. Poczekaj na jego koniec.")
        live_dir = fo = fe = None
        try:
            t0 = time.monotonic()
            if long:   # wyjscie do plikow, zeby /api/postep pokazywal trafienia w trakcie skanu
                live_dir = Path(tempfile.mkdtemp(prefix="panel_live_"))
                fo, fe = open(live_dir / "out.txt", "wb"), open(live_dir / "err.txt", "wb")
                _LIVE.update(out=live_dir / "out.txt", err=live_dir / "err.txt", tool=tool, t0=t0)
                env = dict(env, PYTHONUNBUFFERED="1")
                kw = {"stdout": fo, "stderr": fe}
            else:
                kw = {"capture_output": True, "text": True, "encoding": "utf-8", "errors": "replace"}
            try:
                feed = {"stdin": subprocess.DEVNULL} if stdin_text is None else {"input": stdin_text}
                proc = subprocess.run(cmd, cwd=OUT, env=env, timeout=timeout, **feed, **kw)
                code, out, err = proc.returncode, proc.stdout or "", proc.stderr or ""
            except subprocess.TimeoutExpired:
                code, out, err = -1, "", f"Przekroczono limit czasu ({timeout} s)."
            except OSError as exc:
                code, out, err = -1, "", f"Nie mozna uruchomic narzedzia: {exc}"
            if live_dir is not None:   # czesciowe wyniki zostaja tez po przekroczeniu limitu czasu
                fo.close()
                fe.close()
                out = out or _read_live(_LIVE["out"])
                err = "\n".join(x for x in (_read_live(_LIVE["err"]), err) if x)
            if tool == "username" and report:
                report = find_scan_report(report)
        finally:
            if live_dir is not None:
                for fh in (fo, fe):
                    if fh is not None:
                        fh.close()
                _LIVE.clear()
                shutil.rmtree(live_dir, ignore_errors=True)
            if long:
                _LONG_LOCK.release()
    finally:
        _PROC_SLOTS.release()
    has_report = bool(report) and (OUT / report).exists()
    result = {"code": code, "stdout": out, "stderr": err, "seconds": round(time.monotonic() - t0, 2),
              "report": f"/wyniki/{report}" if has_report else None}
    if tool == "meta":
        result["meta"] = meta_summary(report)
    if tool in SOURCE_INFO and not (tool == "meta" and _text(params, "op").strip() == "config"):
        # kazdy wynik badania: zrodlo, czas UTC, status, ograniczenia, skrot, decyzja (config to nie wynik)
        result["metryczka"] = envelope(tool, args, params, code, out, err, report if has_report else None,
                                       result.get("meta"))
    if tool == "sprawa_profile":   # kod 3 = brak konfiguracji (klucz/proxy): nic nie wyslano, sprawa bez zmian
        result["konfiguracja"] = code != 3
    json_key = {"sprawa": "sprawa", "sprawa_asystent": "asystent", "sprawa_dziennik": "dziennik"}.get(action)
    if json_key and code == 0:   # widok sprawy, asystent i dziennik: JSON z entity_graph
        try:
            result[json_key], result["stdout"] = json.loads(out), ""
        except ValueError:
            result["stderr"] = (err + "\nnieczytelny wynik entity-graph").strip()
    result.update(pivots(action, params, out))
    return result


SCAN_TYPES = ("domena", "email", "login")


def _scan_domain(domain: str) -> str:
    """Regula domeny jak w akcji harvester."""
    if not re.fullmatch(r"[A-Za-z0-9]([A-Za-z0-9.-]*[A-Za-z0-9])?", domain) or ".." in domain:
        raise ValueError("nieprawidlowa domena")
    return domain


def plan_scan(cel, typ) -> list[tuple[str, dict]]:
    """Kroki zbiorczego skanu celu: lista (akcja, parametry) dla run_tool."""
    typ = str(typ or "").strip()
    if typ not in SCAN_TYPES:
        raise ValueError(f"nieznany typ celu: {typ or '-'} (dozwolone: {', '.join(SCAN_TYPES)})")
    cel = _req({"cel": "" if cel is None else cel}, "cel", 253)
    if typ == "domena":
        domain = _scan_domain(cel)
        return [("dns", {"domain": domain}), ("hibp_domain", {"domain": domain}), ("harvester", {"domain": domain})]
    if typ == "email":
        parts = cel.split("@")
        if len(parts) != 2 or not re.fullmatch(r"[A-Za-z0-9._%+-]{1,64}", parts[0]):
            raise ValueError("nieprawidlowy adres e-mail")
        domain = _scan_domain(parts[1])  # czesc lokalna nie trafia do zadnego narzedzia
        return [("dns", {"domain": domain}), ("hibp_domain", {"domain": domain})]
    name = cel.lstrip("@")
    if not re.fullmatch(r"[A-Za-z0-9._]{1,30}", name):
        raise ValueError("login: 1-30 znakow, litery, cyfry, '.', '_'")
    return [("username", {"username": name, "only": True}), ("meta", {"op": "links", "username": name})]


def run_scan(cel, typ) -> dict:
    """Wykonuje plan po kolei przez run_tool (wlasne limity czasu, semafor, blokada dlugich skanow).
    Blad jednego kroku nie przerywa skanu i nigdy nie jest wynikiem negatywnym."""
    plan = plan_scan(cel, typ)
    t0 = time.monotonic()
    kroki = []
    for action, params in plan:
        krok = {"akcja": action, "status": "", "code": None, "seconds": 0, "report": None,
                "stdout": "", "stderr": "", "blad": None}
        try:
            r = run_tool(action, params)
        except (Busy, Overloaded, ValueError) as exc:
            krok.update(status="pominieto", blad=str(exc))
        else:
            code = r["code"]
            krok.update(code=code, seconds=r.get("seconds", 0), report=r.get("report"),
                        stdout=r.get("stdout") or "", stderr=r.get("stderr") or "",
                        status="gotowe" if code == 0 else "uwagi" if code == 1 else "blad",
                        metryczka=r.get("metryczka"))
        kroki.append(krok)
    pods = {s: sum(k["status"] == s for k in kroki) for s in ("gotowe", "uwagi", "blad", "pominieto")}
    statuses = [(k.get("metryczka") or {}).get("status") for k in kroki]
    pods["statusy"] = {key: statuses.count(key) for key in RESULT_STATUS if statuses.count(key)}
    # pelny tylko gdy kazdy krok ma metryczke ze statusem rozstrzygnietym (znaleziono / brak wyniku)
    certain = all(st in ("found", "no_result") for st in statuses if st is not None)
    pods["wynik"] = "pelny" if pods["blad"] == 0 and pods["pominieto"] == 0 and certain else "niepelny"
    wynik = {"cel": str(cel).strip(), "typ": str(typ).strip(), "kroki": kroki, "podsumowanie": pods,
             "seconds": round(time.monotonic() - t0, 2), "code": 0 if pods["wynik"] == "pelny" else 1}
    wynik["report"] = write_scan_report(wynik)
    return wynik


def write_scan_report(wynik: dict) -> str:
    """Raport zbiorczy OUT/skan_<cel>_<stamp>.html; cala tresc przez html.escape. Zwraca '/wyniki/<plik>'."""
    e = html.escape
    stamp = time.strftime("%Y%m%d-%H%M%S") + "-" + secrets.token_hex(4)
    name = f"skan_{slug(wynik['cel'])}_{stamp}.html"
    pods = wynik["podsumowanie"]
    rows = []
    for k in wynik["kroki"]:
        link = f'<a href="{e(k["report"])}" target="_blank" rel="noopener">{e(k["report"])}</a>' if k["report"] else "-"
        m = k.get("metryczka") or {}
        rows.append(f"<tr><td>{e(k['akcja'])}</td><td>{e(m.get('status_label') or k['status'])}</td>"
                    f"<td>{e(m.get('zrodlo', '-'))}</td><td>{e(m.get('czas_utc', '-'))}</td>"
                    f"<td>{e(m.get('kanal', '-'))}</td><td><code>{e(m.get('sha256', '-'))}</code></td>"
                    f"<td>{e(str(k['code']))}</td><td>{e(str(k['seconds']))}</td><td>{link}</td></tr>")
    details = []
    for k in wynik["kroki"]:
        m = k.get("metryczka") or {}
        details.append(f"<h2>{e(k['akcja'])}: {e(m.get('status_label') or k['status'])}</h2>")
        if m:
            details.append(f"<p>Identyfikator: {e(m['identyfikator'] or '-')}. Uwaga: {e(m['uwaga'] or '-')}. "
                           f"Ograniczenia: {e(m['ograniczenia'])} Dowód: {e(m['dowod'])}. "
                           f"Decyzja operatora: {e(m['decyzja'])}.</p>")
        if k["blad"]:
            details.append(f"<p>{e(k['blad'])}</p>")
        if k["stdout"]:
            details.append(f"<pre>{e(k['stdout'])}</pre>")
        if k["stderr"]:
            details.append(f"<pre>{e(k['stderr'])}</pre>")
    body = (
        "<!doctype html>\n<html lang=\"pl\"><head><meta charset=\"utf-8\">"
        f"<title>Skan celu: {e(wynik['cel'])}</title>"
        "<style>body{font:14px/1.5 sans-serif;margin:20px}table{border-collapse:collapse}"
        "td,th{border:1px solid #ccc;padding:4px 8px}pre{background:#f0eee8;padding:8px;white-space:pre-wrap}</style>"
        "</head><body>"
        f"<h1>Skan celu: {e(wynik['cel'])} ({e(wynik['typ'])})</h1>"
        f"<p>Wynik: {e(pods['wynik'])}. Gotowe: {pods['gotowe']}, uwagi: {pods['uwagi']}, "
        f"blad: {pods['blad']}, pominieto: {pods['pominieto']}. Czas: {e(str(wynik['seconds']))} s.</p>"
        f"<p>Raport utworzono (UTC): {e(datetime.now(timezone.utc).isoformat(timespec='seconds'))}. "
        "Wynik pełny tylko wtedy, gdy każdy krok ma status znaleziono albo brak wyniku.</p>"
        "<table><tr><th>Krok</th><th>Status</th><th>Źródło</th><th>Czas UTC</th><th>Kanał</th><th>SHA-256</th>"
        "<th>Kod</th><th>Czas [s]</th><th>Raport</th></tr>"
        + "".join(rows) + "</table>" + "".join(details) + "</body></html>\n"
    )
    OUT.mkdir(exist_ok=True)
    (OUT / name).write_text(body, encoding="utf-8")
    return f"/wyniki/{name}"


_PW_SCRIPT = (
    "import sys, json\n"
    "from hibp_monitor.http import HttpClient, DEFAULT_USER_AGENT\n"
    "from hibp_monitor.passwords import check_password\n"
    "pw = sys.stdin.read()\n"
    "n = check_password(HttpClient(DEFAULT_USER_AGENT), pw)\n"
    "print(json.dumps({'count': n}))\n"
)


def _port_open(host: str, port: int, timeout: float = 0.3) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


def lab_environment() -> dict:
    """Brakujace zaleznosci i konfiguracja: obecnosc interpreterow, kanalu Tor, lokalnego AI i zmiennych
    srodowiska (tylko tak/nie). Nic nie wychodzi poza ten komputer."""
    deps = []
    for key in ("dns", "phone", "hibp", "exif", "username", "meta", "sprawa"):
        py = Path(tool_python(key)[0])
        own = py != Path(sys.executable) or (key == "username" and UE_PY.exists())
        deps.append({"name": TOOLS[key][0], "ok": py.exists(),
                     "note": "własne środowisko" if own else "Python systemowy: zależności muszą być zainstalowane"})
    deps.append({"name": "theHarvester", "ok": HARVESTER_PY.exists(),
                 "note": "narzedzia/theharvester-venv" if HARVESTER_PY.exists() else "brak środowiska theHarvester"})
    try:
        proxy = urllib.parse.urlsplit(PANEL_PROXY)
        host, port = proxy.hostname or "", proxy.port
    except ValueError:
        host, port = "", None
    if not port:
        tor_ok, note = False, "nieprawidłowy adres OSINT_PROXY"
    elif host not in ("127.0.0.1", "localhost", "::1"):
        tor_ok, note = False, "proxy poza tym komputerem: nie sprawdzano (diagnostyka nie łączy się na zewnątrz)"
    else:
        tor_ok = _port_open(host, port)
        note = "osiągalny" if tor_ok else "nieosiągalny: skany w trybie Tor nie wystartują (fail-closed)"
    deps.append({"name": "Kanał Tor/proxy", "ok": tor_ok, "note": note})
    ai_ok = _port_open(*OLLAMA_ADDR)
    deps.append({"name": "Lokalne AI (Ollama)", "ok": ai_ok,
                 "note": "127.0.0.1:11434 odpowiada" if ai_ok else "niedostępne: asystent działa tylko na regułach"})
    config = [{"name": name, "ok": bool(os.environ.get(name)), "note": note} for name, note in CONFIG_VARS]
    return {"dependencies": deps, "config": config,
            "config_note": "Stan zmiennych w środowisku panelu; narzędzia mogą czytać też własne pliki konfiguracji."}


def case_file(query: str) -> tuple[Path, str, str]:
    """Plik eksportu sprawy do pobrania: tylko GraphML albo CSV dla Maltego z katalogu wyniki/sprawy/<nazwa>."""
    q = urllib.parse.parse_qs(query)
    kind = (q.get("typ") or [""])[0]
    files = {"graphml": ("graph.graphml", "application/graphml+xml"), "maltego": ("maltego.csv", "text/csv")}
    if kind not in files:
        raise ValueError("typ: graphml albo maltego")
    name, folder = case_dir({"sprawa": (q.get("sprawa") or [""])[0]})
    fname, ctype = files[kind]
    path = folder / fname
    if not path.is_file() or path.is_symlink():
        raise ValueError("plik eksportu jeszcze nie powstal (zapisz zmiane w sprawie)")
    return path, f"{name}_{fname}", ctype


def check_password_proc(password: str) -> dict:
    """Haslo idzie do podprocesu przez stdin (nie w argumentach, nie w logach). Do sieci tylko prefiks SHA-1."""
    if not isinstance(password, str):
        raise BadField("pole password: oczekiwano tekstu")
    if not password or len(password) > 1000:
        raise ValueError("puste lub za dlugie haslo")
    if not _PROC_SLOTS.acquire(blocking=False):
        raise Overloaded(f"Za duzo rownoczesnych zadan (limit {MAX_PROCS}). Sprobuj za chwile.")
    try:
        proc = subprocess.run(tool_python("hibp") + ["-c", _PW_SCRIPT], input=password, env=tool_env("hibp"),
                              capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=60)
    finally:
        _PROC_SLOTS.release()
    if proc.returncode != 0:
        lines = proc.stderr.strip().splitlines()  # tylko ostatnia linia: bez tracebacku z lokalnymi zmiennymi
        return {"code": proc.returncode, "stdout": "", "stderr": lines[-1] if lines else "blad", "report": None}
    n = json.loads(proc.stdout)["count"]
    msg = (f"UWAGA: to haslo wystapilo w wyciekach {n:,} razy. Nie uzywaj go.".replace(",", " ") if n else
           "Haslo nie wystepuje w znanych wyciekach Pwned Passwords (to nie dowod, ze jest silne).")
    meta = {"zrodlo": "Have I Been Pwned: Pwned Passwords (k-anonimowość)", "identyfikator": "hasło (niezapisywane)",
            "url": "", "czas_utc": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "status": "found" if n else "no_result", "status_label": RESULT_STATUS["found" if n else "no_result"],
            "uwaga": "", "kanal": "bezpośrednio (do sieci tylko 5 znaków skrótu SHA-1)",
            "ograniczenia": "Brak w bazie nie oznacza, że hasło jest silne ani że nie wyciekło gdzie indziej.",
            "sha256": hashlib.sha256(msg.encode("utf-8")).hexdigest(), "dowod": "komunikat wyniku (bez hasła)",
            "decyzja": "brak — decyzję podejmuje operator"}
    return {"code": 0, "stdout": msg, "stderr": "", "report": None, "pwned": n > 0, "metryczka": meta}


class Handler(BaseHTTPRequestHandler):
    server_version = "OsintPanel/0.1"

    def log_message(self, fmt, *args):  # bez logowania tresci zapytan
        sys.stderr.write(f"[panel] {self.command} {self.path.split('?')[0]}\n")

    def _host_ok(self) -> bool:
        host = (self.headers.get("Host") or "").split(":")[0]
        return host in ("127.0.0.1", "localhost")

    def _send(self, status: int, body: bytes, ctype: str, extra: dict | None = None,
              csp: str | None = _CSP_API) -> None:
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Cache-Control", "no-store")
        if csp is not None:
            self.send_header("Content-Security-Policy", csp)
        for key, val in (extra or {}).items():
            self.send_header(key, val)
        self.end_headers()
        self.wfile.write(body)

    def send_error(self, code, message=None, explain=None):  # noqa: ARG002 - zgodnosc z BaseHTTPRequestHandler
        self.log_error("%s", message or code)
        self.close_connection = True
        text = message or (self.responses.get(code, ("blad",))[0])
        self._send(code, text.encode("utf-8"), "text/plain; charset=utf-8")

    def _json(self, status: int, obj: dict, extra: dict | None = None) -> None:
        self._send(status, json.dumps(obj, ensure_ascii=False).encode("utf-8"), "application/json; charset=utf-8",
                   extra)

    def do_GET(self):
        if not self._host_ok():
            return self._send(403, b"forbidden", "text/plain")
        path = self.path.split("?")[0]
        if path == "/":
            nonce = secrets.token_urlsafe(16)
            html = (PANEL / "index.html").read_text(encoding="utf-8")                 .replace("__TOKEN__", TOKEN).replace("__NONCE__", nonce)
            csp = (f"default-src 'none'; script-src 'nonce-{nonce}'; style-src 'unsafe-inline'; "
                   "connect-src 'self'; frame-src 'self'; base-uri 'none'; form-action 'none'; "
                   "frame-ancestors 'none'")
            return self._send(200, html.encode("utf-8"), "text/html; charset=utf-8", csp=csp)
        if path == "/api/raporty":  # lista celow to dane wrazliwe: wymaga tokenu jak POST
            if not secrets.compare_digest(self.headers.get("X-Panel-Token", ""), TOKEN):
                return self._json(403, {"error": "brak dostepu"})
            query = urllib.parse.parse_qs(urllib.parse.urlsplit(self.path).query)
            return self._json(200, list_reports((query.get("cel") or [None])[0]))
        if path == "/api/sprawy":  # nazwy spraw to dane wrazliwe: wymaga tokenu
            if not secrets.compare_digest(self.headers.get("X-Panel-Token", ""), TOKEN):
                return self._json(403, {"error": "brak dostepu"})
            return self._json(200, {"sprawy": list_cases()})
        if path == "/api/postep":  # trafienia trwajacego skanu to dane wrazliwe: wymaga tokenu
            if not secrets.compare_digest(self.headers.get("X-Panel-Token", ""), TOKEN):
                return self._json(403, {"error": "brak dostepu"})
            return self._json(200, live_progress())
        if path == "/api/lab":  # status laboratorium jest lokalny i wymaga tokenu panelu
            if not secrets.compare_digest(self.headers.get("X-Panel-Token", ""), TOKEN):
                return self._json(403, {"error": "brak dostepu"})
            return self._json(200, {**LAB_STATUS, "environment": lab_environment()})
        if path == "/api/sprawa_plik":  # eksport sprawy (GraphML / CSV Maltego): dane sprawy, wymaga tokenu
            if not secrets.compare_digest(self.headers.get("X-Panel-Token", ""), TOKEN):
                return self._json(403, {"error": "brak dostepu"})
            try:
                f, download, ctype = case_file(urllib.parse.urlsplit(self.path).query)
            except ValueError as exc:
                return self._json(400, {"error": str(exc)})
            return self._send(200, f.read_bytes(), ctype + "; charset=utf-8",
                              extra={"Content-Disposition": f'attachment; filename="{download}"'})
        if path.startswith("/wyniki/"):
            name = path[len("/wyniki/"):]
            f = safe_report_path(name)
            if f is not None:
                csp = "sandbox allow-scripts allow-popups allow-popups-to-escape-sandbox"
                if not f.name.startswith("mapa_"):
                    # raporty bez skryptow i zasobow zewnetrznych: nic nie laduje sie z sieci przy otwarciu
                    # (mapa EXIF potrzebuje Leaflet i kafelkow; ostrzega o tym wlasny baner)
                    csp = "default-src 'none'; style-src 'unsafe-inline'; img-src data:; " + csp
                return self._send(200, f.read_bytes(), "text/html; charset=utf-8",
                                  extra={"Content-Security-Policy": csp}, csp=None)
        return self._send(404, b"not found", "text/plain")

    def do_POST(self):
        if not self._host_ok() or not secrets.compare_digest(self.headers.get("X-Panel-Token", ""), TOKEN):
            return self._json(403, {"error": "brak dostepu"})
        try:
            length = int(self.headers.get("Content-Length", "0"))
            action = self.path.strip("/").removeprefix("api/")
            limit = MAX_BODY_MATERIAL if action == "sprawa_profile_material" else MAX_BODY
            if length < 0 or length > limit:
                raise ValueError("za duze zapytanie")
            try:
                data = json.loads(self.rfile.read(length) or b"{}")
            except RecursionError:
                raise ValueError("zbyt gleboko zagniezdzony JSON") from None
            if not isinstance(data, dict):   # [], null, tekst, liczba: nie startujemy narzedzia
                raise ValueError("dokument JSON zapytania musi byc obiektem {...}")
            if action == "hibp_password":
                return self._json(200, check_password_proc(_text(data, "password")))
            if action == "skan_celu":
                return self._json(200, run_scan(_text(data, "cel"), _text(data, "typ")))
            return self._json(200, run_tool(action, data))
        except BadField as exc:
            return self._json(422, {"error": str(exc)})
        except ValueError as exc:
            return self._json(400, {"error": str(exc)})
        except Busy as exc:
            return self._json(409, {"error": str(exc), "busy": True})
        except Overloaded as exc:
            return self._json(429, {"error": str(exc), "busy": True, "overloaded": True}, {"Retry-After": "5"})
        except Exception as exc:  # noqa: BLE001 - panel ma pokazac blad, nie paść
            return self._json(500, {"error": f"{type(exc).__name__}: {exc}"})


def main() -> None:
    OUT.mkdir(exist_ok=True)
    srv = ThreadingHTTPServer((HOST, PORT), Handler)
    url = f"http://{HOST}:{PORT}/"
    print(f"Panel OSINT: {url}  (Ctrl+C konczy). Wyniki: {OUT}")
    if "--no-browser" not in sys.argv:
        webbrowser.open(url)
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
