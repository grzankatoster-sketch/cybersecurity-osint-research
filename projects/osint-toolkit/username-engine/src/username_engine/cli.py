"""python -m username_engine <nazwa> [opcje]"""
from __future__ import annotations

import argparse
import asyncio
import json
import os
import re
import sys
import time
from pathlib import Path

from . import retention
from .correlate import accounts_from, same_name_clusters, variant_links
from .geo import Gazetteer, aggregate, profile_evidence
from .dorks import build_queries, cdx_query_url, parse_cdx, search_links, wayback_targets
from .engine import CONTROL_MODES, PROXY_ABORT_AFTER, channel_counts, rescan_errors, scan, summarize
from .fsutil import atomic_write_text
from .health import filter_healthy, load_health_ex
from .http import PROXY_DOWN, Fetcher, preflight, proxy_label, validate_proxy
from .models import Result, Status, is_abort_placeholder
from .report import (ABORTED_NOTE, MANUAL_INSTRUCTION, PRESKIPPED_REASON, manual_entries, manual_summary,
                     render_html, write_csv)
from .sources import load_db, site_tags
from .variants import generate

DEFAULT_DB = Path(__file__).resolve().parents[2] / "data" / "sites.json"
DEFAULT_RESULTS = Path(__file__).resolve().parents[2] / "wyniki"
WAYBACK_TAGS = {"social", "photo", "video", "coding", "networking", "pl"}
VARIANT_TAGS = {"social", "photo", "video", "coding", "networking", "messaging", "gaming", "music", "blog", "pl"}
REMOVED_SITES = {"facebook", "instagram", "threads"}     # reguły Meta usunięte 2026-10-03 (UA robota podglądu linków)
RETRY_TIMEOUT = 60.0          # limit czasu rund ponownych (nowy obwód Tora bywa wolny)
EXIT_PROXY_DOWN = 3           # proxy niedostępne (przed skanem albo w jego trakcie): zero ruchu bezpośredniego
LEVELS = ("quick", "standard", "full")
PRIORITY_TAGS = {"social", "pl"}     # poziomy quick/standard: serwisy o tych tagach (+ tagi z --tags, suma)
MANUAL_TEXT_LIMIT = 50               # tyle pozycji „do ręcznego sprawdzenia” w terminalu; reszta w raporcie
SECONDS_PER_SITE = {"direct": 0.2, "proxy": 1.0}     # pomiar 04.10.2026: ~17 min bezpośrednio, ~82 min przez Tora (5142 serwisy)
SKIP_LABELS = {"dead": "martwe", "blocked": "zablokowane", "false_positive": "fałszywe trafienia"}


def retry_fetcher(proxy: str, strict_tls: bool) -> Fetcher:
    """Fetcher do rund ponownych (nowy obwód albo proxy zapasowe). Przez proxy NIGDY nie pobieramy bez weryfikacji
    TLS: wyjście proxy/Tora może podmienić certyfikat, a niższa pewność nie przywraca autentyczności odpowiedzi.
    Dlatego nie przekazujemy allow_insecure_retry — domyślnie False przez proxy."""
    return Fetcher(timeout=RETRY_TIMEOUT, strict_tls=strict_tls, proxy=proxy)


_CONTROL_CHARS = re.compile(r"[\x00-\x1f\x7f-\x9f]")
_QUOTED_OR_PAREN = re.compile(r' "[^"]*"| \([^)]*\)')


def safe_text(value) -> str:
    """Tekst z niezaufanego źródła (baza serwisów, profil, archiwum) do wypisania w terminalu: znaki sterujące
    (w tym ESC z sekwencjami terminala) zamieniamy na \\xNN."""
    return _CONTROL_CHARS.sub(lambda m: f"\\x{ord(m.group()):02x}", str(value))


def redact_values(reason: str) -> str:
    """Powód powiązania bez wartości z profilu (cytowanych w "..." i w nawiasach) - np. lokalizacji, nazwy, strony www."""
    return _QUOTED_OR_PAREN.sub("", reason)


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="username_engine", description="Wyszukiwanie kont po nazwie użytkownika.")
    p.add_argument("username", help='nazwa albo imię i nazwisko w cudzysłowie (z --variants), np. "Jan Kowalski"')
    p.add_argument("--db", default=str(DEFAULT_DB), help="baza serwisów (scripts/build_db.py)")
    p.add_argument("--tags", help="tylko serwisy z tymi tagami, np. social,pl")
    p.add_argument("--sites", help="tylko serwisy o tych nazwach (dokładnie, bez wielkości liter), "
                                   "np. GitHub,Reddit; filtr działa przed --limit")
    p.add_argument("--limit", type=int, help="tylko N pierwszych serwisów")
    p.add_argument("--level", choices=LEVELS, default="full",
                   help="poziom skanu: quick = szybki (tylko źródła pasywne: archiwum i dorki, zero zapytań do "
                        "serwisów), standard = serwisy priorytetowe (social, pl + --tags) z archiwum, "
                        "full = pełny (domyślnie: wszystkie sprawne serwisy)")
    p.add_argument("--control", choices=CONTROL_MODES, default="auto",
                   help="zapytanie kontrolne z losową nazwą: auto = tylko słabe reguły")
    p.add_argument("--timeout", type=float, default=15.0)
    p.add_argument("--min-confidence", type=float, default=0.6,
                   help="ukryj trafienia poniżej progu (0 = pokaż wszystkie)")
    p.add_argument("--all", action="store_true", help="pokaż też błędy i braki")
    p.add_argument("--strict-tls", action="store_true",
                   help="błąd certyfikatu TLS = ERROR (bez ponowienia bez weryfikacji; domyślnie ponawiamy "
                        "i oznaczamy wynik jako niezaufany z pewnością <= 0,6)")
    p.add_argument("--details", action="store_true",
                   help="w terminalu pokaż też surowe dane z profili (lokalizacja, narodowość, nazwy, strony www); "
                        "domyślnie tylko wnioski")
    n = p.add_argument_group("kanał sieciowy (OPSEC)")
    n.add_argument("--proxy", metavar="URL", default=None,
                   help="proxy SOCKS5 (socks5h://127.0.0.1:9050 = Tor; nazwy rozwiązuje proxy, zero lokalnego DNS); "
                        "domyślnie zmienna OSINT_PROXY. Awaria proxy przerywa skan, nigdy nie przełącza na ruch "
                        "bezpośredni")
    n.add_argument("--proxy-fallback", metavar="URL", default=None,
                   help="drugie proxy SOCKS5 (np. Mullvad) dla błędów, których nie naprawiło ponawianie przez "
                        "pierwsze; domyślnie zmienna OSINT_PROXY_FALLBACK")
    n.add_argument("--proxy-retries", type=int, default=2, metavar="N",
                   help="ile rund ponowienia błędów na nowym obwodzie proxy (domyślnie 2, 0 = bez ponawiania)")
    n.add_argument("--direct", action="store_true",
                   help="ruch bezpośredni, twoje IP widoczne dla serwisów: ignoruje OSINT_PROXY i "
                        "OSINT_PROXY_FALLBACK (wyklucza się z --proxy)")
    p.add_argument("--include-broken", action="store_true",
                   help="nie pomijaj serwisów oznaczonych w data/health.json jako martwe/zablokowane/fałszywe")
    g = p.add_argument_group("warianty nazwy")
    g.add_argument("--variants", action="store_true", help="(domyślnie włączone) skanuj też warianty nazwy")
    g.add_argument("--no-variants", action="store_true", help="skanuj tylko wpisaną nazwę")
    g.add_argument("--max-variants", type=int, default=6, help="ile nazw łącznie skanować (domyślnie 6)")
    g.add_argument("--years", help="dopiski liczbowe, np. 1990,90")
    g.add_argument("--leet", action="store_true", help="dodaj wariant leet (a->4, e->3...)")
    g.add_argument("--show-variants", action="store_true", help="tylko wypisz warianty i zakończ")
    o = p.add_argument_group("wyszukiwarki, archiwum, wyniki")
    o.add_argument("--dorks", action="store_true", help="wypisz linki do wyszukiwarek (dorki site:)")
    o.add_argument("--dorks-only",
                   action="store_true",
                   help="tylko przygotuj linki do publicznych wyszukiwarek; zero bazy, sieci i skanu serwisów")
    o.add_argument("--wayback", action="store_true",
                   help="sprawdź w archiwum profile, których dziś nie ma (usunięte konta)")
    o.add_argument("--wayback-limit", type=int, default=25)
    o.add_argument("--report", help="raport HTML: sama nazwa pliku, np. raport.html (trafia do katalogu skanu)")
    o.add_argument("--csv", help="wyniki do CSV (Excel): sama nazwa pliku, np. wyniki.csv")
    o.add_argument("--json", dest="json_out", help="pełne wyniki do JSON: sama nazwa pliku")
    r = p.add_argument_group("retencja raportów (usuwanie wygasłych: username_engine purge)")
    r.add_argument("--results-dir", default=str(DEFAULT_RESULTS),
                   help="katalog wyników; każdy skan z eksportem dostaje w nim podkatalog z manifestem")
    r.add_argument("--ttl-hours", type=float, default=retention.DEFAULT_TTL_HOURS,
                   help="ważność raportów w godzinach (domyślnie 12), po niej skan jest usuwany; "
                        "0 = bez wygasania (tylko jawnie)")
    return p


def build_purge_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="username_engine purge",
                                description="Usuwa wygasłe skany (raporty HTML/JSON/CSV) z katalogu wyników.")
    p.add_argument("--results-dir", default=str(DEFAULT_RESULTS), help="katalog wyników")
    p.add_argument("--dry-run", action="store_true", help="tylko policz, nic nie usuwaj")
    return p


def run_purge(results_dir: str, dry_run: bool = False, quiet: bool = False) -> dict:
    """Wygasłe skany z katalogu wyników; komunikat tylko gdy coś usunięto, pominięto albo się nie udało."""
    res = retention.purge_expired(results_dir, dry_run=dry_run)
    if dry_run:
        print(f"Do usunięcia (wygasłe skany): {res['would_delete']}.")
    elif res["deleted"] or not quiet:
        print(f"Usunięto {res['deleted']} wygasłych skanów ({res['files']} plików).")
    if res["skipped"]:
        print(f"Pominięto {res['skipped']} katalogów, które wyglądają na skany, ale nie spełniają warunków "
              "bezpiecznego usunięcia (dowiązanie, podkatalog, zły manifest).", file=sys.stderr)
    for err in res["errors"]:
        print(f"Nie udało się usunąć: {safe_text(err)} (zostanie ponowione).", file=sys.stderr)
    return res


def parse_site_names(raw: str | None) -> list[str]:
    """--sites -> lista nazw bez duplikatów (kolejność wpisania)."""
    if not raw:
        return []
    return list(dict.fromkeys(n.strip() for n in raw.split(",") if n.strip()))


def unknown_site_names(sites, names: list[str]) -> list[str]:
    known = {s.name.lower() for s in sites}
    return [n for n in names if n.lower() not in known]


def select_sites(sites, tags: str | None, limit: int | None, names: list[str] | None = None):
    if names:
        wanted = {n.lower() for n in names}
        sites = [s for s in sites if s.name.lower() in wanted]
    if tags:
        wanted = {t.strip().lower() for t in tags.split(",") if t.strip()}
        sites = [s for s in sites if wanted & {t.lower() for t in site_tags(s)}]
    return sites[:limit] if limit else sites


def resolve_network(args) -> tuple[str | None, str | None]:
    """(proxy, proxy zapasowe) z opcji i zmiennych OSINT_PROXY / OSINT_PROXY_FALLBACK. ValueError = zła konfiguracja
    (komunikat bez danych logowania). --direct ignoruje zmienne środowiskowe."""
    if args.direct:
        if args.proxy or args.proxy_fallback:
            raise ValueError("--direct wyklucza się z --proxy i --proxy-fallback")
        return None, None
    proxy = args.proxy or os.environ.get("OSINT_PROXY") or None
    fallback = args.proxy_fallback or os.environ.get("OSINT_PROXY_FALLBACK") or None
    for label, url in (("--proxy / OSINT_PROXY", proxy), ("--proxy-fallback / OSINT_PROXY_FALLBACK", fallback)):
        if url:
            try:
                validate_proxy(url)
            except ValueError as e:
                raise ValueError(f"{label}: {e}") from None
    if fallback and not proxy:
        raise ValueError("--proxy-fallback wymaga ustawionego --proxy (bez proxy nie ma kanału podstawowego)")
    if args.proxy_retries < 0:
        raise ValueError("--proxy-retries nie może być ujemne")
    return proxy, fallback


def check_channel(proxy: str | None, fallback: str | None) -> tuple[dict, int]:
    """Kontrola kanału przed skanem. Zwraca (opis kanału do raportu, kod wyjścia: 0 = można skanować).
    Fail-closed: proxy niedostępne = kod 3 i zero ruchu do celów."""
    if not proxy:
        print("Kanał: bezpośrednio (twoje IP widoczne dla serwisów)")
        return {"mode": "direct"}, 0
    pre = asyncio.run(preflight(proxy))
    if not pre.ok:
        print(f"Proxy niedostępne ({safe_text(pre.error)}) — skan przerwany, zero ruchu bezpośredniego.",
              file=sys.stderr)
        return {}, EXIT_PROXY_DOWN
    info = {"mode": "tor" if pre.is_tor else "proxy", "proxy_label": proxy_label(proxy),
            "exit_ip_masked": pre.exit_ip_masked, "is_tor": pre.is_tor}
    if pre.is_tor:
        print(f"Kanał: Tor (wyjście {pre.exit_ip_masked})")
    else:
        print(f"Kanał: proxy {proxy_label(proxy)} (wyjście {pre.exit_ip_masked})")
        print("Uwaga: to proxy nie jest wyjściem Tor (IsTor=false) — izolacja obwodów nie działa, ale kontynuuję.",
              file=sys.stderr)
    if fallback:
        fb = asyncio.run(preflight(fallback))
        if not fb.ok:
            print(f"Proxy zapasowe niedostępne ({safe_text(fb.error)}) — skan przerwany, zero ruchu bezpośredniego.",
                  file=sys.stderr)
            return {}, EXIT_PROXY_DOWN
        info.update(fallback_label=proxy_label(fallback), fallback_exit_ip_masked=fb.exit_ip_masked)
        print(f"Kanał zapasowy: proxy {proxy_label(fallback)} (wyjście {fb.exit_ip_masked})")
    return info, 0


def format_result(r: Result) -> str:
    site, reason = safe_text(r.site), safe_text(r.reason)
    if r.channel in ("proxy-retry", "fallback"):
        reason += f"; kanał: {r.channel}"
    if r.status is Status.FOUND:
        return f"[+] {r.confidence:.2f}  {site}: {safe_text(r.url)}  ({reason})"
    mark = {"NOT_FOUND": "[-]", "ERROR": "[!]", "UNSUPPORTED": "[~]"}[r.status.value]
    return f"{mark}       {site}: {reason}"


def names_to_scan(args) -> list[str]:
    """Wpisana nazwa (w oryginalnej pisowni) + warianty. Warianty domyślnie włączone (--no-variants wyłącza)."""
    if args.no_variants and not args.show_variants:
        return [args.username] if args.username.strip() else []
    years = [int(y) for y in args.years.split(",") if y.strip().isdigit()] if args.years else None
    variants = generate(args.username, years=years, leet=args.leet, limit=max(1, args.max_variants))
    typed = args.username.strip()
    if " " in typed or not variants:
        return variants                       # "Jan Kowalski" nie jest nazwą użytkownika — tylko warianty
    # wpisana pisownia pierwsza (część serwisów rozróżnia wielkość liter: RamblerDating), bez duplikatu małymi
    return [typed] + [v for v in variants if v != typed.lower()][: max(0, args.max_variants - 1)]


def variant_pool(sites: list, tags: str | None) -> list:
    """Serwisy dla wariantów: najlepsze reguły (własne + WhatsMyName) w głównych kategoriach — szybko (~1 min)."""
    if tags:
        return sites
    return [s for s in sites if s.source == "custom" or
            (s.source == "wmn" and VARIANT_TAGS & {t.lower() for t in s.tags})]


WAYBACK_PROXY_TIMEOUT = 60.0   # archive.org przez Tora: 30-40 s na zapytanie (pomiar 05.10.2026), domyślne 15 s = timeout
WAYBACK_ATTEMPTS = 3           # 503 / timeout przez Tora: kolejna próba na nowym obwodzie
WAYBACK_BACKOFF = 5.0


async def check_wayback(fetcher: Fetcher, urls: list[str], fresh=None) -> dict[str, list | str]:
    """Zrzuty CDX dla adresów profili. `fresh` (fabryka Fetchera, tylko przez proxy): każde zapytanie na nowym
    obwodzie z dłuższym limitem i ponowieniami — archive.org dławi pojedyncze wyjścia Tora (503)."""
    sem = asyncio.Semaphore(3)

    async def via_fresh(query: str):
        resp = None
        for attempt in range(WAYBACK_ATTEMPTS):
            if attempt:
                await asyncio.sleep(WAYBACK_BACKOFF * attempt)
            async with fresh() as f:
                resp = await f.fetch("GET", query)
            if resp.status == 200 or (resp.error or "").startswith(PROXY_DOWN):
                break
        return resp

    async def one(url: str):
        try:
            query = cdx_query_url(url)
        except ValueError:
            return url, "błąd archiwum: niepoprawny adres profilu"
        async with sem:
            resp = await (via_fresh(query) if fresh else fetcher.fetch("GET", query))
        if resp.status != 200:
            return url, f"błąd archiwum: {resp.error or resp.status}"
        try:
            return url, parse_cdx(resp.text)
        except ValueError:
            return url, "błąd archiwum: niepoprawna odpowiedź"

    return dict(await asyncio.gather(*(one(u) for u in urls)))


def main(argv: list[str] | None = None) -> int:
    # wyjście przekierowane do pliku na Windows ma kodowanie cp1250: znaki spoza niego (↔, ≥, nazwy z profili)
    # wywracały skan UnicodeEncodeError po kilku minutach pracy (pomiar 03.10.2026)
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")
        except (AttributeError, ValueError):
            pass
    argv = sys.argv[1:] if argv is None else list(argv)
    if argv and argv[0] == "purge":         # nazwę "purge" można zeskanować przez: -- purge
        pargs = build_purge_parser().parse_args(argv[1:])
        res = run_purge(pargs.results_dir, pargs.dry_run)
        return 1 if res["errors"] else 0
    args = build_parser().parse_args(argv)
    names = names_to_scan(args)
    if not names:
        print("Z podanej nazwy nie da się zbudować poprawnej nazwy użytkownika.", file=sys.stderr)
        return 2
    if args.show_variants:
        print("\n".join(names))
        return 0
    if args.dorks_only:
        links = search_links(build_queries(names))
        print("Wyszukiwarki (otwórz ręcznie; nie pobieramy wyników automatycznie):")
        for item in links:
            print(f"[{item['engine']}] {safe_text(item['query'])}\n    {safe_text(item['url'])}")
        return 0
    try:
        ttl_hours = retention.parse_ttl_hours(args.ttl_hours)
        outputs = {key: retention.safe_output_name(getattr(args, key)) for key in ("report", "csv", "json_out")
                   if getattr(args, key) is not None}
        if len({n.lower() for n in outputs.values()}) < len(outputs):
            raise ValueError("--report, --csv i --json muszą mieć różne nazwy plików")
    except ValueError as e:
        print(f"Błąd opcji: {safe_text(e)}", file=sys.stderr)
        return 2
    try:
        proxy, fallback = resolve_network(args)
    except ValueError as e:
        print(f"Błąd opcji: {safe_text(e)}", file=sys.stderr)
        return 2
    try:
        run_purge(args.results_dir, quiet=True)      # na starcie każdego skanu; błąd sprzątania nie blokuje skanu
    except Exception as e:
        print(f"Uwaga: usuwanie wygasłych skanów nie powiodło się ({type(e).__name__}).", file=sys.stderr)
    try:
        all_sites = load_db(args.db)
    except (OSError, ValueError) as e:
        print(f"Nie można wczytać bazy: {e}\nZbuduj ją: python scripts/build_db.py", file=sys.stderr)
        return 2
    site_names = parse_site_names(args.sites)
    unknown = unknown_site_names(all_sites, site_names)
    if unknown:
        print(f"Nieznane serwisy w --sites: {', '.join(safe_text(n) for n in unknown)} "
              "(nazwy jak w bazie, np. GitHub,Reddit).", file=sys.stderr)
        if any(n.lower() in REMOVED_SITES for n in unknown):
            print("Reguły Facebook, Instagram i Threads zostały usunięte (opierały się na podszywaniu się pod "
                  "robota podglądu linków, czego nie robimy). Sprawdź te profile ręcznie w przeglądarce; linki do "
                  "wyszukiwarek: --dorks.", file=sys.stderr)
        return 2
    blocked_sites = []
    if not args.include_broken:
        try:
            health, stale = load_health_ex(Path(args.db).with_name("health.json"))
        except (OSError, ValueError) as e:
            health, stale = {}, 0
            print(f"Uwaga: nie można wczytać kontroli stanu bazy ({type(e).__name__}) - pomijam ją.", file=sys.stderr)
        if stale:
            print(f"Pominięto {stale} wpisów kontroli stanu bazy starszych niż 30 dni (odśwież: ue-zdrowie).")
        blocked_sites = [s for s in all_sites if health.get(s.name, {}).get("state") == "blocked"]
        all_sites, skipped = filter_healthy(all_sites, health)
        if skipped:
            print(f"Pominięto {sum(skipped.values())} niesprawnych serwisów wg kontroli bazy ("
                  + ", ".join(f"{SKIP_LABELS.get(k, k)}: {v}" for k, v in skipped.most_common())
                  + "). Wszystkie: --include-broken\n")
        elif not health:
            print("Brak kontroli stanu bazy — skan obejmie też martwe wpisy. Uruchom: ue-zdrowie\n")
    level = args.level
    eff_tags = args.tags      # quick/standard: priorytet = PRIORITY_TAGS + --tags (suma, nie przecięcie)
    if level != "full":
        eff_tags = ",".join(sorted(PRIORITY_TAGS | {t.strip().lower() for t in (args.tags or "").split(",") if t.strip()}))
    sites = select_sites(all_sites, eff_tags, args.limit, site_names)
    if site_names:
        chosen = {s.name.lower() for s in sites}
        dropped = [n for n in site_names if n.lower() not in chosen]
        if dropped:
            print(f"Wybrane serwisy pominięte (kontrola bazy, --level, --tags albo --limit): "
                  f"{', '.join(safe_text(n) for n in dropped)}. Niesprawne mimo to: --include-broken\n")
    if not sites:
        print("Brak serwisów po filtrach.", file=sys.stderr)
        return 2
    # warianty (poza pierwszą nazwą) tylko na głównych kategoriach, chyba że podano --tags
    variant_sites = variant_pool(sites, args.tags or args.sites)  # --sites: warianty na tych samych serwisach
    if len(names) > 1 and level != "quick":
        print(f"Skanuję {len(names)} nazw: {', '.join(names)}\n  {names[0]}: {len(sites)} serwisów, "
              f"warianty: po {len(variant_sites)} serwisów (najlepsze reguły; wyłącz: --no-variants)\n")

    channel_info, code = check_channel(proxy, fallback)      # przed JAKIMKOLWIEK ruchem do celów
    if code:
        return code
    if proxy:
        print(f"Przez proxy: nazwy rozwiązuje proxy, błędy sieci ponawiam do {args.proxy_retries}x na nowym obwodzie"
              + (", potem przez proxy zapasowe." if fallback else "."))

    if level != "full":
        print(_level_line(level, len(sites), eff_tags, bool(proxy), args.wayback_limit))
    scan_dir = None
    if outputs:
        try:
            scan_dir = retention.start_scan(args.results_dir, ttl_hours)
        except OSError as e:
            print(f"Nie można utworzyć katalogu skanu w {safe_text(args.results_dir)}: {type(e).__name__}",
                  file=sys.stderr)
            return 2
        print(f"Katalog skanu: {scan_dir.path} ({retention.expiry_note(scan_dir.expires_at)})")
    out_path = {key: str(scan_dir.path / name) for key, name in outputs.items()} if scan_dir else {}

    scans: dict[str, list[Result]] = {}
    summaries: dict[str, dict] = {}
    wayback: dict[str, list | str] = {}
    state: dict = {"abort": None}      # {"name", "checked", "total"} gdy bezpiecznik zatrzymał skan (martwe proxy)
    do_wayback = args.wayback or level in ("quick", "standard")
    if level == "quick":
        args.dorks = True              # tryb pasywny: linki do wyszukiwarek zawsze

    def fresh():          # nowy obwód (Fetcher z nowym loginem izolacji SOCKS), dłuższy limit czasu
        return retry_fetcher(proxy, args.strict_tls)

    def wayback_fresh():  # archiwum przez Tora: nowy obwód na każde zapytanie, ponowienia robi check_wayback
        return Fetcher(timeout=WAYBACK_PROXY_TIMEOUT, retries=0, strict_tls=args.strict_tls, proxy=proxy)

    def fallback_fetcher():
        return retry_fetcher(fallback, args.strict_tls)

    def on_round(kind: str, n: int) -> None:
        where = "przez proxy zapasowe" if kind == "fallback" else "na nowym obwodzie"
        print(f"  ponawiam {n} błędów {where}...", flush=True)

    def on_recovered(r: Result) -> None:
        if r.status is Status.FOUND and r.confidence >= args.min_confidence and not args.all:
            print(format_result(r), flush=True)

    async def run():
        kw = {"proxy": proxy} if proxy else {}       # bez proxy: wywołanie jak dotąd
        async with Fetcher(timeout=args.timeout, strict_tls=args.strict_tls, **kw) as fetcher:
            for i, name in enumerate(names if level != "quick" else []):
                started = time.monotonic()
                pool = sites if i == 0 else variant_sites
                print(f"=== {name}: sprawdzam {len(pool)} serwisów...", flush=True)
                progress = Progress(len(pool), args.min_confidence, live_hits=not args.all)
                results = await scan(name, pool, fetcher, control=args.control, on_result=progress.update,
                                     channel="proxy" if proxy else "direct",
                                     abort_after=PROXY_ABORT_AFTER if proxy else None)
                progress.finish()
                if proxy:       # nigdy nie wracamy do ruchu bezpośredniego: tylko nowe obwody i proxy zapasowe
                    results = await rescan_errors(name, pool, results, fresh if args.proxy_retries else None,
                                                  fallback_fetcher if fallback else None, args.proxy_retries,
                                                  control=args.control, on_round=on_round,
                                                  on_recovered=on_recovered)
                scans[name], summaries[name] = results, summarize(results)
                summaries[name]["seconds"] = round(time.monotonic() - started)
                print_scan(name, results, summaries[name], args)
                if getattr(results, "aborted", False):      # proxy padło w trakcie: koniec skanu, bez Wayback i wariantów
                    state["abort"] = {"name": name, "total": len(pool),
                                      "checked": sum(1 for r in results if not is_abort_placeholder(r))}
                    break
            if level == "quick":
                scans[names[0]], summaries[names[0]] = [], {**summarize([]), "seconds": 0}
            if do_wayback and not state["abort"]:
                if level == "quick":
                    pool = sites                      # tryb pasywny: bez wcześniejszego skanu, całe zbiór priorytetowy
                else:
                    missing = {r.site for r in scans[names[0]] if r.status is not Status.FOUND}
                    pool = [s for s in sites if s.name in missing]
                urls = wayback_targets(pool, names[0], WAYBACK_TAGS, args.wayback_limit)
                print(f"\nArchiwum: sprawdzam {len(urls)} profili, których dziś nie ma..." if level != "quick" else
                      f"\nArchiwum: sprawdzam {len(urls)} profili (tryb pasywny, tylko Wayback CDX)...")
                wayback.update(await check_wayback(fetcher, urls, wayback_fresh if proxy else None))
                for url, snaps in wayback.items():
                    if isinstance(snaps, list) and snaps:
                        print(f"[A] {safe_text(url)}: " + ("ślad w archiwum (nie dowód istnienia konta): "
                                                           if level == "quick" else "")
                              + f"zrzuty {', '.join(safe_text(s.date) for s in snaps)}"
                              f"  -> {safe_text(snaps[0].archive_url)}")
                errs = sum(1 for v in wayback.values() if isinstance(v, str))
                hits = sum(1 for v in wayback.values() if isinstance(v, list) and v)
                print(f"Archiwum: {hits} profili z zrzutami, {errs} błędów archiwum.")

    asyncio.run(run())

    failures: list[str] = []
    try:
        if level == "quick":      # nic nie skanowano: analiza kraju i powiązań nie ma na czym pracować
            analysis = {"country": [], "profiles_with_data": 0, "variant_links": {}, "pairs": []}
        else:
            gaz = Gazetteer(Path(args.db).with_name("geo.json"))
            analysis = analyze(scans, names[0], {s.name: s for s in sites}, gaz, args.min_confidence)
    except Exception as e:      # analiza jest dodatkiem: jej błąd nie może odebrać użytkownikowi wyników i eksportów
        analysis = {"country": [], "profiles_with_data": 0, "variant_links": {}, "pairs": [],
                    "error": f"{type(e).__name__}: {e}"}
        print(f"Uwaga: analiza nie powiodła się ({safe_text(analysis['error'])}) - eksporty zostaną zapisane bez niej.",
              file=sys.stderr)
        failures.append("analiza")
    if level != "quick":
        print_analysis(analysis, args.details)
    channel_info["counts"] = channel_counts([r for rs in scans.values() for r in rs])

    extra_manual = [Result(s.name, s.profile_url(names[0]), Status.ERROR,
                           reason=PRESKIPPED_REASON)
                    for s in select_sites(blocked_sites, eff_tags, None, site_names)] if level != "quick" else []
    manual_pool = scans[names[0]] + extra_manual
    errs_manual, skipped_manual = manual_entries(manual_pool)
    abort = state["abort"]
    meta = {"level": level, "priority_tags": sorted(PRIORITY_TAGS),
            "tags_used": sorted(t for t in eff_tags.split(",") if t) if eff_tags else None,
            "sites_selected": len(sites),
            "sites_checked": sum(1 for rs in scans.values() for r in rs if not is_abort_placeholder(r)),
            "aborted": bool(abort), "abort": abort,
            "manual_check_count": len(errs_manual) + len(skipped_manual),
            "manual_check_aborted_count": len(skipped_manual)}

    links = search_links(build_queries(names))
    if args.dorks:
        print("\nWyszukiwarki (otwórz w przeglądarce):")
        for d in links:
            if d["engine"] == "google":
                print(f"  {safe_text(d['query'])}\n    {safe_text(d['url'])}")

    def export(label: str, path: str, write) -> None:
        """Każdy eksport osobno: błąd jednego (np. brak miejsca, zła ścieżka) nie blokuje pozostałych."""
        try:
            write()
            print(f"{label}: {Path(path).resolve()}")
        except Exception as e:
            print(f"Błąd eksportu {label} ({safe_text(path)}): {type(e).__name__}: {safe_text(e)}", file=sys.stderr)
            failures.append(label)

    print_manual_list(manual_pool, "report" in out_path)
    if "report" in out_path:
        export("Raport HTML", out_path["report"], lambda: atomic_write_text(
            out_path["report"],
            render_html(args.username, scans, summaries, links, wayback or None, args.min_confidence, analysis,
                        manual_extra=extra_manual, retention_note=retention.expiry_note(scan_dir.expires_at),
                        channel_info=channel_info, level=level, aborted=abort)))
    if "csv" in out_path:
        export("CSV", out_path["csv"], lambda: write_csv(out_path["csv"], scans))
    if "json_out" in out_path:
        export("JSON", out_path["json_out"], lambda: atomic_write_text(out_path["json_out"], json.dumps(
            {"query": args.username, "meta": meta, "channel": channel_info, "summaries": summaries,
             "analysis": analysis, "results": {n: [r.to_dict() for r in rs] for n, rs in scans.items()},
             "wayback": {u: ([{"date": sn.date, "url": sn.archive_url} for sn in v] if isinstance(v, list) else v)
                         for u, v in wayback.items()}},
            ensure_ascii=False, indent=1)))
    if scan_dir:
        try:
            retention.seal_scan(scan_dir)
        except Exception as e:
            print(f"Błąd zapisu manifestu skanu: {type(e).__name__}: {safe_text(e)}", file=sys.stderr)
            failures.append("manifest")
    if abort:
        phase = ("w trakcie ponowień błędów" if abort["checked"] >= abort["total"] else
                 f"w trakcie skanu (sprawdzono {abort['checked']} z {abort['total']} serwisów)")
        print(f"Proxy przestało działać {phase} — "
              "skan przerwany, zero ruchu bezpośredniego." + (" Raport częściowy zapisany." if scan_dir else ""),
              file=sys.stderr)
        return EXIT_PROXY_DOWN
    return 1 if failures else 0


def _level_line(level: str, n_sites: int, tags: str | None, via_proxy: bool, wayback_limit: int) -> str:
    """Jedna linia przed skanem: poziom, liczba serwisów i szacunek czasu (pomiar: 0,2 s/serwis bezpośrednio, 1 s przez proxy)."""
    shown = ", ".join((tags or "").split(","))
    if level == "quick":
        return (f"Poziom szybki: tylko źródła pasywne (zero zapytań do serwisów docelowych): archiwum Wayback dla "
                f"profili z {n_sites} serwisów priorytetowych (tagi: {shown}), do {wayback_limit} zapytań, plus linki dorków.")
    minutes = max(1, round(n_sites * SECONDS_PER_SITE["proxy" if via_proxy else "direct"] / 60))
    return (f"Poziom standard: {n_sites} serwisów priorytetowych (tagi: {shown}), szacunkowo ~{minutes} min "
            f"({'przez proxy' if via_proxy else 'bezpośrednio'}), potem archiwum Wayback (do {wayback_limit} zapytań).")


def print_manual_list(results: list[Result], has_report: bool, limit: int = MANUAL_TEXT_LIMIT) -> None:
    """„Do ręcznego sprawdzenia”: wszystkie ERROR z adresem profilu (w terminalu najwyżej `limit`, reszta w raporcie)."""
    errs, skipped = manual_entries(results)
    entries = errs + skipped
    if not entries:
        return
    print(f"\nDo ręcznego sprawdzenia ({manual_summary(results)}):\n  {MANUAL_INSTRUCTION}")
    for r in entries[:limit]:
        reason = ABORTED_NOTE if is_abort_placeholder(r) else r.reason
        print(f"  - {safe_text(r.site)}: {safe_text(r.url)} ({safe_text(reason)})")
    if len(entries) > limit:
        print(f"  ... i {len(entries) - limit} więcej " + ("w raporcie" if has_report else "(pełna lista: --report)"))


COUNTRY_NAMES = {"PL": "Polska", "DE": "Niemcy", "GB": "Wielka Brytania", "US": "USA", "UA": "Ukraina",
                 "RU": "Rosja", "CZ": "Czechy", "SK": "Słowacja", "FR": "Francja", "NL": "Holandia",
                 "IE": "Irlandia", "NO": "Norwegia", "SE": "Szwecja", "IT": "Włochy", "ES": "Hiszpania"}


def analyze(scans: dict[str, list[Result]], original: str, site_by_name: dict, gaz: Gazetteer,
            min_conf: float) -> dict:
    """Kraj (z profili nazwy wyjściowej + wariantów mocno z nią powiązanych), powiązania wariantów, pary kont."""
    links = variant_links(scans, original, gaz, min_conf) if len(scans) > 1 else {}
    # tylko warianty z mocnym powiązaniem (linki wzajemne); same pola kopiowalne nie przenoszą poszlak kraju
    trusted = {original} | {v for v, info in links.items() if info.get("level") == "mocne"}
    evidence = []
    profiles = 0
    for name in trusted:
        for r in scans.get(name, []):
            if r.status is Status.FOUND and r.confidence >= min_conf and not r.insecure:
                site = site_by_name.get(r.site)
                profiles += bool(r.profile)
                evidence += profile_evidence(r.site, r.url, r.profile, site.tags if site else [], gaz)
    return {
        "country": aggregate(evidence),
        "profiles_with_data": profiles,
        "variant_links": links,
        "pairs": same_name_clusters(accounts_from(scans, min_conf), gaz),
    }


def level_text(info: dict) -> str:
    """Poziom dowodów zamiast procentu (ocena nie jest prawdopodobieństwem)."""
    level = info.get("level") or "brak"
    return level + (", tylko pola kopiowalne" if info.get("copy_only") else "")


def print_analysis(a: dict, details: bool = False) -> None:
    """Wnioski z analizy. Surowe dane osobowe z profili (lokalizacja, narodowość, nazwy, strony www) trafiają do
    stdout tylko z --details (logi CI i harmonogramów bywają współdzielone); raport HTML/JSON i tak je zawiera."""
    print("--- Analiza")
    if a.get("error"):
        print(f"Analiza niedostępna: {safe_text(a['error'])}")
    if a["country"]:
        for c in a["country"]:
            name = COUNTRY_NAMES.get(c["country"], c["country"])
            print(f"Kraj: {name} ({safe_text(c['country'])}) {c['percent']}% głosów, siła dowodów: {c['strength']}")
            notes = c["evidence"] if details else c.get("evidence_public", [])
            for e in notes[:4]:
                print(f"    - {safe_text(e)}")
            hidden = len(c["evidence"]) - len(c.get("evidence_public", c["evidence"]))
            if hidden > 0 and not details:
                print(f"    - (+{hidden} poszlak z danych profili ukryte w terminalu; pokaż: --details)")
    elif not a.get("error"):
        print(f"Kraj: brak poszlak (profile z danymi: {a['profiles_with_data']})")

    def why(reasons: list[str]) -> str:
        return "; ".join(safe_text(r if details else redact_values(r)) for r in reasons)

    if a["variant_links"]:
        print("Powiązanie wariantów z nazwą wyjściową:")
        for v, info in a["variant_links"].items():
            if info["score"] is None:
                print(f"    {safe_text(v)}: {safe_text(info['reasons'][0])}")
            else:
                print(f"    {safe_text(v)}: dowody {level_text(info)} ({info['accounts']} kont)"
                      + (f" — {safe_text(info['pair'])}: {why(info['reasons'])}" if info["pair"] else
                         f" — {safe_text(info['reasons'][0])}"))
    for p in a["pairs"][:5]:
        print(f"Możliwe powiązanie kont (dowody {level_text(p)}): {safe_text(p['a'])} ↔ {safe_text(p['b'])} — "
              + why(p["reasons"]))
    print("Uwaga: kraj i powiązania to wnioski z poszlak, nie fakty.\n")


def _enable_vt() -> None:
    """Włącza sekwencje ANSI w konsoli Windows (czyszczenie linii licznika)."""
    if sys.platform != "win32":
        return
    try:
        import ctypes
        k = ctypes.windll.kernel32
        h = k.GetStdHandle(-12)  # STD_ERROR_HANDLE
        mode = ctypes.c_uint32()
        if k.GetConsoleMode(h, ctypes.byref(mode)):
            k.SetConsoleMode(h, mode.value | 0x0004)  # ENABLE_VIRTUAL_TERMINAL_PROCESSING
    except Exception:
        pass


class Progress:
    """Licznik postępu w jednej linii (stderr) + trafienia wypisywane od razu, gdy przyjdą."""

    def __init__(self, total: int, min_conf: float, live_hits: bool = True, every: float = 0.25):
        self.total, self.min_conf, self.live_hits, self.every = total, min_conf, live_hits, every
        self.done = self.found = self.errors = 0
        self.started = self._last = time.monotonic()
        self.tty = sys.stderr.isatty()
        if self.tty:
            _enable_vt()

    def _line(self) -> str:
        pct = 100 * self.done // max(1, self.total)
        return (f"  [{self.done}/{self.total} {pct}%] znalezione: {self.found}  błędy: {self.errors}  "
                f"{time.monotonic() - self.started:.0f} s")

    def update(self, r: Result) -> None:
        self.done += 1
        hit = r.status is Status.FOUND and r.confidence >= self.min_conf
        self.found += hit
        self.errors += r.status is Status.ERROR
        if hit and self.live_hits:
            if self.tty:
                sys.stderr.write("\r\033[K")
            print(format_result(r), flush=True)
        now = time.monotonic()
        if self.tty and (hit or now - self._last >= self.every or self.done == self.total):
            sys.stderr.write("\r\033[K" + self._line())
            sys.stderr.flush()
            self._last = now
        elif not self.tty and (self.done % 100 == 0 or self.done == self.total):  # panel czyta to na zywo
            print(self._line(), file=sys.stderr, flush=True)

    def finish(self) -> None:
        if self.tty:
            sys.stderr.write("\r\033[K")
            sys.stderr.flush()


def print_scan(name: str, results: list[Result], s: dict, args) -> None:
    if args.all:  # pełna lista posortowana; zwykłe trafienia były już wypisane na żywo
        shown = sorted(results, key=lambda r: (r.status is not Status.FOUND, -r.confidence, r.site.lower()))
        for r in shown:
            print(format_result(r))
    hidden = sum(1 for r in results if r.status is Status.FOUND and r.confidence < args.min_confidence)
    print(f"Sprawdzono {s['checked']} serwisów w {s['seconds']} s: znaleziono {s['found']} "
          f"(pokazano ≥{args.min_confidence}: {s['found'] - hidden}), brak {s['not_found']}, "
          f"błędy {s['error']}, nieobsługiwane {s['unsupported']}.")
    if s["top_errors"]:
        print("Najczęstsze błędy: " + ", ".join(f"{safe_text(k)} ×{v}" for k, v in s["top_errors"]))
    print()


if __name__ == "__main__":
    raise SystemExit(main())
