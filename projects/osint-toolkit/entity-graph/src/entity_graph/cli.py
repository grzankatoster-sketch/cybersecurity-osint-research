"""CLI: python -m entity_graph run --purpose "..." --domain example.com [...]"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sys
import unicodedata
from datetime import datetime, timezone
from pathlib import Path

from . import __version__
from .engine import Options, investigate, new_graph
from .export import render_html, to_graphml, to_maltego_csv
from .guardrails import AuditLog, GuardrailError, current_operator, validate_purpose, verify_audit
from .http import HttpClient
from .kropki import render_svg
from . import asystent, kandydaci, profile_discovery, relacje, sprawa, teczka, telefon
from .model import Graph, Node, Status, write_atomic
from .polacz import connect_dots
from .importers import org_intel
from .importers.base import MAX_FILE_BYTES, ImportCtx
from .model import utc_now
from .normalize import EntityType
from .transforms import REGISTRY, Context, Settings
from .transforms.email import HIBP_ENV
from .transforms.phone import parse_phone_check, run_phone_check
from .vault import EvidenceVault, RecordingFetcher, verify_vault

EVIDENCE_DIR = "evidence"

SEED_FLAGS = {
    "ip": EntityType.IP, "domain": EntityType.DOMAIN, "email": EntityType.EMAIL, "username": EntityType.USERNAME,
    "person": EntityType.PERSON, "phone": EntityType.PHONE, "url": EntityType.URL,
}


def printable(text: object) -> str:
    """Znaki sterujące z cudzych danych -> widoczne \\xNN (ochrona terminala)."""
    return "".join(f"\\x{ord(c):02x}" if unicodedata.category(c) == "Cc" and c not in "\n\t" else c for c in str(text))


def _csv_set(raw: str) -> frozenset[str]:
    return frozenset(x.strip() for x in raw.split(",") if x.strip())


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="entity-graph",
        description="Graf powiązań OSINT dla zleconych, autoryzowanych badań (due diligence, audyt własnej "
                    "infrastruktury). Każde badanie wymaga --purpose i zapisuje dziennik audytu.")
    sub = p.add_subparsers(dest="cmd", required=True)

    r = sub.add_parser("run", help="uruchom badanie")
    r.add_argument("--purpose", required=True, help="WYMAGANE: cel i podstawa badania (trafia do dziennika audytu)")
    r.add_argument("--operator", help="kto prowadzi badanie (domyślnie użytkownik systemu)")
    r.add_argument("--case-ref", default="", help="sygnatura zlecenia/sprawy (opcjonalnie)")
    for flag in SEED_FLAGS:
        r.add_argument(f"--{flag}", action="append", default=[], metavar="WARTOSC",
                       help=f"zalążek: {flag} (można powtarzać)")
    r.add_argument("--depth", type=int, default=1, help="głębokość rozwijania odkrytych IP/domen (domyślnie 1)")
    r.add_argument("--out", help="katalog wyników (domyślnie ./eg-<data>); w nim graph.json, graph.graphml, report.html, audit.jsonl")
    r.add_argument("--only", default="", help="tylko te transformacje (po przecinku; lista: entity-graph transforms)")
    r.add_argument("--skip", default="", help="pomiń te transformacje (po przecinku)")
    r.add_argument("--offline", action="store_true", help="tylko transformacje bez sieci (osoba, e-mail->domena, telefon, URL)")
    r.add_argument("--max-usernames", type=int, default=12, help="limit kandydatów nazw użytkownika z imienia i nazwiska")
    r.add_argument("--max-subdomains", type=int, default=100, help="limit subdomen z crt.sh na domenę")
    r.add_argument("--max-nodes", type=int, default=500, help="twardy limit węzłów grafu")
    r.add_argument("--max-runs", type=int, default=200, help="twardy limit uruchomień transformacji")
    r.add_argument("--expand-subdomains", action="store_true", help="rozwijaj też subdomeny z crt.sh (dużo zapytań)")
    r.add_argument("--expand-candidates", action="store_true",
                   help="skanuj też WYGENEROWANYCH kandydatów nazw użytkownika (pełny skan każdego, wolno)")
    r.add_argument("--phone-region", default="PL", help="region numerów bez + (domyślnie PL)")
    r.add_argument("--ue-tags", help="username-engine: tylko te kategorie serwisów, np. social,pl")
    r.add_argument("--ue-limit", type=int, help="username-engine: tylko N pierwszych serwisów")
    r.add_argument("--ue-timeout", type=float, default=900.0, help="limit czasu skanu username-engine w sekundach")
    r.add_argument("--timeout", type=float, default=20.0, help="limit czasu pojedynczego zapytania HTTP")
    r.add_argument("--no-evidence", action="store_true",
                   help="nie zapisuj skarbca dowodów (surowych odpowiedzi źródeł w <out>/evidence)")

    j = sub.add_parser("polacz", help="połącz kropki: scal wyniki narzędzi siostrzanych (pliki/katalogi) w jeden graf (offline)")
    j.add_argument("--purpose", required=True, help="WYMAGANE: cel i podstawa badania (trafia do dziennika audytu)")
    j.add_argument("--operator", help="kto prowadzi badanie (domyślnie użytkownik systemu)")
    j.add_argument("--case-ref", default="", help="sygnatura zlecenia/sprawy (opcjonalnie)")
    j.add_argument("paths", nargs="+", metavar="PLIK_LUB_KATALOG",
                   help="pliki wynikowe (JSON/CSV/ULDK) albo katalogi z nimi; format wykrywany po zawartości")
    j.add_argument("--out", help="katalog wyników (domyślnie ./eg-<data>); w nim graph.json, graph.graphml, report.html, audit.jsonl")
    j.add_argument("--min-confidence", type=float, default=0.0,
                   help="username-engine: pomiń konta z pewnością poniżej progu (domyślnie 0 = bierz wszystkie jak w pliku)")

    e = sub.add_parser("export", help="wyeksportuj istniejący graph.json do GraphML, CSV dla Maltego i HTML")
    e.add_argument("graph", help="plik graph.json")
    e.add_argument("--graphml", help="plik wyjściowy GraphML")
    e.add_argument("--html", help="plik wyjściowy raportu HTML")
    e.add_argument("--maltego", help="plik wyjściowy CSV (Maltego: Import Graph from Table); istniejący plik: błąd")
    e.add_argument("--force", action="store_true", help="--maltego: nadpisz istniejący plik (domyślnie odmowa)")

    k = sub.add_parser("kropki", help="narysuj graph.json jako kropki i linie (statyczny SVG, offline)")
    k.add_argument("graph", help="plik graph.json")
    k.add_argument("--svg", help="plik wyjściowy (domyślnie kropki.svg obok graph.json)")
    k.add_argument("--max-nodes", type=int, default=200, help="najwyżej tyle węzłów (najbardziej połączone; domyślnie 200)")
    k.add_argument("--min-confidence", type=float, default=0.0, help="pomiń krawędzie o pewności poniżej progu")

    q = sub.add_parser("przeglad", help="teczka osoby: przejrzyj znalezione profile i potwierdź/odrzuć (interaktywnie)")
    q.add_argument("case", metavar="KATALOG", help="katalog badania (graph.json + audit.jsonl)")
    q.add_argument("--person", required=True, help="imię i nazwisko osoby z grafu")
    q.add_argument("--operator", help="kto podejmuje decyzje (domyślnie użytkownik systemu)")

    c = sub.add_parser("potwierdz", help="teczka osoby: potwierdź albo odrzuć jeden profil (bez interakcji)")
    c.add_argument("case", metavar="KATALOG", help="katalog badania (graph.json + audit.jsonl)")
    c.add_argument("--person", required=True, help="imię i nazwisko osoby z grafu")
    c.add_argument("--profil", required=True, help="adres URL profilu")
    c.add_argument("--dowod", required=True, help="WYMAGANE: dlaczego to (nie) ta osoba; trafia do dziennika audytu")
    c.add_argument("--odrzuc", action="store_true", help="odrzuć zamiast potwierdzić")
    c.add_argument("--dodaj", action="store_true", help="dodaj profil znaleziony ręcznie, jeśli nie ma go w grafie")
    c.add_argument("--operator", help="kto podejmuje decyzję (domyślnie użytkownik systemu)")

    x = sub.add_parser("rozszerz", help="rozszerzanie rekordów sterowane dowodami: rundy kandydatów z oceną i limitami")
    x.add_argument("identifier", metavar="IDENTYFIKATOR", help="identyfikator tekstowy (domyślnie nazwa użytkownika)")
    x.add_argument("--purpose", required=True, help="WYMAGANE: cel i podstawa badania (trafia do dziennika audytu)")
    x.add_argument("--operator", help="kto prowadzi badanie (domyślnie użytkownik systemu)")
    x.add_argument("--case-ref", default="", help="sygnatura zlecenia/sprawy (opcjonalnie)")
    x.add_argument("--type", default="username", choices=["username", "email", "domain", "url"],
                   help="rodzaj identyfikatora (domyślnie username)")
    x.add_argument("--profile", action="append", default=[], metavar="URL",
                   help="KOTWICA: profil, o którym wiadomo, że należy do badanego podmiotu (można powtarzać)")
    x.add_argument("--website", default="", help="dane początkowe: własna strona www podmiotu")
    x.add_argument("--email", action="append", default=[], help="dane początkowe: adres e-mail podmiotu")
    x.add_argument("--display-name", default="", help="dane początkowe: nazwa wyświetlana")
    x.add_argument("--entity-kind", default="", choices=["", "person", "organization"], help="dane początkowe: typ encji")
    x.add_argument("--adapters", default="username_scan", help="skonfigurowane adaptery (transformacje, po przecinku)")
    x.add_argument("--auto", action="store_true",
                   help="automatyczna kontynuacja: kolejne rundy z mocno uzasadnionych kandydatów "
                        "(bez niej: tylko runda 1 i lista propozycji)")
    x.add_argument("--max-rounds", type=int, default=2, help="limit głębokości (rund, domyślnie 2)")
    x.add_argument("--max-queries", type=int, default=10, help="limit zapytań do adapterów (domyślnie 10)")
    x.add_argument("--max-seconds", type=float, default=1800.0, help="limit czasu całości w sekundach (domyślnie 1800)")
    x.add_argument("--max-cost", type=float, default=50.0, help="limit kosztu w jednostkach (username_scan = 5, inne = 1)")
    x.add_argument("--max-candidates", type=int, default=50, help="limit ocenianych kandydatów na rundę")
    x.add_argument("--max-followups", type=int, default=5, help="limit nowych identyfikatorów z jednego kandydata")
    x.add_argument("--out", help="katalog wyników (domyślnie ./eg-<data>); plik STOP w nim zatrzymuje przebieg")
    x.add_argument("--offline", action="store_true", help="tylko adaptery bez sieci")
    x.add_argument("--ue-tags", help="username-engine: tylko te kategorie serwisów, np. social,pl")
    x.add_argument("--ue-limit", type=int, help="username-engine: tylko N pierwszych serwisów")
    x.add_argument("--ue-timeout", type=float, default=900.0, help="limit czasu skanu username-engine w sekundach")
    x.add_argument("--timeout", type=float, default=20.0, help="limit czasu pojedynczego zapytania HTTP")

    a = sub.add_parser("relacja", help="sprawa: zapisz twierdzenie operatora o relacji dwóch osób (wymaga potwierdzenia)")
    a.add_argument("case", metavar="KATALOG", help="katalog sprawy (graph.json + audit.jsonl)")
    a.add_argument("--person", required=True, help="pierwsza osoba z grafu")
    a.add_argument("--typ", required=True, choices=list(relacje.INPUT_KINDS),
                   help="pierwsza osoba jest: rodzic / dziecko drugiej; rodzenstwo; partner (małżonek lub partner); "
                        "inna (wymaga --opis)")
    a.add_argument("--druga-osoba", required=True, help="druga osoba z grafu")
    a.add_argument("--zrodlo", required=True,
                   help="WYMAGANE: publiczny adres http(s) albo dokument:ŚCIEŻKA pliku w katalogu sprawy")
    a.add_argument("--dowod", required=True, help="WYMAGANE: krótko, co źródło mówi o relacji")
    a.add_argument("--fragment", default="", help="krótki fragment lub notatka (do 300 znaków, nie cała treść)")
    a.add_argument("--opis", default="", help="opis relacji typu 'inna' (do 80 znaków)")
    a.add_argument("--dodaj", action="store_true", help="dopisz jawnie osobę, której nie ma w grafie")
    a.add_argument("--operator", help="kto zapisuje (domyślnie użytkownik systemu)")

    d = sub.add_parser("relacja-potwierdz", help="sprawa: potwierdź albo odrzuć twierdzenie o relacji (osobne uzasadnienie)")
    d.add_argument("case", metavar="KATALOG", help="katalog sprawy (graph.json + audit.jsonl)")
    d.add_argument("--id", required=True, help="identyfikator twierdzenia (r-...)")
    d.add_argument("--dowod", required=True, help="WYMAGANE: uzasadnienie decyzji, inne niż dowód twierdzenia")
    d.add_argument("--odrzuc", action="store_true", help="odrzuć zamiast potwierdzić")
    d.add_argument("--operator", help="kto podejmuje decyzję (domyślnie użytkownik systemu)")

    t = sub.add_parser("telefon", help="sprawa: kontekst numeru z planu numeracyjnego (phone-check, offline)")
    t.add_argument("case", metavar="KATALOG", help="katalog sprawy (graph.json + audit.jsonl)")
    t.add_argument("--numer", help="numer do sprawdzenia przez phone-check (offline)")
    t.add_argument("--plik", help="gotowy wynik phone-check (JSON) zamiast uruchamiania")
    t.add_argument("--region", default="PL", help="region numerów bez + (domyślnie PL)")
    t.add_argument("--operator-aktualny",
                   help="operator odczytany RĘCZNIE z oficjalnej weryfikacji (osobna obserwacja, wymaga --numer)")
    t.add_argument("--zrodlo", help="przy --operator-aktualny: adres http(s) albo dokument:ŚCIEŻKA w sprawie")
    t.add_argument("--data", help="przy --operator-aktualny: dzień weryfikacji RRRR-MM-DD")
    t.add_argument("--operator", help="kto zapisuje (domyślnie użytkownik systemu)")

    k = sub.add_parser("kandydaci", help="sprawa: jedna runda kandydatów profili (username-engine) w jawnym budżecie")
    k.add_argument("case", metavar="KATALOG", help="katalog sprawy (graph.json + audit.jsonl)")
    k.add_argument("--person", default="", help="punkt wejścia: osoba z grafu (jej kandydaci nazw użytkownika)")
    k.add_argument("--username", default="", help="punkt wejścia: nazwa użytkownika z grafu albo z propozycji rundy")
    k.add_argument("--nazwy", default="", help="tylko te nazwy spośród kandydatów osoby (po przecinku)")
    k.add_argument("--max-nazw", type=int, default=3, help=f"najwyżej tyle nazw w rundzie (1-{kandydaci.MAX_NAMES})")
    k.add_argument("--max-queries", type=int, default=3, help=f"limit wywołań username-engine (1-{kandydaci.MAX_QUERIES})")
    k.add_argument("--max-cost", type=float, default=15.0,
                   help=f"limit kosztu w jednostkach, username_scan = 5 (do {kandydaci.MAX_COST:g})")
    k.add_argument("--max-seconds", type=float, default=600.0, help=f"limit czasu rundy w s (do {kandydaci.MAX_SECONDS:g})")
    k.add_argument("--max-rounds", type=int, default=3, help=f"limit rund kandydatów w sprawie (1-{kandydaci.MAX_ROUNDS})")
    k.add_argument("--ue-tags", help="username-engine: tylko te kategorie serwisów, np. social,pl")
    k.add_argument("--ue-limit", type=int, help="username-engine: tylko N pierwszych serwisów (1-10000)")
    k.add_argument("--operator", help="kto uruchamia (domyślnie użytkownik systemu)")

    lim = profile_discovery.Limits()
    f = sub.add_parser("szukaj-profili",
                       help="sprawa: linki do możliwych profili po imieniu i nazwisku (Brave Search API, własny klucz)")
    f.add_argument("case", metavar="KATALOG", help="katalog sprawy (graph.json + audit.jsonl)")
    f.add_argument("--person", required=True, help="imię i nazwisko osoby z grafu (2-6 słów, same litery)")
    f.add_argument("--kontekst", default="", help="opcjonalnie: do 5 słów, np. miasto albo firma (dodatkowe zapytania)")
    f.add_argument("--dodaj", action="store_true", help="dopisz jawnie osobę, której nie ma w grafie")
    for flag, name, kind in (("--max-calls", "calls", int), ("--max-results", "results", int),
                             ("--max-candidates", "candidates", int), ("--max-seconds", "seconds", float)):
        lo, hi = profile_discovery.Limits.HARD[name]
        f.add_argument(flag, type=kind, default=getattr(lim, name),
                       help=f"limit (domyślnie {getattr(lim, name):g}, zakres {lo}-{hi})")
    f.add_argument("--operator", help="kto uruchamia (domyślnie użytkownik systemu)")

    m = sub.add_parser("material-profilu",
                       help="sprawa: kandydat z adresem i tekstem od operatora (analiza lokalna, bez sieci)")
    m.add_argument("case", metavar="KATALOG", help="katalog sprawy (graph.json + audit.jsonl)")
    m.add_argument("--person", required=True, help="imię i nazwisko osoby z grafu")
    m.add_argument("--url", required=True, help="adres źródła http(s), bez danych logowania")
    src = m.add_mutually_exclusive_group()
    src.add_argument("--tekst", default="", help="tekst skopiowany przez operatora (do 20 000 znaków)")
    src.add_argument("--tekst-stdin", action="store_true", help="tekst ze standardowego wejścia UTF-8 (używa go panel)")
    m.add_argument("--dodaj", action="store_true", help="dopisz jawnie osobę, której nie ma w grafie")
    m.add_argument("--operator", help="kto zapisuje (domyślnie użytkownik systemu)")

    s = sub.add_parser("sprawa", help="sprawa: osoby, telefony, twierdzenia i kandydaci jako JSON (bez zmian w sprawie)")
    s.add_argument("case", metavar="KATALOG", help="katalog sprawy (graph.json + audit.jsonl)")

    a = sub.add_parser("asystent", help="sprawa: porządek, sprzeczności i dozwolone kolejne kroki jako JSON "
                                        "(reguły; --ai = lokalny model przez Ollama, tylko 127.0.0.1)")
    a.add_argument("case", metavar="KATALOG", help="katalog sprawy (graph.json + audit.jsonl)")
    a.add_argument("--ai", action="store_true", help="uporządkuj wynik reguł lokalnym modelem (nie zmienia sprawy)")
    a.add_argument("--model", default=os.environ.get("EG_AI_MODEL", asystent.DEFAULT_MODEL), help="model Ollama")
    a.add_argument("--ai-url", default=os.environ.get("EG_AI_URL", asystent.DEFAULT_URL),
                   help="adres Ollama na tym komputerze (inne adresy są odrzucane)")
    a.add_argument("--operator", help="kto korzysta (wpis w dzienniku audytu przy --ai)")

    dz = sub.add_parser("dziennik", help="sprawa: dziennik audytu (spójność łańcucha i ostatnie wpisy) jako JSON")
    dz.add_argument("case", metavar="KATALOG", help="katalog sprawy (graph.json + audit.jsonl)")
    dz.add_argument("--limit", type=int, default=200, help="ile ostatnich wpisów (1-1000)")

    oi = sub.add_parser("import-org-intel",
                        help="sprawa: zaimportuj eksport JSON albo store.json pakietu org-intel (offline; osoby pomijane)")
    oi.add_argument("--input", required=True, metavar="PLIK.json", help="eksport `org-intel export --format json` albo store.json")
    oi.add_argument("--case", required=True, metavar="KATALOG", help="katalog sprawy (graph.json + audit.jsonl)")
    oi.add_argument("--dry-run", action="store_true", help="pokaż raport na kopii grafu: nic nie jest zapisywane")
    oi.add_argument("--operator", help="kto importuje (domyślnie użytkownik systemu)")
    oi.add_argument("--json", action="store_true", help="raport jako JSON (alias --format json)")
    oi.add_argument("--format", choices=["text", "json"], default=None, help="format raportu (domyślnie text)")
    oi.add_argument("--report", metavar="ŚCIEŻKA", help="zapisz też raport JSON do pliku (atomowo; bez danych osobowych)")
    oi.add_argument("--strict", action="store_true",
                    help="pierwsze odrzucenie (także nieznane pole rekordu) = odmowa: kod 5, nic nie zapisano, bez wpisu w dzienniku")

    sub.add_parser("transforms", help="lista dostępnych transformacji")

    v = sub.add_parser("audit-verify", help="sprawdź spójność łańcucha skrótów dziennika audytu")
    v.add_argument("audit", help="plik audit.jsonl")

    w = sub.add_parser("evidence-verify", help="sprawdź skarbiec dowodów: pliki, skróty SHA-256 i dziennik audytu")
    w.add_argument("case", metavar="KATALOG", help="katalog badania (audit.jsonl + evidence/)")
    return p


def _seed_nodes(args) -> tuple[list[Node], list[dict]]:
    seeds, inputs = [], []
    for flag, etype in SEED_FLAGS.items():
        for raw in getattr(args, flag):
            try:
                node = Node.make(etype, raw, source="seed", region=args.phone_region)
            except ValueError as exc:
                raise GuardrailError(f"--{flag}: {exc}") from exc
            seeds.append(node)
            inputs.append({"type": etype.value, "value": node.value})
    if not seeds:
        raise GuardrailError("podaj co najmniej jeden zalążek: " + ", ".join(f"--{f}" for f in SEED_FLAGS))
    return seeds, inputs


def cmd_run(args, ctx: Context | None = None) -> int:
    purpose = validate_purpose(args.purpose)
    seeds, inputs = _seed_nodes(args)
    unknown = (_csv_set(args.only) | _csv_set(args.skip)) - set(REGISTRY)
    if unknown:
        raise GuardrailError("nieznane transformacje: " + ", ".join(sorted(unknown)))
    if args.depth < 0 or args.max_usernames < 0 or args.max_nodes < 1 or args.max_runs < 1:
        raise GuardrailError("limity muszą być dodatnie (depth i max-usernames mogą być 0)")
    started = datetime.now(timezone.utc)
    out = Path(args.out) if args.out else Path.cwd() / f"eg-{started.strftime('%Y%m%d-%H%M%S')}"
    if (out / "graph.json").exists():
        raise GuardrailError(f"{out} zawiera już graph.json; podaj nowy katalog --out")
    out.mkdir(parents=True, exist_ok=True)

    opts = Options(depth=args.depth, max_nodes=args.max_nodes, max_runs=args.max_runs, only=_csv_set(args.only),
                   skip=_csv_set(args.skip), expand_subdomains=args.expand_subdomains,
                   expand_candidates=args.expand_candidates, offline=args.offline)
    operator = args.operator or current_operator()
    audit = AuditLog(out / "audit.jsonl", operator)
    audit_options = {**opts.to_audit(), "max_usernames": args.max_usernames, "max_subdomains": args.max_subdomains,
                     "hibp_key_present": bool(os.environ.get(HIBP_ENV, "").strip()),
                     "evidence_vault": not args.no_evidence}
    try:
        audit.start(purpose, inputs, audit_options, args.case_ref)   # PRZED pierwszym zapytaniem
    except OSError as exc:
        raise GuardrailError(f"nie można zapisać dziennika audytu ({exc}); badanie nie zostało rozpoczęte") from exc

    if ctx is None:
        ctx = Context(fetch=HttpClient(timeout=args.timeout))
    ctx.settings = Settings(
        max_usernames=args.max_usernames, max_subdomains=args.max_subdomains, phone_region=args.phone_region,
        ue_tags=args.ue_tags, ue_limit=args.ue_limit, ue_timeout=args.ue_timeout, offline=args.offline)
    vault = None
    if not args.no_evidence:
        vault = EvidenceVault(out / EVIDENCE_DIR, now=ctx.now)
        ctx.fetch = RecordingFetcher(ctx.fetch, vault)
        ctx.vault = vault
    graph = new_graph(purpose, operator, args.case_ref, inputs, audit_options, started.isoformat(timespec="seconds"))
    if any(s.type in (EntityType.PERSON, EntityType.EMAIL, EntityType.PHONE, EntityType.USERNAME) for s in seeds):
        print("Uwaga: zalążki dotyczą danych osobowych. Przetwarzaj je tylko w granicach celu: " + printable(purpose),
              file=sys.stderr)
    investigate(graph, seeds, ctx, audit, opts, progress=lambda m: print(printable(m), file=sys.stderr))
    graph.meta["finished"] = datetime.now(timezone.utc).isoformat(timespec="seconds")
    if vault is not None:
        keys = ("ref", "url", "status", "error", "sha256", "fetched_at", "transform", "node")
        graph.meta["evidence_vault"] = {"dir": EVIDENCE_DIR, "count": len(vault.entries),
                                        "entries": [{k: e.get(k) for k in keys} for e in vault.entries]}
    graph.save(out / "graph.json")
    write_atomic(out / "graph.graphml", to_graphml(graph))
    write_atomic(out / "report.html", render_html(graph))
    counts = {s: sum(1 for r in graph.runs if r.status is s) for s in Status}
    print(f"\nGotowe: {len(graph.nodes)} węzłów, {len(graph.edges)} krawędzi; uruchomienia: "
          + ", ".join(f"{s.value}={n}" for s, n in counts.items()))
    if vault is not None:
        print(f"Skarbiec dowodów: {len(vault.entries)} odpowiedzi ({EVIDENCE_DIR}/)")
    print(f"Wyniki: {out}  (graph.json, graph.graphml, report.html, audit.jsonl)")
    return 1 if counts[Status.ERROR] else 0


def cmd_rozszerz(args, ctx: Context | None = None, registry: dict | None = None) -> int:
    from .expand import Scope, Seed, expand
    purpose = validate_purpose(args.purpose)
    registry = registry if registry is not None else REGISTRY
    etype = SEED_FLAGS[args.type]
    try:
        Node.make(etype, args.identifier)
        profiles = tuple(Node.make(EntityType.URL, p).value for p in args.profile)
        emails = tuple(Node.make(EntityType.EMAIL, e).value for e in args.email)
    except ValueError as exc:
        raise GuardrailError(f"nieprawidłowe dane początkowe: {exc}") from exc
    seed = Seed(args.identifier, etype, profiles, args.website.strip(), emails, args.display_name.strip(),
                args.entity_kind)
    scope = Scope(adapters=tuple(sorted(_csv_set(args.adapters))), auto_continue=args.auto,
                  max_rounds=args.max_rounds, max_queries=args.max_queries, max_seconds=args.max_seconds,
                  max_cost=args.max_cost, max_candidates=args.max_candidates, max_followups=args.max_followups,
                  offline=args.offline)
    try:
        scope.validate(registry, etype)
    except ValueError as exc:
        raise GuardrailError(str(exc)) from exc
    started = datetime.now(timezone.utc)
    out = Path(args.out) if args.out else Path.cwd() / f"eg-{started.strftime('%Y%m%d-%H%M%S')}"
    if (out / "graph.json").exists():
        raise GuardrailError(f"{out} zawiera już graph.json; podaj nowy katalog --out")
    out.mkdir(parents=True, exist_ok=True)
    stop_file = out / "STOP"
    operator = args.operator or current_operator()
    audit = AuditLog(out / "audit.jsonl", operator)
    inputs = [{"type": etype.value, "value": args.identifier}, {"type": "seed_attributes", "value": seed.to_report()}]
    options = {"mode": "rozszerz", **{k: (list(v) if isinstance(v, tuple) else v) for k, v in vars(scope).items()}}
    try:
        audit.start(purpose, inputs, options, args.case_ref)   # PRZED pierwszym zapytaniem
    except OSError as exc:
        raise GuardrailError(f"nie można zapisać dziennika audytu ({exc}); badanie nie zostało rozpoczęte") from exc
    if ctx is None:
        ctx = Context(fetch=HttpClient(timeout=args.timeout))
    ctx.settings = Settings(ue_tags=args.ue_tags, ue_limit=args.ue_limit, ue_timeout=args.ue_timeout,
                            offline=args.offline)
    graph = new_graph(purpose, operator, args.case_ref, inputs, options, started.isoformat(timespec="seconds"))
    print("Uwaga: kandydaci to hipotezy; przetwarzaj dane tylko w granicach celu: " + printable(purpose),
          file=sys.stderr)
    report = expand(graph, seed, ctx, audit, scope, registry=registry, should_stop=stop_file.exists,
                    progress=lambda m: print(printable(m), file=sys.stderr))
    graph.meta["finished"] = datetime.now(timezone.utc).isoformat(timespec="seconds")
    graph.save(out / "graph.json")
    write_atomic(out / "graph.graphml", to_graphml(graph))
    write_atomic(out / "report.html", render_html(graph))
    d = report["totals"]["decisions"]
    print(f"\nRundy: {len(report['rounds'])}, zapytania: {report['totals']['queries']}; decyzje: "
          f"rozwiń={d['rozwin']}, przegląd={d['przeglad']}, zatrzymaj={d['zatrzymaj']}")
    print(f"Koniec: {printable(report['stop_reason'])}")
    print(f"Wyniki: {out}  (report.html: sekcja 'Rozszerzanie rekordów')")
    return 1 if any(r.status is Status.ERROR for r in graph.runs) else 0


def cmd_polacz(args) -> int:
    purpose = validate_purpose(args.purpose)
    if not 0.0 <= args.min_confidence <= 1.0:
        raise GuardrailError("--min-confidence musi być z zakresu 0-1")
    started = datetime.now(timezone.utc)
    out = Path(args.out) if args.out else Path.cwd() / f"eg-{started.strftime('%Y%m%d-%H%M%S')}"
    if (out / "graph.json").exists():
        raise GuardrailError(f"{out} zawiera już graph.json; podaj nowy katalog --out")
    out.mkdir(parents=True, exist_ok=True)
    operator = args.operator or current_operator()
    inputs = [{"type": "file", "value": str(p)} for p in args.paths]
    options = {"mode": "polacz", "offline": True, "min_confidence": args.min_confidence}
    audit = AuditLog(out / "audit.jsonl", operator)
    try:
        audit.start(purpose, inputs, options, args.case_ref)   # PRZED odczytem pierwszego pliku
    except OSError as exc:
        raise GuardrailError(f"nie można zapisać dziennika audytu ({exc}); łączenie nie zostało rozpoczęte") from exc
    print("Uwaga: pliki mogą zawierać dane osobowe. Przetwarzaj je tylko w granicach celu: " + printable(purpose),
          file=sys.stderr)
    graph = new_graph(purpose, operator, args.case_ref, inputs, options, started.isoformat(timespec="seconds"))
    result = connect_dots(graph, args.paths, audit, min_confidence=args.min_confidence, exclude=(out,),
                          progress=lambda m: print(printable(m), file=sys.stderr))
    graph.meta["finished"] = datetime.now(timezone.utc).isoformat(timespec="seconds")
    graph.save(out / "graph.json")
    write_atomic(out / "graph.graphml", to_graphml(graph))
    write_atomic(out / "report.html", render_html(graph))
    inp = result["inputs"]
    print(f"\nGotowe: {len(graph.nodes)} węzłów, {len(graph.edges)} krawędzi; pliki: IMPORTED={inp['IMPORTED']}, "
          f"SKIPPED={inp['SKIPPED']}, ERROR={inp['ERROR']}; scalenia={result['merges']}, powiązania={result['links']}, "
          f"same_person={result['same_person']}")
    print(f"Wyniki: {out}  (graph.json, graph.graphml, report.html, audit.jsonl)")
    if not graph.nodes:
        print("Uwaga: nic nie zaimportowano (żaden plik nie został rozpoznany).", file=sys.stderr)
        return 1
    return 1 if inp["ERROR"] or result["statuses"][Status.ERROR.value] else 0


def cmd_export(args) -> int:
    if not (args.graphml or args.html or args.maltego):
        raise GuardrailError("podaj --graphml, --maltego i/lub --html")
    graph = Graph.load(args.graph)
    maltego = _check_maltego_path(args.maltego, args.graph, args.force) if args.maltego else None   # przed zapisem czegokolwiek
    if args.graphml:
        write_atomic(args.graphml, to_graphml(graph))
        print(f"GraphML: {args.graphml}")
    if args.html:
        write_atomic(args.html, render_html(graph))
        print(f"HTML: {args.html}")
    if maltego is not None:
        _write_export_file(maltego, to_maltego_csv(graph), args.force)
        print(f"Maltego CSV: {args.maltego}")
    return 0


def _check_maltego_path(raw: str, graph_path: str, force: bool) -> Path:
    """--maltego nie zapisuje do pliku sprawy (graph.json, audit.jsonl, ... w dowolnym katalogu; maltego.csv tylko poza
    katalogiem sprawy), do pliku wejściowego ani do istniejącego pliku (chyba że --force). Odmowa = kod 2."""
    path = Path(raw)
    if path.is_dir() or not path.parent.is_dir():
        raise GuardrailError("--maltego: podaj ścieżkę pliku w istniejącym katalogu")
    key = _report_name_key(path.name)
    if key in {_report_name_key(n) for n in REPORT_RESERVED_NAMES - {"maltego.csv"}}:
        raise GuardrailError(f"--maltego: nazwa {path.name.split(':', 1)[0]!r} jest zastrzeżona dla plików sprawy")
    target = path.resolve()
    source = Path(graph_path)
    if target == source.resolve() or _same_file(path, source):
        raise GuardrailError("--maltego: ścieżka wskazuje plik wejściowy graph.json")
    if key == "maltego.csv" and any(_looks_like_case_dir(d) for d in (target.parent, *target.parent.parents)):
        raise GuardrailError("--maltego: maltego.csv w katalogu sprawy zapisuje sama sprawa; podaj inną ścieżkę")
    if (path.exists() or path.is_symlink()) and not force:
        raise GuardrailError("--maltego: plik już istnieje (nie jest nadpisywany); podaj nową ścieżkę albo --force")
    return path


def _write_export_file(path: Path, text: str, force: bool) -> None:
    """Zapis eksportu przez plik tymczasowy otwarty trybem 'x' (kolizja z cudzym plikiem tymczasowym = odmowa, plik
    nietknięty). Bez --force: os.link (atomowo, błąd gdy cel istnieje); z --force: os.replace (atomowa podmiana).
    Plik tymczasowy usuwany tylko wtedy, gdy utworzyło go to wywołanie."""
    tmp = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    try:
        handle = open(tmp, "x", encoding="utf-8", newline="")  # noqa: SIM115 - zamykane w bloku with poniżej
    except FileExistsError:
        raise GuardrailError(f"--maltego: istnieje już plik tymczasowy {tmp.name} (nie jest usuwany); "
                             "usuń go albo podaj inną ścieżkę") from None
    try:
        with handle:
            handle.write(text)
        if force:
            os.replace(tmp, path)
        else:
            try:
                os.link(tmp, path)
            except FileExistsError:
                raise GuardrailError("--maltego: plik już istnieje (nie jest nadpisywany); "
                                     "podaj nową ścieżkę albo --force") from None
            except OSError:
                try:
                    with open(path, "x", encoding="utf-8", newline="") as fh:
                        fh.write(text)
                except FileExistsError:
                    raise GuardrailError("--maltego: plik już istnieje (nie jest nadpisywany); "
                                         "podaj nową ścieżkę albo --force") from None
    finally:
        try:
            tmp.unlink()   # tylko nasz plik tymczasowy (po os.replace już go nie ma)
        except OSError:
            pass


def cmd_kropki(args) -> int:
    if not 0.0 <= args.min_confidence <= 1.0:   # także NaN: porównanie z NaN jest zawsze fałszywe
        raise GuardrailError("--min-confidence musi być z zakresu 0-1")
    graph = Graph.load(args.graph)
    target = Path(args.svg) if args.svg else Path(args.graph).with_name("kropki.svg")
    write_atomic(target, render_svg(graph, args.max_nodes, args.min_confidence))
    print(f"Kropki: {target} ({len(graph.nodes)} węzłów w grafie)")
    return 0


def _open_case(case: str, operator: str | None) -> tuple[Path, Graph, AuditLog]:
    """Katalog badania z graph.json i spójnym dziennikiem audytu (cel badania pochodzi z dziennika)."""
    c = sprawa.open_case(case, operator)
    return c.folder, c.graph, c.audit


def _save_case(folder: Path, graph: Graph, audit: AuditLog, person: Node) -> None:
    edges = teczka.propagate(graph, person)
    audit.write("teczka", person=person.value, linked=len(edges))
    sprawa.save_case(sprawa.Case(folder, graph, audit, ""))
    _print_dossier(graph, person)


def _print_dossier(graph: Graph, person: Node) -> None:
    d = teczka.dossier(graph, person)
    print(f"\nTeczka: {printable(person.value)}")
    print(f"  potwierdzone profile ({len(d['confirmed'])}):")
    for node, _ in d["confirmed"]:
        print(f"    + {printable(node.value)}")
    print(f"  odrzucone ({len(d['rejected'])})")
    print(f"  dane połączone przez potwierdzone profile ({len(d['data'])}):")
    for node, e in d["data"]:
        print(f"    {node.type.value:<12} {printable(node.value):<40} {e.confidence:.2f}")


def _decide(graph: Graph, audit: AuditLog, person: Node, profile: Node, decision: str, evidence: str) -> None:
    teczka.validate_evidence(evidence)
    try:   # wpis "przed": bez niego decyzja się nie wykonuje
        audit.write("decision_request", person=person.value, profile=profile.value, decision=decision)
    except OSError as exc:
        raise GuardrailError(f"nie można zapisać dziennika audytu ({exc}); decyzja nie została zapisana") from exc
    edge = teczka.decide(graph, person, profile, decision, evidence)
    audit.write("decision", person=person.value, profile=profile.value, decision=decision, evidence=edge.evidence)


ASK = input  # podmieniane w testach


def cmd_przeglad(args) -> int:
    folder, graph, audit = _open_case(args.case, args.operator)
    person = teczka.find_person(graph, args.person)
    print("Decyzja 'to ta osoba' należy do Ciebie. Ta sama nazwa lub zdjęcie to trop, nie dowód.")
    seen: set[str] = set()
    changed = False
    while True:
        pending = [c for c in teczka.candidates(graph, person) if not c.decision and c.node.id not in seen]
        if not pending:
            print("Brak kolejnych kandydatów." if seen or changed else
                  "Brak kandydatów: uruchom 'eg run --person ... --expand-candidates' albo dodaj profil przez 'eg potwierdz --dodaj'.")
            break
        cand = pending[0]
        seen.add(cand.node.id)
        a = cand.node.attrs
        conf = f"{cand.confidence:.2f}" if cand.confidence is not None else "-"
        print(f"\n[{len(pending)} do przejrzenia] {printable(cand.node.value)}")
        print(f"  serwis: {printable(a.get('site', '-'))}  pewność konta: {conf}")
        for label, key in (("nazwa wyświetlana", "display_name"), ("strona www", "website"), ("utworzono", "created")):
            if a.get(key):
                print(f"  {label}: {printable(a[key])}")
        for link in a.get("links") or []:
            print(f"  link: {printable(link)}")
        for reason in cand.reasons:
            print(f"  skąd: {printable(reason)}")
        answer = ASK("To ta osoba? [t]ak / [n]ie / [p]omiń / [k]oniec: ").strip().lower()[:1]
        if answer == "k":
            break
        if answer not in ("t", "n"):
            continue
        decision = teczka.CONFIRMED if answer == "t" else teczka.REJECTED
        while True:
            evidence = ASK("Dowód (co zgadza się / nie zgadza): ")
            try:
                _decide(graph, audit, person, cand.node, decision, evidence)
                break
            except ValueError as exc:
                print(f"  {exc}")
        teczka.propagate(graph, person)
        changed = True
    if changed:
        _save_case(folder, graph, audit, person)
        print(f"\nZapisano: {folder}  (graph.json, report.html, kropki.svg, audit.jsonl)")
    else:
        _print_dossier(graph, person)
    return 0


def cmd_potwierdz(args) -> int:
    folder, graph, audit = _open_case(args.case, args.operator)
    person = teczka.find_person(graph, args.person)
    profile_id = Node.make(EntityType.URL, args.profil).id
    if profile_id not in graph.nodes:
        if not args.dodaj:
            raise GuardrailError(f"profilu {args.profil} nie ma w grafie; jeśli znalazłeś go ręcznie, dodaj --dodaj")
        audit.write("manual_profile", profile=teczka.add_manual_profile(graph, args.profil).value)
    profile = graph.nodes[profile_id]
    _decide(graph, audit, person, profile, teczka.REJECTED if args.odrzuc else teczka.CONFIRMED, args.dowod)
    _save_case(folder, graph, audit, person)
    return 0


def _person(graph: Graph, name: str, add: bool) -> tuple[Node, bool]:
    try:
        return teczka.find_person(graph, name), False
    except ValueError:
        if not add:
            raise
    return relacje.add_person(graph, name)


def _print_claims(graph: Graph) -> None:
    items = relacje.claims(graph)
    print(f"\nTwierdzenia o relacjach ({len(items)}): ocena człowieka, nie dowód pokrewieństwa")
    for c in items:
        a, b = graph.nodes.get(c["src"]), graph.nodes.get(c["dst"])
        print(f"  {c['id']}  {printable(a.value if a else c['src'])} -- {printable(relacje.describe(c))} -- "
              f"{printable(b.value if b else c['dst'])}  [{c['status']}, pewność {c.get('confidence', 0):.2f}]")
    for line in relacje.contradictions(graph):
        print(f"  UWAGA, sprzeczne twierdzenia do wyjaśnienia: {printable(line)}")


def cmd_relacja(args) -> int:
    case = sprawa.open_case(args.case, args.operator)
    g = case.graph
    source = sprawa.check_reference(args.zrodlo, case.folder)   # zła referencja: nic nie jest zapisywane
    fields = {"person": args.person, "kind": args.typ, "other": args.druga_osoba, "source": source}

    def action() -> dict:
        a, added_a = _person(g, args.person, args.dodaj)
        b, added_b = _person(g, args.druga_osoba, args.dodaj)
        claim, changed = relacje.add_claim(g, a, b, args.typ, source, args.dowod, case.purpose, args.fragment,
                                           args.opis, case.audit.operator)
        return {"changed": changed or added_a or added_b, "claim": claim["id"], "status": claim["status"],
                "confidence": claim["confidence"],
                "added_people": [x.value for x, new in ((a, added_a), (b, added_b)) if new]}

    result = sprawa.audited(case, "relation_claim", fields, action)
    print(f"Twierdzenie {result['claim']}: {result['status']} (pewność {result['confidence']:.2f}); wymaga potwierdzenia "
          "osobnym uzasadnieniem. Nic nie zostało wyszukane ani uruchomione.")
    _print_claims(g)
    return 0


def cmd_relacja_potwierdz(args) -> int:
    case = sprawa.open_case(args.case, args.operator)
    decision = relacje.REJECTED if args.odrzuc else relacje.CONFIRMED
    relacje.find_claim(case.graph, args.id)

    def action() -> dict:
        claim, changed = relacje.decide(case.graph, args.id, decision, args.dowod, case.audit.operator)
        return {"changed": changed, "claim": claim["id"], "status": claim["status"],
                "confidence": claim["confidence"], "evidence": claim["decision_evidence"]}

    result = sprawa.audited(case, "relation_decision", {"claim": args.id, "decision": decision}, action)
    print(f"Twierdzenie {result['claim']}: {result['status']} (pewność {result['confidence']:.2f})"
          + ("" if result["changed"] else "; bez zmian"))
    _print_claims(case.graph)
    return 0


def _print_phone(graph: Graph, number: str, region: str) -> None:
    ctx = telefon.context(graph.nodes[Node.make(EntityType.PHONE, number, region=region).id])
    print(f"\nKontekst numeru {printable(ctx['value'])} (plan numeracyjny; numer nie jest wiązany z osobą):")
    for f in ctx["fields"]:
        print(f"  {f['label']}: {printable(f['value'])}")
    if ctx["manual_check_url"]:
        print(f"  ręczna weryfikacja aktualnego operatora (otwierasz sam): {printable(ctx['manual_check_url'])}")
    for c in ctx["conflicts"]:
        print(f"  KONFLIKT obserwacji (pole nieznane): {printable(c)}")


def cmd_telefon(args, ctx: Context | None = None) -> int:
    case = sprawa.open_case(args.case, args.operator)
    region = (args.region or "PL").strip().upper()
    if not re.fullmatch(r"[A-Z]{2}", region):
        raise GuardrailError("--region: dwuliterowy kod ISO, np. PL")
    if args.operator_aktualny:
        if not (args.numer and args.zrodlo and args.data) or args.plik:
            raise GuardrailError("--operator-aktualny wymaga --numer, --zrodlo i --data (bez --plik)")
        ref = sprawa.check_reference(args.zrodlo, case.folder)
        day = telefon.check_day(args.data)

        def manual() -> dict:
            node, changed = telefon.attach_manual_carrier(case.graph, args.numer, args.operator_aktualny, ref, day,
                                                          region=region)
            return {"changed": changed, "phone": node.value, "conflicts": node.conflicts()}

        result = sprawa.audited(case, "phone_manual_carrier", {"phone": args.numer, "source": ref, "day": day}, manual)
        print("Zapisano osobną obserwację operatora z ręcznej weryfikacji" + ("" if result["changed"] else " (już była)")
              + "; operator z planu numeracji nie został nadpisany.")
        _print_phone(case.graph, result["phone"], region)
        return 0
    if bool(args.numer) == bool(args.plik):
        raise GuardrailError("podaj dokładnie jedno: --numer albo --plik")
    row = None
    if args.plik:
        try:
            row = parse_phone_check(json.loads(Path(args.plik).read_text(encoding="utf-8")))
        except (OSError, ValueError) as exc:
            raise GuardrailError(f"--plik: nieczytelny wynik phone-check ({type(exc).__name__})") from exc
        if row is None:
            raise GuardrailError("--plik: to nie jest wynik phone-check")
    fields = {"phone": args.numer or "", "via": f"plik {Path(args.plik).name}" if args.plik else "phone-check (offline)",
              "region": region}

    def action() -> dict:
        data, status, note = row, Status.FOUND, ""
        if data is None:
            data, status, note = run_phone_check(args.numer, region, ctx or Context())
            if data is None:
                raise GuardrailError(f"{status.value}: {note}")
        elif not data.get("valid"):
            status, note = Status.NOT_FOUND, f"numer niepoprawny w planie numeracji: {data.get('error')}"
        node, changed = telefon.attach_plan(case.graph, data, region=region)
        return {"changed": changed, "phone": node.value, "status": status.value, "note": note,
                "conflicts": node.conflicts()}

    result = sprawa.audited(case, "phone_context", fields, action)
    print(f"{result['status']}: {printable(result['phone'])}"
          + ("" if result["changed"] else " (ten sam wynik był już w sprawie: bez zmian)"))
    _print_phone(case.graph, result["phone"], region)
    return 0


def cmd_kandydaci(args, ctx: Context | None = None) -> int:
    from .expand import Scope
    case = sprawa.open_case(args.case, args.operator)
    g = case.graph
    if not 1 <= args.max_nazw <= kandydaci.MAX_NAMES or (args.ue_limit is not None and not 1 <= args.ue_limit <= 10000):
        raise GuardrailError(f"--max-nazw: 1-{kandydaci.MAX_NAMES}; --ue-limit: 1-10000")
    if args.ue_tags and not re.fullmatch(r"[A-Za-z0-9_,][A-Za-z0-9_,-]{0,99}", args.ue_tags):
        raise GuardrailError("--ue-tags: kategorie po przecinku, np. social,pl")
    try:
        entry = kandydaci.resolve_entry(g, args.person.strip(), args.username.strip())
        names = sorted(_csv_set(args.nazwy)) or None
        plan = kandydaci.plan_names(g, entry, names, args.max_nazw)
        scope = Scope(adapters=(kandydaci.ADAPTER,), auto_continue=False, max_rounds=1, max_queries=args.max_queries,
                      max_seconds=args.max_seconds, max_cost=args.max_cost)
        kandydaci.check_scope(scope, len(plan))
    except ValueError as exc:
        raise GuardrailError(str(exc)) from exc
    if ctx is None:
        ctx = Context()
    ctx.settings = Settings(ue_tags=args.ue_tags, ue_limit=args.ue_limit, ue_timeout=min(900.0, args.max_seconds))
    fields = {"entry": f"{entry.type.value}: {entry.value}", "names": [n.value for n in plan],
              "scope": {"max_queries": args.max_queries, "max_cost": args.max_cost, "max_seconds": args.max_seconds,
                        "max_rounds": args.max_rounds, "ue_tags": args.ue_tags, "ue_limit": args.ue_limit}}
    print("Uwaga: kandydaci profili to hipotezy; profil łączy z osobą tylko Twoja decyzja (eg potwierdz). Cel: "
          + printable(case.purpose), file=sys.stderr)

    def action() -> dict:
        rep = kandydaci.run_round(g, entry, plan, ctx, case.audit, scope, max_rounds=args.max_rounds)
        return {"changed": True, "round": rep["round"], "totals": rep["totals"], "stop_reason": rep["stop_reason"],
                "proposals": [p["identifier"] for p in rep["proposals"]]}

    try:
        result = sprawa.audited(case, "profile_round", fields, action)
    except ValueError as exc:
        raise GuardrailError(str(exc)) from exc
    rep = kandydaci.rounds(g)[-1]
    for q in rep["queries"]:
        print(f"  {q['status']:<9} {printable(q['identifier'])}" + (f"  ({printable(q['note'])})" if q.get("note") else ""))
    for c in rep["candidates"]:
        print(f"  kandydat: {printable(c['profile'])}  [{kandydaci.DECISION_PL.get(c['decision'], c['decision'])}, "
              f"dowody {c['level']}]")
    t = result["totals"]
    print(f"Runda {result['round']}: zapytania {t['queries']}/{args.max_queries}, koszt {t['cost']:g}/{args.max_cost:g}, "
          f"czas {t['seconds']} s; {printable(result['stop_reason'])}")
    if result["proposals"]:
        print("Propozycje kolejnej rundy (nic nie uruchomiono): " + ", ".join(printable(p) for p in result["proposals"]))
    return 1 if t["statuses"]["ERROR"] else 0


PROFILE_HTTP = None   # klient HTTP dla szukaj-profili; podmieniany w testach (atrapa transportu)
EXIT_CONFIG = 3       # brak albo błąd konfiguracji: nic nie wysłano, sprawa bez zmian


def _check_person(graph: Graph, name: str, add: bool) -> None:
    """Przed wpisem audytu: osoba w grafie albo jawne --dodaj (błąd = nic nie zapisujemy)."""
    try:
        teczka.find_person(graph, name)
    except ValueError:
        if not add:
            raise GuardrailError(f"osoby '{name}' nie ma w sprawie; dopisz ją jawnie przez --dodaj") from None


def cmd_szukaj_profili(args, environ=None) -> int:
    case = sprawa.open_case(args.case, args.operator)
    g = case.graph
    limits = profile_discovery.Limits(args.max_calls, args.max_results, args.max_candidates, args.max_seconds)
    try:
        limits.validate()
    except ValueError as exc:
        raise GuardrailError(str(exc)) from exc
    cfg = profile_discovery.load_config(environ)
    problem = cfg.blocking_problem()
    plan = []
    try:
        _, brave = profile_discovery.load_connector()
    except Exception as exc:  # noqa: BLE001 - brak pakietu siostrzanego to problem konfiguracji, nie wynik
        problem = problem or f"{profile_discovery.REASONS['unavailable']}: {type(exc).__name__}"
        brave = None
    if brave is not None:
        try:
            plan = brave.build_queries(args.person, args.kontekst)
        except ValueError as exc:
            raise GuardrailError(str(exc)) from exc
    if problem:
        print(f"Brak konfiguracji wyszukiwania (nic nie wysłano, sprawa bez zmian): {printable(problem)}",
              file=sys.stderr)
        return EXIT_CONFIG
    _check_person(g, args.person, args.dodaj)
    print(f"Uwaga: imię i nazwisko oraz kontekst trafiają do dostawcy wyszukiwarki ({profile_discovery.PROVIDER}). "
          f"Kanał: {cfg.channel()}. Wyniki to hipotezy, nie wszystkie konta. Cel: {printable(case.purpose)}",
          file=sys.stderr)
    fields = {"person": args.person, "context": args.kontekst, "provider": profile_discovery.PROVIDER,
              "channel": cfg.channel(), "planned_queries": len(plan),
              "limits": {k: getattr(limits, k) for k in profile_discovery.Limits.HARD}}

    def action() -> dict:
        person, added = profile_discovery.resolve_person(g, args.person, args.dodaj)
        rep = profile_discovery.search(g, person, args.kontekst, limits, cfg, http=PROFILE_HTTP)
        return {"changed": True, "run": rep["number"], "added_person": added, "totals": rep["totals"],
                "stop_reason": rep["stop_reason"], "partial": rep["partial"]}

    try:
        result = sprawa.audited(case, "profile_search", fields, action)
    except profile_discovery.ConfigError as exc:
        print(f"Brak konfiguracji wyszukiwania (nic nie wysłano): {printable(exc)}", file=sys.stderr)
        return EXIT_CONFIG
    rep = profile_discovery.state(g)["runs"][-1]
    for q in rep["queries"]:
        print(f"  {q['status']:<9} {printable(q['query'])}  [{q['reason']}; wyników {q['results']}, "
              f"przyjęto {q['accepted']}, wywołań {q['attempts']}]")
    for q in rep["skipped"]:
        print(f"  pominięto {printable(q['query'])}  [{printable(q['why'])}]")
    t = result["totals"]
    print(f"Przebieg {result['run']}: wywołania {t['calls']}/{limits.calls}, kandydaci {t['candidates_seen']} "
          f"(nowi {t['new_candidates']}), odrzucone adresy {t['discarded']}, czas {t['seconds']} s; "
          f"{printable(result['stop_reason'])}" + (" (wynik częściowy)" if result["partial"] else ""))
    print("Kandydaci to hipotezy: decyzję podejmujesz przez 'eg potwierdz' (z dowodem). Zero wyników zapytania "
          "nie oznacza braku kont.")
    return 1 if t["statuses"]["ERROR"] else 0


def _read_stdin_text(limit: int) -> str:
    data = sys.stdin.buffer.read(limit * 4 + 1)
    if len(data) > limit * 4:
        raise GuardrailError(f"materiał: najwyżej {limit} znaków")
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError:
        raise GuardrailError("materiał: oczekiwano tekstu UTF-8") from None


def cmd_material_profilu(args) -> int:
    from .profile_analyzer import MAX_MATERIAL, clean_material
    from .profile_urls import check_url
    case = sprawa.open_case(args.case, args.operator)
    g = case.graph
    text = _read_stdin_text(MAX_MATERIAL) if args.tekst_stdin else args.tekst
    try:
        purl = check_url(args.url, require_platform=False)
        clean = clean_material(text)
    except ValueError as exc:
        raise GuardrailError(str(exc)) from exc
    _check_person(g, args.person, args.dodaj)
    fields = {"person": args.person, "url": purl.canonical, "text_chars": len(clean),
              "text_sha256": profile_discovery._sha(clean)}

    def action() -> dict:
        person, added = profile_discovery.resolve_person(g, args.person, args.dodaj)
        res = profile_discovery.add_material(g, person, args.url, text)
        res["changed"] = res["changed"] or added
        return res

    result = sprawa.audited(case, "profile_material", fields, action)
    print(f"{'Zapisano' if result['changed'] else 'Bez zmian (ten sam adres i tekst już były w sprawie)'}: "
          f"{printable(result['url'])} [{result['url_class']}]; analiza: {result['analysis_status']}, ustaleń "
          f"{result['findings']}. Materiał traktujemy jako dostarczony przez operatora, nie zweryfikowaną kopię strony.")
    if not result["account"]:
        print("To nie jest adres konta (post, grupa albo strona organizacji): nie łączy się z osobą jako profil.")
    return 0


def cmd_sprawa(args) -> int:
    case = sprawa.open_case(args.case)
    print(json.dumps(sprawa.summary(case.graph), ensure_ascii=False))
    return 0


def cmd_asystent(args) -> int:
    case = sprawa.open_case(args.case, args.operator)
    result = asystent.analyze(case.graph)
    if args.ai:
        url = asystent.check_loopback(args.ai_url)   # zly adres: blad przed wpisem w dzienniku i bez polaczenia
        payload = json.dumps(asystent.ai_payload(result), ensure_ascii=False, sort_keys=True)
        # wpis "przed": co (skrot danych) i dokad idzie, zanim cokolwiek trafi do modelu
        case.audit.write("asystent_ai", phase="przed", model=args.model, adres=url,
                         dane_sha256=hashlib.sha256(payload.encode("utf-8")).hexdigest())
        ai = asystent.ai_review(result, url=url, model=args.model)
        result["ai"] = ai
        # do dziennika tylko fakt uzycia, model, status i skrot tekstu (bez tresci odpowiedzi)
        case.audit.write("asystent_ai", phase="po", model=ai["model"], status=ai["status"],
                         sha256=ai.get("sha256", ""), usuniete_linie=ai["usuniete_linie"])
    print(json.dumps(result, ensure_ascii=False))
    return 0


def cmd_dziennik(args) -> int:
    # bez open_case: dziennik ma dać się obejrzeć także wtedy, gdy łańcuch jest przerwany (wtedy spojny=false)
    path = Path(args.case) / "audit.jsonl"
    if not path.is_file():
        raise GuardrailError(f"brak dziennika audytu w {args.case}")
    print(json.dumps(asystent.audit_entries(path, args.limit), ensure_ascii=False))
    return 0


EXIT_PARTIAL = 4      # import-org-intel: część rekordów odrzucona (pozostałe zaimportowane); jak w org-intel ingest
EXIT_STRICT = 5       # import-org-intel --strict: odmowa przy pierwszym odrzuceniu; sprawa i dziennik bez zmian


def _org_intel_report(case_folder: Path, name: str, stats, imp, dry: bool, refused: bool = False) -> dict:
    return {"dry_run": dry, "strict": imp.strict, "refused": refused, "file": name, "format": imp.format,
            "case": str(case_folder), **stats.to_dict(),
            "rejections": [{"record": r.label, "reason": r.reason} for r in imp.rejected],
            "warnings": list(imp.warnings), "records_in_file": dict(imp.counts)}


def _print_org_intel_report(rep: dict) -> None:
    if rep["refused"]:
        print("ODMOWA (--strict): nic nie zapisano")
    elif rep["dry_run"]:
        print("DRY-RUN: nic nie zapisano")
    print(f"Import org-intel: {printable(rep['file'])} (format: {rep['format']}), sprawa {printable(rep['case'])}")
    print(f"Identyfikator importu: {rep['import_id']}")
    print(f"Węzły:     utworzone {rep['nodes_created']}, zaktualizowane {rep['nodes_updated']}, "
          f"bez zmian (pominięte) {rep['nodes_unchanged']}, odrzucone {rep['rejected_records']}")
    print(f"Krawędzie: utworzone {rep['edges_created']}, zaktualizowane {rep['edges_updated']}, "
          f"bez zmian (pominięte) {rep['edges_unchanged']}, odrzucone {rep['rejected_edges']}")
    print(f"Pominięte: osoba – poza zakresem importu: {rep['skipped_people']}")
    print(f"Zamaskowane e-maile (pola): {rep['masked_fields']}; nieznane pola rekordów: {rep['unknown_fields']}")
    for item in rep["rejections"]:
        print(f"  ODRZUCONO {printable(item['record'])}: {printable(item['reason'])}")
    for warning in rep["warnings"]:
        print(f"  uwaga: {printable(warning)}")


def _same_file(a: Path, b: Path) -> bool:
    try:
        return a.exists() and b.exists() and os.path.samefile(a, b)
    except OSError:
        return False


# Nazwy plików sprawy zastrzeżone dla --report: maltego.csv jawnie, niezależnie od wersji sprawa.CASE_FILES.
REPORT_RESERVED_NAMES = sprawa.CASE_FILES | {"maltego.csv"}


def _report_name_key(name: str) -> str:
    """Nazwa pliku tak, jak ją rozumie Windows: bez strumienia ':x', końcowych kropek i spacji, bez wielkości liter."""
    return name.split(":", 1)[0].rstrip(". ").casefold()


def _looks_like_case_dir(folder: Path) -> bool:
    return any((folder / name).exists() for name in ("graph.json", "audit.jsonl"))


def _check_report_path(raw: str, case: str, input_path: str) -> Path:
    """--report nie może wskazywać pliku ŻADNEJ sprawy ani pliku wejściowego (także przez '..', ścieżkę względną,
    symlink, junction albo twarde dowiązanie) i nie nadpisuje istniejącego pliku. Sprawdzane przed czymkolwiek
    innym, także przy --dry-run; odmowa = kod 2."""
    path = Path(raw)
    if path.is_dir() or not path.parent.is_dir():
        raise GuardrailError("--report: podaj ścieżkę pliku w istniejącym katalogu")
    if _report_name_key(path.name) in {_report_name_key(n) for n in REPORT_RESERVED_NAMES}:
        raise GuardrailError(f"--report: nazwa {path.name.split(':', 1)[0]!r} jest zastrzeżona dla plików sprawy")
    target = path.resolve()                       # rozwiązuje '..', ścieżki względne, symlinki i junctiony
    source = Path(input_path)
    if target == source.resolve() or _same_file(path, source):
        raise GuardrailError("--report: ścieżka wskazuje plik wejściowy --input")
    # Istniejący plik (także symlink albo twarde dowiązanie do pliku sprawy) nigdy nie jest nadpisywany.
    if path.exists() or path.is_symlink():
        raise GuardrailError("--report: plik już istnieje (raport nie nadpisuje plików); podaj nową ścieżkę")
    case_dir = Path(case).resolve()
    if target == case_dir or case_dir in target.parents:
        raise GuardrailError("--report: ścieżka leży w katalogu sprawy (raport nadpisałby plik sprawy); "
                             "zapisz raport poza katalogiem sprawy")
    for folder in (target.parent, *target.parent.parents):   # katalog DOWOLNEJ sprawy albo jego podkatalog
        if _looks_like_case_dir(folder):
            raise GuardrailError("--report: ścieżka leży w katalogu sprawy (zawiera graph.json albo audit.jsonl); "
                                 "zapisz raport poza katalogami spraw")
    # Plik tymczasowy zapisu raportu sprawdzany PRZED importem: kolizja wykryta dopiero przy zapisie raportu
    # oznaczałaby kod 2 przy już zapisanym imporcie.
    tmp = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    if tmp.exists() or tmp.is_symlink():
        raise GuardrailError(f"--report: istnieje już plik tymczasowy {tmp.name} (nie jest usuwany); "
                             "usuń go albo podaj inną ścieżkę raportu")
    return path


def _write_new_file(path: Path, text: str) -> None:
    """Zapis TYLKO nowego pliku: treść do pliku tymczasowego, potem os.link (atomowo, błąd, gdy cel istnieje).
    Bez obsługi twardych dowiązań: otwarcie w trybie 'x' (też nie nadpisuje). Plik tymczasowy jest usuwany tylko
    wtedy, gdy utworzyło go to wywołanie; istniejący wcześniej plik o tej nazwie nie jest ruszany."""
    tmp = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    try:
        handle = open(tmp, "x", encoding="utf-8", newline="\n")  # noqa: SIM115 - zamykane w bloku with poniżej
    except FileExistsError:
        raise GuardrailError(f"--report: istnieje już plik tymczasowy {tmp.name} (nie jest usuwany); "
                             "usuń go albo podaj inną ścieżkę raportu") from None
    try:
        with handle:
            handle.write(text)
        try:
            os.link(tmp, path)
        except FileExistsError:
            raise GuardrailError("--report: plik już istnieje (raport nie nadpisuje plików)") from None
        except OSError:
            try:
                with open(path, "x", encoding="utf-8", newline="\n") as fh:
                    fh.write(text)
            except FileExistsError:
                raise GuardrailError("--report: plik już istnieje (raport nie nadpisuje plików)") from None
    finally:
        try:
            tmp.unlink()  # tylko nasz plik tymczasowy (utworzony powyżej trybem 'x')
        except OSError:
            pass


def cmd_import_org_intel(args) -> int:
    if args.json and args.format == "text":
        raise GuardrailError("--json (alias --format json) jest sprzeczne z --format text")
    fmt = "json" if args.json else (args.format or "text")
    report_path = _check_report_path(args.report, args.case, args.input) if args.report else None
    path = Path(args.input)
    if path.suffix.lower() == ".csv":
        raise GuardrailError("CSV z org-intel nie jest obsługiwany (wiele plików, rozbita proweniencja, zamaskowane "
                             "e-maile): użyj `org-intel export --format json` albo store.json")
    if path.stat().st_size > MAX_FILE_BYTES:
        raise GuardrailError(f"plik większy niż {MAX_FILE_BYTES // (1024 * 1024)} MB")
    raw = path.read_bytes()
    digest = hashlib.sha256(raw).hexdigest()
    try:
        data = json.loads(raw.decode("utf-8-sig"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        raise GuardrailError("plik nie jest poprawnym JSON w UTF-8") from None
    case = sprawa.open_case(args.case, args.operator)
    if org_intel.kind_of(data) is None:
        hint = (" To wejściowy format org-intel: uruchom najpierw `org-intel ingest`, potem `org-intel export "
                "--format json`." if isinstance(data, dict) and "organizations" in data and "schema_version" not in data
                else "")
        raise GuardrailError("nierozpoznany plik: oczekiwano eksportu JSON albo store.json org-intel." + hint)
    now = utc_now()
    graph = Graph.from_dict(case.graph.to_dict()) if args.dry_run else case.graph    # dry-run: tylko kopia w pamięci
    imp = org_intel.parse(data, ImportCtx(org_intel.TOOL, path.name, now), existing=graph, strict=args.strict,
                          file_sha256=digest)
    if imp.error:
        raise GuardrailError(imp.error)
    refused = args.strict and bool(imp.rejected)
    if refused:
        # Decyzja PRZED sprawa.audited: nic nie jest zapisywane, także wpis w dzienniku (dziennik notuje zmiany sprawy,
        # a odmowa jej nie zmienia). Ślad odmowy: kod 5, raport na ekranie i w --report (z identyfikatorem importu).
        stats = org_intel.ImportStats(rejected_records=len(imp.rejected), rejected_edges=imp.rejected_edges,
                                      skipped_people=imp.skipped_people, masked_fields=imp.masked_fields,
                                      unknown_fields=imp.unknown_fields, import_id=imp.import_id)
    elif args.dry_run:
        stats = org_intel.apply(graph, imp, path.name, now)
    else:
        fields = {"file": path.name, "sha256": digest, "format": imp.format, "records": dict(imp.counts),
                  "import_id": imp.import_id, "strict": args.strict}

        def action() -> dict:
            result = org_intel.apply(graph, imp, path.name, now)
            return {"changed": result.changed, **result.to_dict()}

        done = sprawa.audited(case, "org_intel_import", fields, action)
        stats = org_intel.ImportStats(**{k: v for k, v in done.items() if k != "changed"})
    report = _org_intel_report(case.folder, path.name, stats, imp, args.dry_run, refused)
    if report_path is not None:
        _write_new_file(report_path, json.dumps(report, ensure_ascii=False, indent=2) + "\n")
    if fmt == "json":
        print(json.dumps(report, ensure_ascii=False, indent=2))
    else:
        _print_org_intel_report(report)
    return EXIT_STRICT if refused else (EXIT_PARTIAL if stats.rejected_records else 0)


def cmd_transforms() -> int:
    for t in REGISTRY.values():
        net = "sieć " if t.network else "offline"
        print(f"{t.name:<18} {net}  {','.join(i.value for i in t.inputs):<14} {t.description}")
    return 0


def main(argv: list[str] | None = None, ctx: Context | None = None) -> int:
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")
        except (AttributeError, ValueError):
            pass
    args = build_parser().parse_args(argv)
    try:
        if args.cmd == "run":
            return cmd_run(args, ctx)
        if args.cmd == "rozszerz":
            return cmd_rozszerz(args, ctx)
        if args.cmd == "polacz":
            return cmd_polacz(args)
        if args.cmd == "export":
            return cmd_export(args)
        if args.cmd == "przeglad":
            return cmd_przeglad(args)
        if args.cmd == "potwierdz":
            return cmd_potwierdz(args)
        if args.cmd == "kropki":
            return cmd_kropki(args)
        if args.cmd == "relacja":
            return cmd_relacja(args)
        if args.cmd == "relacja-potwierdz":
            return cmd_relacja_potwierdz(args)
        if args.cmd == "telefon":
            return cmd_telefon(args, ctx)
        if args.cmd == "kandydaci":
            return cmd_kandydaci(args, ctx)
        if args.cmd == "szukaj-profili":
            return cmd_szukaj_profili(args)
        if args.cmd == "material-profilu":
            return cmd_material_profilu(args)
        if args.cmd == "sprawa":
            return cmd_sprawa(args)
        if args.cmd == "asystent":
            return cmd_asystent(args)
        if args.cmd == "dziennik":
            return cmd_dziennik(args)
        if args.cmd == "import-org-intel":
            return cmd_import_org_intel(args)
        if args.cmd == "transforms":
            return cmd_transforms()
        if args.cmd == "evidence-verify":
            ok, msg = verify_vault(args.case)
            print(("OK: " if ok else "BŁĄD: ") + printable(msg))
            return 0 if ok else 1
        ok, msg = verify_audit(args.audit)
        print(("OK: " if ok else "BŁĄD: ") + msg)
        return 0 if ok else 1
    except (GuardrailError, ValueError, OSError) as exc:
        print(f"Błąd: {printable(exc)}", file=sys.stderr)
        return 2
