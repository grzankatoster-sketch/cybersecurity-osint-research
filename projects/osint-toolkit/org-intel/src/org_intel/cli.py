"""Interfejs wiersza polecen org-intel (argparse).

Kody wyjscia: 0 OK; 2 blad uzycia/konfiguracji (w tym polecenie sieciowe bez --online); 3 blad sieci;
4 ingest zakonczony, ale czesc rekordow odrzucono (pozostale zapisano).
DOMYSLNIE OFFLINE: polecenia sieciowe bez --online koncza sie kodem 2, bez zadnego ruchu sieciowego.
"""

from __future__ import annotations

import argparse
import json
import logging
import sys
from collections.abc import Sequence
from datetime import UTC, datetime
from pathlib import Path
from typing import TextIO

from . import __version__, correlate, export, parsers, verify
from .hibp_catalog import ConfigError, HibpCatalogClient
from .http import Client, NetworkError
from .logging_redact import make_handler
from .models import VerificationStatus
from .normalize import normalize_domain
from .store import DEFAULT_STORE, Store, StoreError

EXIT_OK = 0
EXIT_USAGE = 2
EXIT_NETWORK = 3
EXIT_PARTIAL = 4


class UsageError(Exception):
    """Blad uzycia/konfiguracji (kod 2)."""


def build_parser() -> argparse.ArgumentParser:
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument(
        "--store", type=Path, default=DEFAULT_STORE, help=f"plik magazynu JSON (domyślnie {DEFAULT_STORE})"
    )

    p = argparse.ArgumentParser(prog="org-intel", description=__doc__.split("\n\n")[0])
    p.add_argument("--version", action="version", version=f"org-intel {__version__}")
    sub = p.add_subparsers(dest="command", required=True)

    s = sub.add_parser("ingest", parents=[common], help="zaimportuj plik JSON (własny format albo katalog HIBP)")
    s.add_argument("file", type=Path)
    s.add_argument(
        "--audit-mode",
        action="store_true",
        help="zapisz zaakceptowane rekordy wejściowe do raw/ obok magazynu (domyślnie wyłączone)",
    )

    s = sub.add_parser("search-company", parents=[common], help="szukaj firmy po nazwie, KRS, NIP lub REGON")
    s.add_argument("query")
    s.add_argument("--json", action="store_true")

    s = sub.add_parser("incidents", parents=[common], help="incydenty dla domeny (i jej subdomen)")
    s.add_argument("--domain", required=True)
    s.add_argument("--json", action="store_true")

    s = sub.add_parser("export", parents=[common], help="eksport magazynu do JSON albo CSV")
    s.add_argument("--format", choices=["json", "csv"], required=True)
    s.add_argument("--out", type=Path, required=True, help="plik (json) albo katalog (csv)")
    s.add_argument("--include-emails", action="store_true", help="pełne adresy e-mail osób (domyślnie maskowane)")

    s = sub.add_parser("verify-domain", parents=[common], help="weryfikacja własności domeny rekordem TXT")
    s.add_argument("domain")
    s.add_argument("--check", action="store_true", help="sprawdź rekord TXT (wymaga --online)")
    s.add_argument("--online", action="store_true", help="zezwól na ruch sieciowy (DNS-over-HTTPS)")

    s = sub.add_parser(
        "fetch-hibp-catalog",
        parents=[common],
        help="pobierz publiczny katalog metadanych incydentów HIBP (wymaga --online)",
    )
    s.add_argument("--online", action="store_true", help="zezwól na ruch sieciowy")
    s.add_argument("--user-agent", help="wymagany przez HIBP nagłówek User-Agent")
    s.add_argument("--refresh", action="store_true", help="pomiń cache (TTL 24 h)")
    s.add_argument(
        "--audit-mode",
        action="store_true",
        help="zapisz zaakceptowane rekordy (tylko dozwolone pola) do raw/ obok magazynu (domyślnie wyłączone)",
    )
    return p


def _dump(obj, out: TextIO) -> None:
    print(json.dumps(obj, ensure_ascii=False, indent=2), file=out)


def _require_online(args, what: str) -> None:
    if not args.online:
        raise UsageError(
            f"{what} wymaga ruchu sieciowego. Domyślnie org-intel działa offline: dodaj --online, aby go zezwolić."
        )


# --- polecenia ----------------------------------------------------------------------


def cmd_ingest(args, out: TextIO, now: datetime | None) -> int:
    store = Store.load(args.store, audit_mode=args.audit_mode)
    try:
        result = parsers.parse_file(args.file, known_orgs=list(store.organizations.values()), now=now)
    except parsers.ParseError as exc:
        raise UsageError(str(exc)) from None
    summary = store.apply(result, now=now)
    store.save()
    return _report_ingest(args.file.name, result, summary, args.store, out)


def _report_ingest(origin: str, result: parsers.ParseResult, summary, store_path: Path, out: TextIO) -> int:
    print(f"Import {origin} (format: {result.format})", file=out)
    print(
        f"Zaakceptowano: {result.accepted_count} encji "
        f"(organizacje {len(result.organizations)}, domeny {len(result.domains)}, "
        f"osoby {len(result.persons)}, incydenty {len(result.incidents)}); "
        f"obserwacji: {len(result.observations)}; odrzucono: {len(result.rejections)}",
        file=out,
    )
    print("Nowe w magazynie: " + (", ".join(f"{k} {v}" for k, v in sorted(summary.added.items())) or "brak"), file=out)
    for w in result.warnings:
        print(f"  uwaga: {w.label}: {w.reason}", file=out)
    for text in summary.warnings:
        print(f"  uwaga: {text}", file=out)
    for r in result.rejections:
        print(f"  ODRZUCONO {r.label}: {r.reason}", file=out)
    if summary.raw_file:
        print(f"Tryb audytowy: surowe rekordy zapisano w {summary.raw_file}", file=out)
    print(f"Magazyn: {store_path}", file=out)
    return EXIT_PARTIAL if result.rejections else EXIT_OK


def _fmt_links(title: str, links, out: TextIO, name) -> None:
    if not links:
        return
    print(f"  {title}:", file=out)
    for ln in links:
        print(
            f"    - {name(ln.entity)} [{ln.derivation.value}, pewność {ln.confidence.value}] "
            f"({ln.via}; źródła: {', '.join(ln.source_ids) or 'brak'})",
            file=out,
        )


def cmd_search_company(args, out: TextIO, now: datetime | None) -> int:
    store = Store.load(args.store)
    try:
        views = correlate.search_company(store, args.query)
    except ValueError as exc:
        raise UsageError(str(exc)) from None
    if args.json:
        _dump({"query": args.query, "results": [v.to_dict() for v in views]}, out)
        return EXIT_OK
    if not views:
        print(f"Brak wyników dla: {args.query}", file=out)
        return EXIT_OK
    for v in views:
        o = v.organization
        ids = ", ".join(f"{k.upper()} {val}" for k, val in (("krs", o.krs), ("nip", o.nip), ("regon", o.regon)) if val)
        print(f"{o.legal_name}  [{o.id}]  pewność {v.confidence.value}", file=out)
        if ids:
            print(f"  {ids}", file=out)
        if o.previous_names:
            print(f"  poprzednie nazwy: {'; '.join(o.previous_names)}", file=out)
        if o.status:
            raw = f" (rejestr: {o.status_raw})" if o.status_raw and o.status_raw != o.status else ""
            print(f"  status: {o.status}{raw}", file=out)
        if o.registered_address:
            print(f"  adres siedziby: {o.registered_address}", file=out)
        _fmt_links("domeny", v.domains, out, lambda d: f"{d.domain} ({d.verification_status.value})")
        _fmt_links("osoby publiczne", v.persons, out, lambda p: f"{p.name}" + (f", {p.role}" if p.role else ""))
        _fmt_links("incydenty", v.incidents, out, lambda i: f"{i.name} ({i.incident_date or 'brak daty'})")
        print("  źródła:", file=out)
        for s in v.sources:
            print(
                f"    - {s.name} <{s.url}> [{s.source_type.value}, pobrano {s.retrieved_at}, licencja: "
                f"{s.license or 'brak'}]",
                file=out,
            )
    return EXIT_OK


def cmd_incidents(args, out: TextIO, now: datetime | None) -> int:
    try:
        domain = normalize_domain(args.domain)
    except ValueError as exc:
        raise UsageError(str(exc)) from None
    store = Store.load(args.store)
    links = correlate.incidents_for_domain(store, domain)
    if args.json:
        _dump({"domain": domain, "incidents": [x.to_dict() for x in links]}, out)
        return EXIT_OK
    if not links:
        print(f"Brak incydentów dla {domain}", file=out)
        return EXIT_OK
    print(f"Incydenty dla {domain}:", file=out)
    for ln in links:
        i = ln.entity
        print(
            f"  - {i.name} ({i.incident_date or 'brak daty'}) [{ln.derivation.value}, pewność {ln.confidence.value}] "
            f"status: {', '.join(s.value for s in i.status) or 'brak'}; źródła: {', '.join(ln.source_ids)}",
            file=out,
        )
    return EXIT_OK


def cmd_export(args, out: TextIO, now: datetime | None) -> int:
    store = Store.load(args.store)
    if args.format == "json":
        path = export.export_json(store, args.out, include_emails=args.include_emails, now=now)
        print(f"Zapisano {path}", file=out)
    else:
        files = export.export_csv(store, args.out, include_emails=args.include_emails)
        print(f"Zapisano {len(files)} plików w {args.out}", file=out)
    if not args.include_emails:
        print("Adresy e-mail osób zamaskowane (użyj --include-emails, aby je wyeksportować).", file=out)
    return EXIT_OK


def cmd_verify_domain(
    args, out: TextIO, now: datetime | None, resolver: verify.Resolver | None, client: Client | None
) -> int:
    if args.check:
        _require_online(args, "Sprawdzenie rekordu TXT (--check)")
    try:
        domain = normalize_domain(args.domain)
    except ValueError as exc:
        raise UsageError(str(exc)) from None
    store = Store.load(args.store)
    try:
        if not args.check:
            issued = verify.issue_token(store, domain, now=now)
            store.save()
            print(issued.instruction(), file=out)
            return EXIT_OK
        status = verify.check(store, domain, resolver or verify.DohResolver(client), now=now)
    except verify.VerificationError as exc:
        raise UsageError(str(exc)) from None
    store.save()
    if status is VerificationStatus.VERIFIED:
        print(f"Domena {domain}: zweryfikowana.", file=out)
        return EXIT_OK
    print(
        f"Domena {domain}: weryfikacja nieudana (brak pasującego rekordu TXT). "
        f"Dodaj rekord i ponów: org-intel verify-domain {domain} --check --online",
        file=out,
    )
    return EXIT_OK


def cmd_fetch_hibp(args, out: TextIO, now: datetime | None, client: Client | None) -> int:
    _require_online(args, "Pobranie katalogu HIBP")
    if not args.user_agent or not args.user_agent.strip():
        raise UsageError('HIBP wymaga User-Agent: podaj --user-agent "nazwa-firmy org-intel/0.1 (kontakt)".')
    store = Store.load(args.store, audit_mode=args.audit_mode)
    try:
        connector = HibpCatalogClient(args.user_agent, args.store.parent / "cache", client=client)
    except ConfigError as exc:
        raise UsageError(str(exc)) from None
    fetched = connector.fetch(refresh=args.refresh)
    retrieved = datetime.fromtimestamp(fetched.fetched_at, UTC)
    meta = parsers.CatalogMeta(
        content_hash=fetched.content_hash,
        origin="cache (TTL 24 h)" if fetched.from_cache else "online",
        etag=fetched.etag,
        last_modified=fetched.last_modified,
    )
    try:
        result = parsers.parse_text(fetched.text, now=retrieved, meta=meta)
    except parsers.ParseError as exc:
        raise UsageError(
            f"Odpowiedź HIBP nie jest katalogiem: {exc} (odrzucono przy minimalizacji: {len(fetched.rejected)})"
        ) from None
    result.rejections.extend(parsers.Rejection(r.get("label", "?"), r.get("reason", "?")) for r in fetched.rejected)
    summary = store.apply(result, now=now)
    store.save()
    print("Źródło: " + ("cache (TTL 24 h)" if fetched.from_cache else "pobrano z HIBP"), file=out)
    return _report_ingest("katalog HIBP", result, summary, args.store, out)


# --- main ------------------------------------------------------------------------------------


def main(
    argv: Sequence[str] | None = None,
    *,
    client: Client | None = None,
    resolver: verify.Resolver | None = None,
    out: TextIO | None = None,
    now: datetime | None = None,
) -> int:
    if out is None:
        out = sys.stdout
        for stream in (sys.stdout, sys.stderr):
            if hasattr(stream, "reconfigure"):
                stream.reconfigure(encoding="utf-8", errors="replace")
    args = build_parser().parse_args(argv)  # bledy skladni -> SystemExit(2)
    root = logging.getLogger("org_intel")
    if not root.handlers:
        root.addHandler(make_handler(sys.stderr, logging.WARNING))
        root.setLevel(logging.INFO)
    try:
        if args.command == "ingest":
            return cmd_ingest(args, out, now)
        if args.command == "search-company":
            return cmd_search_company(args, out, now)
        if args.command == "incidents":
            return cmd_incidents(args, out, now)
        if args.command == "export":
            return cmd_export(args, out, now)
        if args.command == "verify-domain":
            return cmd_verify_domain(args, out, now, resolver, client)
        if args.command == "fetch-hibp-catalog":
            return cmd_fetch_hibp(args, out, now, client)
    except UsageError as exc:
        print(f"Błąd: {exc}", file=sys.stderr)
        return EXIT_USAGE
    except StoreError as exc:
        print(f"Błąd: {exc}", file=sys.stderr)
        return EXIT_USAGE
    except NetworkError as exc:
        print(f"Błąd sieci: {exc}", file=sys.stderr)
        return EXIT_NETWORK
    return EXIT_USAGE
