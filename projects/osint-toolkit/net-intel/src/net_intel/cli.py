"""CLI: python -m net_intel {ip|rdap|subdomains} CEL [--json] [--html plik] [--timeout S]

Kody wyjścia: 0 = sprawdzono, bez ustaleń WARN/FAIL; 1 = ustalenia WARN/FAIL, nie udało się sprawdzić
(wszystkie źródła zawiodły) albo błąd zapisu raportu HTML; 2 = błąd użycia (zły adres/domena/opcja).
"""

from __future__ import annotations

import argparse
import math
import os
import sys
import tempfile
from datetime import date, datetime
from pathlib import Path
from typing import Callable

from .domain import normalize_domain
from .http import Fetch, urllib_fetch
from .ipinfo import TOKEN_ENV, fetch_ipinfo, local_scope, parse_ip, reverse_lookup
from .rdap import RdapError, lookup
from .report import (
    Report, build_ip_report, build_rdap_failed_report, build_rdap_report, build_subdomains_report,
    render_html, render_json, render_text,
)
from .subdomains import MAX_RESOLVE, enumerate_subdomains, resolve_entries, system_resolve


def _positive_finite(raw: str) -> float:
    try:
        value = float(raw)
    except ValueError as exc:
        raise argparse.ArgumentTypeError(f"nieprawidłowa liczba: {raw!r}") from exc
    if not math.isfinite(value) or value <= 0:
        raise argparse.ArgumentTypeError(f"timeout musi być skończony i większy od 0 (podano {raw!r})")
    return value


def _workers(raw: str) -> int:
    try:
        value = int(raw)
    except ValueError as exc:
        raise argparse.ArgumentTypeError(f"nieprawidłowa liczba: {raw!r}") from exc
    if not 1 <= value <= 50:
        raise argparse.ArgumentTypeError("współbieżność: zakres 1-50")
    return value


def write_atomic(path: str, content: str) -> None:
    """Zapis przez plik tymczasowy w tym samym katalogu + os.replace: brak częściowych plików."""
    target = Path(path)
    fd, tmp = tempfile.mkstemp(dir=target.parent, prefix=f".{target.name}.", suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(content)
        os.replace(tmp, target)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="python -m net_intel",
        description="Pasywny wywiad o jawnej infrastrukturze: adres IP, RDAP domeny, subdomeny. "
                    "Używaj na zasobach własnych, klientów (za zgodą) lub publicznych.",
    )
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--json", action="store_true", help="wynik jako JSON (zamiast tabeli tekstowej)")
    common.add_argument("--html", metavar="PLIK", help="zapisz raport HTML do pliku")
    common.add_argument("--timeout", type=_positive_finite, default=20.0,
                        help="timeout pojedynczego zapytania w sekundach (domyślnie 20)")
    sub = p.add_subparsers(dest="command", required=True, metavar="{ip,rdap,subdomains}")

    ip = sub.add_parser("ip", parents=[common], help="informacje o adresie IP (ipinfo.io + odwrotny DNS)",
                        description=f"Adres IP: ipinfo.io (opcjonalny token ze zmiennej {TOKEN_ENV}) i PTR z DNS.")
    ip.add_argument("target", metavar="IP", help="adres IPv4 lub IPv6")

    rd = sub.add_parser("rdap", parents=[common], help="RDAP domeny: rejestrator, daty, statusy, serwery nazw")
    rd.add_argument("target", metavar="domena", help="domena zarejestrowana, np. example.com")

    sd = sub.add_parser("subdomains", parents=[common], help="pasywne wyliczanie subdomen (HackerTarget, Cert Spotter, crt.sh)")
    sd.add_argument("target", metavar="domena", help="domena, np. example.com")
    sd.add_argument("--resolve", action="store_true", help="rozwiąż adresy A/AAAA znalezionych nazw (zapytania DNS systemowego resolvera)")
    sd.add_argument("--concurrency", type=_workers, default=10, help="współbieżność przy --resolve (1-50, domyślnie 10)")
    return p


def run_command(args: argparse.Namespace, *, fetch: Fetch, reverse: Callable | None, resolve: Callable | None,
                today: date | datetime | None) -> Report:
    if args.command == "ip":
        ip = args.target  # zwalidowany w main()
        note = local_scope(ip)
        if note:
            return build_ip_report(str(ip), note, None, "", None)
        token = os.environ.get(TOKEN_ENV, "").strip() or None
        info, err = fetch_ipinfo(str(ip), fetch, args.timeout, token)
        rev = (reverse or reverse_lookup)(str(ip), args.timeout)
        return build_ip_report(str(ip), None, info, err, rev)
    domain = args.target
    if args.command == "rdap":
        try:
            return build_rdap_report(lookup(domain, fetch, args.timeout, today))
        except RdapError as exc:
            return build_rdap_failed_report(domain, str(exc))
    result = enumerate_subdomains(domain, fetch, args.timeout)
    skipped = 0
    if args.resolve and not result.all_failed:
        skipped = resolve_entries(result, resolve or system_resolve, workers=args.concurrency,
                                  deadline=max(60.0, args.timeout * 3), limit=MAX_RESOLVE)
    return build_subdomains_report(result, skipped)


def main(argv: list[str] | None = None, *, fetch: Fetch | None = None, reverse: Callable | None = None,
         resolve: Callable | None = None, today: date | datetime | None = None) -> int:
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")
        except (AttributeError, ValueError):
            pass
    args = build_parser().parse_args(argv)  # błąd użycia: argparse kończy kodem 2
    try:
        args.target = parse_ip(args.target) if args.command == "ip" else normalize_domain(args.target)
    except ValueError as exc:
        print(f"Błąd: {exc}", file=sys.stderr)
        return 2
    report = run_command(args, fetch=fetch or urllib_fetch, reverse=reverse, resolve=resolve, today=today)

    html_error = None
    if args.html:
        try:
            write_atomic(args.html, render_html(report))
        except OSError as exc:
            html_error = exc
            print(f"Błąd zapisu raportu HTML ({args.html}): {exc}", file=sys.stderr)
    print(render_json(report) if args.json else render_text(report))
    if args.html and not args.json and html_error is None:
        print(f"\nZapisano raport HTML: {args.html}")
    return 1 if html_error else report.exit_code
