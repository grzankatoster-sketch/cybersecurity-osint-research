"""CLI: python -m site_audit adres [--json] [--html plik] [--timeout 8] [--budget 60] [--no-extra]"""

from __future__ import annotations

import argparse
import math
import os
import sys
import tempfile
from pathlib import Path

from .analyze import analyze
from .collector import collect
from .fetch import Fetcher
from .report import build_report, render_html, render_json, render_text
from .target import TargetError, parse_target, system_resolver


def _positive_finite(raw: str) -> float:
    try:
        value = float(raw)
    except ValueError as exc:
        raise argparse.ArgumentTypeError(f"nieprawidłowa liczba: {raw!r}") from exc
    if not math.isfinite(value) or value <= 0:
        raise argparse.ArgumentTypeError(f"wartość musi być skończona i większa od 0 (podano {raw!r})")
    return value


def _positive_int(raw: str) -> int:
    try:
        value = int(raw)
    except ValueError as exc:
        raise argparse.ArgumentTypeError(f"nieprawidłowa liczba całkowita: {raw!r}") from exc
    if value <= 0:
        raise argparse.ArgumentTypeError(f"wartość musi być większa od 0 (podano {raw!r})")
    return value


def write_atomic(path: str, content: str) -> None:
    """Zapis przez plik tymczasowy w tym samym katalogu + os.replace: brak czesciowych plikow."""
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
        prog="python -m site_audit",
        description="Audyt jawnej konfiguracji strony WWW: przekierowania, TLS, HSTS, CSP, nagłówki, ciasteczka, "
                    "security.txt, robots.txt, sitemap, mieszana treść. Kilka zwykłych żądań GET, bez skanowania; "
                    "używaj na stronach własnych lub za zgodą.",
    )
    p.add_argument("url", help="adres strony, np. example.com albo https://example.com/sklep")
    p.add_argument("--json", action="store_true", help="wynik jako JSON (zamiast tabeli tekstowej)")
    p.add_argument("--html", metavar="PLIK", help="zapisz raport HTML do pliku")
    p.add_argument("--timeout", type=_positive_finite, default=8.0, help="limit pojedynczej operacji sieciowej w s (domyślnie 8)")
    p.add_argument("--budget", type=_positive_finite, default=60.0, help="łączny limit czasu audytu w s (domyślnie 60)")
    p.add_argument("--max-bytes", type=_positive_int, default=2_000_000, help="limit pobranej treści na żądanie (domyślnie 2 MB)")
    p.add_argument("--no-extra", action="store_true", help="tylko strona główna: bez robots.txt, security.txt, sitemap")
    p.add_argument("--allow-private", action="store_true",
                   help="pozwól na adresy prywatne/lokalne (audyt własnej sieci); domyślnie blokowane")
    return p


def main(argv: list[str] | None = None, resolver=None) -> int:
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")
        except (AttributeError, ValueError):
            pass
    args = build_parser().parse_args(argv)
    try:
        target = parse_target(args.url)
    except TargetError as exc:
        print(f"Błąd: {exc}", file=sys.stderr)
        return 2
    fetcher = Fetcher(timeout=args.timeout, budget=args.budget, max_bytes=args.max_bytes,
                      allow_private=args.allow_private, resolver=resolver or system_resolver)
    data = collect(target, fetcher, extras=not args.no_extra,
                   progress=None if args.json else lambda m: print(m, file=sys.stderr))
    report = build_report(data, analyze(data))

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
    if html_error:
        return 1
    return 3 if data.main.response is None else 0
