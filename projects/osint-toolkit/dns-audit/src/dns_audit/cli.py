"""CLI: python -m dns_audit domena [--json] [--selectors a,b] [--resolver 1.1.1.1] [--html plik]"""

from __future__ import annotations

import argparse
import math
import os
import re
import sys
import tempfile
from pathlib import Path

from .analyze import analyze
from .collector import collect, merge_selectors
from .report import build_report, render_html, render_json, render_text
from .resolver import DnsPythonResolver, DohResolver, preflight

DEFAULT_DOH = "https://cloudflare-dns.com/dns-query"  # Quad9 odrzuca HTTP/1.1 (505); Mullvad DoH nie odpowiada przez Tora

_LABEL_RE = re.compile(r"^(?!-)[a-z0-9-]{1,63}(?<!-)$")


def normalize_domain(raw: str) -> str:
    d = raw.strip().lower()
    d = re.sub(r"^[a-z][a-z0-9+.-]*://", "", d)
    d = d.split("/")[0].split("?")[0].split("#")[0]
    if "@" in d:
        d = d.rsplit("@", 1)[1]
    d = d.split(":")[0].rstrip(".")
    try:
        d = d.encode("idna").decode("ascii")
    except UnicodeError as exc:
        raise ValueError(f"nieprawidłowa domena: {raw!r}") from exc
    labels = d.split(".")
    if len(d) > 253 or len(labels) < 2 or not all(_LABEL_RE.match(x) for x in labels):
        raise ValueError(f"nieprawidłowa domena: {raw!r}")
    return d


def _positive_finite(raw: str) -> float:
    try:
        value = float(raw)
    except ValueError as exc:
        raise argparse.ArgumentTypeError(f"nieprawidłowa liczba: {raw!r}") from exc
    if not math.isfinite(value) or value <= 0:
        raise argparse.ArgumentTypeError(f"timeout musi być skończony i większy od 0 (podano {raw!r})")
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
        prog="python -m dns_audit",
        description="Audyt DNS i konfiguracji poczty domeny (SPF, DMARC, DKIM, DNSSEC, MTA-STS, CAA...). "
                    "Tylko publiczne rekordy DNS; używaj na domenach własnych lub jawnych.",
    )
    p.add_argument("domain", help="domena do sprawdzenia, np. example.com")
    p.add_argument("--json", action="store_true", help="wynik jako JSON (zamiast tabeli tekstowej)")
    p.add_argument("--selectors", default="", help="własne selektory DKIM, po przecinku (dodawane do domyślnych)")
    p.add_argument("--only-selectors", action="store_true", help="sprawdź tylko selektory z --selectors")
    p.add_argument("--resolver", default=None, help="adres IP resolvera, np. 1.1.1.1 (domyślnie systemowy)")
    p.add_argument("--html", metavar="PLIK", help="zapisz raport HTML do pliku")
    g = p.add_mutually_exclusive_group()
    g.add_argument("--proxy", default=None, metavar="URL",
                   help="tryb OPSEC: zapytania jako DNS-over-HTTPS przez proxy SOCKS5, np. socks5h://127.0.0.1:9150 "
                        "(Tor); domyślnie zmienna OSINT_PROXY")
    g.add_argument("--direct", action="store_true", help="ignoruj OSINT_PROXY: zapytania bezpośrednie (resolver widzi domenę)")
    p.add_argument("--doh", default=DEFAULT_DOH, metavar="URL", help=f"serwer DoH używany z proxy (domyślnie {DEFAULT_DOH})")
    p.add_argument("--timeout", type=_positive_finite, default=4.0, help="timeout pojedynczego zapytania w sekundach (domyślnie 4)")
    return p


def main(argv: list[str] | None = None, resolver=None) -> int:
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")
        except (AttributeError, ValueError):
            pass
    args = build_parser().parse_args(argv)
    try:
        domain = normalize_domain(args.domain)
    except ValueError as exc:
        print(f"Błąd: {exc}", file=sys.stderr)
        return 2
    custom = [s for s in args.selectors.split(",") if s.strip()]
    selectors = merge_selectors(custom, use_defaults=not args.only_selectors)
    if args.only_selectors and not selectors:
        print("Błąd: --only-selectors wymaga --selectors", file=sys.stderr)
        return 2
    if resolver is None:
        proxy = None if args.direct else (args.proxy or os.environ.get("OSINT_PROXY", "").strip() or None)
        try:
            if proxy:
                if args.resolver:
                    print("Błąd: --resolver jest niezgodny z proxy (zwykły DNS nie przejdzie przez Tor); "
                          "użyj --direct albo usuń --resolver", file=sys.stderr)
                    return 2
                # Tor jest wolniejszy niż zwykły DNS: timeout co najmniej 10 s
                resolver = DohResolver(args.doh, proxy, timeout=max(args.timeout, 10.0))
            else:
                resolver = DnsPythonResolver(args.resolver, timeout=args.timeout, lifetime=args.timeout * 2)
        except ValueError as exc:
            print(f"Błąd: {exc}", file=sys.stderr)
            return 2
        if proxy:
            print(f"Kanał: DoH przez proxy {resolver.description}", file=sys.stderr)
            problem = preflight(resolver)
            if problem:
                resolver.close()
                print(f"Proxy/DoH niedostępne ({problem}) — audyt przerwany, zero zapytań bezpośrednich.", file=sys.stderr)
                return 3
        else:
            print("Kanał: bezpośrednio (resolver widzi audytowaną domenę)", file=sys.stderr)

    try:
        data = collect(
            domain, resolver, selectors,
            progress=None if args.json else lambda m: print(m, file=sys.stderr),
            explicit_selectors=custom,
        )
    finally:
        if hasattr(resolver, "close"):
            resolver.close()
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
    return 1 if html_error else 0
