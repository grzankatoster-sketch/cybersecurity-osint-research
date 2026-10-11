"""CLI: python -m hibp_monitor {breaches,password,domain-search} ..."""
from __future__ import annotations

import argparse
import getpass
import json
import sys
import time
import warnings
from pathlib import Path
from typing import Callable, Mapping, Sequence

from . import __version__
from .breaches import (
    Breach, DomainReport, check_domain, fetch_catalog, load_config, load_state, normalize_domain,
    safe_text, save_state, strip_html,
)
from .domain_search import MissingApiKey, domain_search, get_api_key
from .http import DEFAULT_USER_AGENT, Client, HibpError, HttpClient
from .passwords import check_password

EXIT_OK, EXIT_USAGE, EXIT_NETWORK = 0, 2, 3


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="hibp_monitor",
        description="Defensywny monitor Have I Been Pwned dla WLASNYCH domen i hasel (oficjalne API).",
    )
    p.add_argument("--version", action="version", version=f"hibp-monitor {__version__}")
    sub = p.add_subparsers(dest="command", required=True)

    b = sub.add_parser("breaches", help="nowe wycieki dla domen z config.toml (bez klucza API) lub katalog")
    b.add_argument("--config", type=Path, default=Path("config.toml"), help="plik konfiguracji (domyslnie config.toml)")
    b.add_argument("--state", type=Path, help="plik stanu (domyslnie z config.toml)")
    b.add_argument("--domain", action="append", default=[], help="domena zamiast listy z config.toml (mozna powtarzac)")
    b.add_argument("--user-agent", help="nadpisuje user_agent z konfiguracji")
    b.add_argument("--no-save", action="store_true", help="nie zapisuj stanu (podglad)")
    b.add_argument("--catalog", action="store_true", help="pokaz pelny katalog /breaches zamiast monitora domen")
    b.add_argument("--since", help="z --catalog: tylko wycieki z AddedDate >= YYYY-MM-DD")
    b.add_argument("--limit", type=int, default=20, help="z --catalog: maks. liczba pozycji (0 = wszystkie)")
    b.add_argument("--json", action="store_true", help="wynik jako JSON")

    pw = sub.add_parser("password", help="czy haslo jest w wyciekach (k-anonymity; haslo przez getpass)")
    pw.add_argument("--user-agent")
    pw.add_argument("--json", action="store_true")

    ds = sub.add_parser("domain-search", help="[platne] konta Twojej ZWERYFIKOWANEJ domeny w wyciekach")
    ds.add_argument("domain", help="domena zweryfikowana na Twoim koncie HIBP")
    ds.add_argument("--show-addresses", action="store_true", help="pokaz adresy (domyslnie tylko liczby)")
    ds.add_argument("--user-agent")
    ds.add_argument("--json", action="store_true")
    return p


def _dump(obj: object, out) -> None:
    print(json.dumps(obj, ensure_ascii=False, indent=2), file=out)


def _fmt_breach(b: Breach, out) -> None:
    flags = [f for f, on in (("zweryfikowany", b.is_verified), ("wrazliwy", b.is_sensitive),
                              ("wycofany", b.is_retired), ("spam", b.is_spam_list)) if on]
    print(safe_text(f"  - {b.title or b.name} [{b.name}]  wyciek: {b.breach_date or '?'}  "
                    f"dodano: {b.added_date[:10] or '?'}  kont: {b.pwn_count:,}".replace(",", " ")), file=out)
    if b.data_classes:
        print(safe_text(f"    dane: {', '.join(str(c) for c in b.data_classes)}"), file=out)
    if flags:
        print(f"    flagi: {', '.join(flags)}", file=out)
    desc = strip_html(b.description)
    if desc:
        print(safe_text(f"    {desc[:240]}{'...' if len(desc) > 240 else ''}"), file=out)


def _make_client(args: argparse.Namespace, client: Client | None, cfg_agent: str | None = None) -> Client:
    if client is not None:
        return client
    return HttpClient(args.user_agent or cfg_agent or DEFAULT_USER_AGENT)


def cmd_breaches(args, client, out, pause: Callable[[float], None]) -> int:
    cfg_agent = None
    if args.catalog:
        cat = fetch_catalog(_make_client(args, client))
        if args.since:
            cat = [b for b in cat if b.added_date[:10] >= args.since]
        cat.sort(key=lambda b: (b.added_date, b.name), reverse=True)
        shown = cat if args.limit == 0 else cat[: args.limit]
        if args.json:
            _dump(
                {"total": len(cat), "shown": len(shown), "breaches": [b.to_dict(with_description=True) for b in shown]},
                out,
            )
        else:
            print(f"Katalog HIBP: {len(cat)} wyciekow (pokazano {len(shown)}, od najnowszych)", file=out)
            for b in shown:
                _fmt_breach(b, out)
        return EXIT_OK

    if args.domain:
        try:
            domains = [normalize_domain(d) for d in args.domain]
        except ValueError as exc:
            raise HibpError(str(exc)) from None
        state_path = args.state or Path("state.json")
    else:
        cfg = load_config(args.config)
        domains, cfg_agent = cfg["domains"], cfg["user_agent"]
        state_path = args.state or cfg["state_file"]
    if not domains:
        raise HibpError("Brak domen do sprawdzenia: wpisz je w config.toml (domains = [...]) lub uzyj --domain.")

    http = _make_client(args, client, cfg_agent)
    state = load_state(state_path)
    reports: list[DomainReport] = []
    for i, d in enumerate(domains):
        if i:
            pause(1.6)  # grzecznie wzgledem limitu zapytan
        reports.append(check_domain(http, state, d))
    if not args.no_save:
        save_state(state_path, state)

    if args.json:
        _dump({"state_file": None if args.no_save else str(state_path), "domains": [
            {"domain": r.domain, "first_run": r.first_run, "total_breaches": r.total,
             "new": [b.to_dict(with_description=True) for b in r.new]} for r in reports]}, out)
        return EXIT_OK
    for r in reports:
        if r.first_run:
            print(f"{r.domain}: pierwsze uruchomienie (baseline), wyciekow zrodlowych: {r.total}", file=out)
        elif r.new:
            print(f"{r.domain}: NOWE wycieki od ostatniego uruchomienia: {len(r.new)} (lacznie {r.total})", file=out)
        else:
            print(f"{r.domain}: brak nowych wyciekow (lacznie {r.total})", file=out)
        for b in r.new:
            _fmt_breach(b, out)
    print(("Stan NIE zapisany (--no-save)." if args.no_save else f"Stan zapisano: {state_path}"), file=out)
    return EXIT_OK


def _secure_getpass(prompt: str) -> str:
    """getpass, ktory przerywa, gdy terminal nie pozwala ukryc echa (GetPassWarning), zamiast pokazac haslo."""
    with warnings.catch_warnings():
        warnings.simplefilter("error", getpass.GetPassWarning)
        try:
            return getpass.getpass(prompt)
        except getpass.GetPassWarning:
            raise HibpError(
                "Terminal nie pozwala ukryc wpisywanego hasla (brak kontroli echa). "
                "Uruchom polecenie w prawdziwym terminalu (nie w potoku/IDE)."
            ) from None


def cmd_password(args, client, out, getpass_fn: Callable[[str], str]) -> int:
    password = getpass_fn("Haslo (nie jest wyswietlane ani zapisywane): ")
    if not password:
        raise HibpError("Puste haslo.")
    count = check_password(_make_client(args, client), password)
    del password
    if args.json:
        _dump({"pwned": count > 0, "count": count}, out)
    elif count:
        print(f"UWAGA: to haslo wystapilo w wyciekach {count:,} razy. Nie uzywaj go.".replace(",", " "), file=out)
    else:
        print("Haslo nie wystepuje w znanych wyciekach Pwned Passwords (to nie dowod, ze jest silne).", file=out)
    return EXIT_OK


def cmd_domain_search(args, client, out, environ: Mapping[str, str] | None) -> int:
    key = get_api_key(environ)  # najpierw klucz: bez niego zadnego ruchu sieciowego
    res = domain_search(_make_client(args, client), args.domain, key, args.show_addresses)
    if args.json:
        _dump(res.to_dict(), out)
        return EXIT_OK
    print(f"{res.domain}: kont z wyciekow: {res.total_accounts}", file=out)
    for name, n in res.per_breach.items():
        print(safe_text(f"  - {name}: {n}"), file=out)
    if res.addresses is not None:
        print("Adresy:", file=out)
        for alias, brs in sorted(res.addresses.items()):
            print(safe_text(f"  {alias}@{res.domain}: {', '.join(brs)}"), file=out)
    elif res.total_accounts:
        print("Adresy ukryte (dodaj --show-addresses, jesli to Twoja domena).", file=out)
    return EXIT_OK


def main(
    argv: Sequence[str] | None = None,
    *,
    client: Client | None = None,
    getpass_fn: Callable[[str], str] = _secure_getpass,
    environ: Mapping[str, str] | None = None,
    out=None,
    pause: Callable[[float], None] = time.sleep,
) -> int:
    if out is None:
        out = sys.stdout
        try:
            sys.stdout.reconfigure(encoding="utf-8")
        except (AttributeError, ValueError):
            pass
    args = build_parser().parse_args(argv)
    try:
        if args.command == "breaches":
            return cmd_breaches(args, client, out, pause)
        if args.command == "password":
            return cmd_password(args, client, out, getpass_fn)
        return cmd_domain_search(args, client, out, environ)
    except MissingApiKey as exc:
        print(safe_text(exc), file=sys.stderr)
        return EXIT_USAGE
    except ValueError as exc:
        print(safe_text(f"Blad: {exc}"), file=sys.stderr)
        return EXIT_USAGE
    except HibpError as exc:
        print(safe_text(f"Blad: {exc}"), file=sys.stderr)
        return EXIT_NETWORK if (exc.status or "sieci" in str(exc)) else EXIT_USAGE
