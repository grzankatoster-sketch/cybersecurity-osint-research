"""python -m meta_search <operacja> ...

Operacje: threads-profile NICK | threads-search FRAZA | instagram-profile NICK [--media N] |
facebook-page ID_LUB_NAZWA | links NICK | config
Kod wyjścia: 0 wynik/brak wyniku/linki, 1 błąd źródła, 2 błędne zapytanie, 3 brak konfiguracji,
4 token/uprawnienia, 5 limit zapytań."""
from __future__ import annotations

import argparse
import json
import os
import re
import sys
import tempfile
from pathlib import Path

from .config import load_config
from .contract import LABELS_PL, MetaResult
from .facebook_pages import FacebookPagesClient
from .instagram import MAX_MEDIA, InstagramClient
from .links import manual_links
from .report import render_html
from .threads import ThreadsClient

_CONTROL = re.compile(r"[\x00-\x1f\x7f-\x9f]")


def safe(value) -> str:
    return _CONTROL.sub(lambda m: f"\\x{ord(m.group()):02x}", str(value))


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="meta_search", description="Wyszukiwanie w serwisach Meta (oficjalne API).")
    sub = p.add_subparsers(dest="op", required=True)

    def outputs(sp):
        sp.add_argument("--json", dest="json_out", help="wynik do pliku JSON (kontrakt meta-search)")
        sp.add_argument("--html", dest="html_out", help="raport HTML")
        sp.add_argument("--timeout", type=float, default=15.0)

    sp = sub.add_parser("threads-profile", help="publiczny profil Threads po dokładnym nicku (API profile_lookup)")
    sp.add_argument("username")
    outputs(sp)
    sp = sub.add_parser("threads-search", help="publiczne posty Threads po frazie (API keyword_search)")
    sp.add_argument("query")
    sp.add_argument("--type", dest="search_type", choices=("TOP", "RECENT"), default="TOP")
    sp.add_argument("--mode", dest="search_mode", choices=("KEYWORD", "TAG"), default="KEYWORD")
    sp.add_argument("--limit", type=int, default=25, help="1-100 (jedna strona wyników)")
    sp.add_argument("--author", help="tylko posty tego nicku")
    outputs(sp)
    sp = sub.add_parser("instagram-profile", help="konto profesjonalne Instagram po nicku (Business Discovery)")
    sp.add_argument("username")
    sp.add_argument("--media", type=int, default=0, help=f"ile ostatnich mediów dołączyć (0-{MAX_MEDIA}, domyślnie 0)")
    outputs(sp)
    sp = sub.add_parser("facebook-page", help="publiczne dane Strony Facebooka po id lub nazwie (Graph API)")
    sp.add_argument("page")
    outputs(sp)
    sp = sub.add_parser("links", help="linki do ręcznego sprawdzenia nicku (Threads, Instagram, Facebook)")
    sp.add_argument("username")
    outputs(sp)
    sub.add_parser("config", help="stan konfiguracji (bez wartości tokenu)")
    sp = sub.add_parser("purge", help="retencja: usuwa wyniki meta_*.json/.html starsze niż N dni (domyślnie podgląd)")
    sp.add_argument("directory", help="katalog wyników, np. ../panel/wyniki")
    sp.add_argument("--days", type=int, default=30, help="wiek w dniach (1-3650, domyślnie 30)")
    sp.add_argument("--delete", action="store_true", help="naprawdę usuń (bez tej flagi tylko lista)")
    return p


PURGE_NAME = re.compile(r"^meta_[A-Za-z0-9._-]{1,200}\.(json|html)$")


def purge(directory: str, days: int, delete: bool, now: float | None = None) -> int:
    """Retencja (Meta Platform Terms: usuwać dane, gdy nie służą już celowi). Tylko zwykłe pliki meta_*.json/.html
    bezpośrednio w katalogu (bez podkatalogów i dowiązań); bez --delete wyłącznie lista do usunięcia."""
    import time
    if not 1 <= days <= 3650:
        print("--days: 1-3650", file=sys.stderr)
        return 2
    root = Path(directory)
    if not root.is_dir():
        print(f"brak katalogu: {safe(directory)}", file=sys.stderr)
        return 2
    limit = (now if now is not None else time.time()) - days * 86400
    old, failed = [], []
    for f in sorted(root.iterdir()):
        if not PURGE_NAME.match(f.name):
            continue
        try:                                   # plik zniknal lub jest zajety (Windows): pomin, raportuj, nie przerywaj
            if not (f.is_file() and not f.is_symlink() and f.stat().st_mtime < limit):
                continue
            if delete:
                f.unlink()
        except OSError:
            failed.append(f)
            continue
        old.append(f)
        print(f"{'usunięto' if delete else 'do usunięcia'}: {safe(f.name)}")
    for f in failed:
        print(f"nie udało się: {safe(f.name)}", file=sys.stderr)
    print(f"{'Usunięto' if delete else 'Do usunięcia'} {len(old)} plików starszych niż {days} dni"
          + ("" if delete else " (podgląd; dodaj --delete)"))
    return 1 if failed else 0


def _write(path: str, text: str) -> None:
    target = Path(path)
    fd, tmp = tempfile.mkstemp(dir=target.parent if str(target.parent) else ".", suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(text)
        os.replace(tmp, target)
    except BaseException:
        Path(tmp).unlink(missing_ok=True)
        raise


def print_result(res: MetaResult) -> None:
    print(f"[{LABELS_PL[res.status]}] {res.platform}/{res.operation}: {safe(res.query)}")
    print(f"  źródło: {res.source_kind.value} {res.endpoint}".rstrip())
    if res.message:
        print(f"  {safe(res.message)}")
    for it in res.items:
        if it["type"] == "profile":
            print(f"  @{safe(it['username'])} | {safe(it['name'])} | obserwujący: {it['follower_count']} | "
                  f"{it['profile_url']}")
        elif it["type"] == "post":
            print(f"  @{safe(it['username'])} {safe(it['timestamp'])}: {safe(it['text'][:120])} {safe(it['permalink'])}")
        elif it["type"] == "page":
            print(f"  {safe(it['name'])} | {safe(it['category'])} | fani: {it['fan_count']} | "
                  f"weryfikacja: {safe(it['verification_status'] or '-')} | {safe(it['link'])}")
        elif it["type"] == "link":
            print(f"  {safe(it['label'])}: {safe(it['url'])}")
    for c in res.caveats:
        print(f"  uwaga: {c}")


def main(argv: list[str] | None = None) -> int:
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")
        except (AttributeError, ValueError):
            pass
    args = build_parser().parse_args(argv)
    if args.op == "purge":
        return purge(args.directory, args.days, args.delete)
    cfg = load_config()
    if args.op == "config":
        print(json.dumps(cfg.describe(), ensure_ascii=False, indent=1))
        return 0
    if args.op == "threads-profile":
        res = ThreadsClient(cfg, timeout=args.timeout).profile(args.username)
    elif args.op == "threads-search":
        res = ThreadsClient(cfg, timeout=args.timeout).search(args.query, args.search_type, args.limit, args.author,
                                                              args.search_mode)
    elif args.op == "instagram-profile":
        res = InstagramClient(cfg, timeout=args.timeout).profile(args.username, args.media)
    elif args.op == "facebook-page":
        res = FacebookPagesClient(cfg, timeout=args.timeout).page(args.page)
    else:
        res = manual_links(args.username)
    print_result(res)
    failed = False
    for path, text in ((args.json_out, lambda: json.dumps(res.to_dict(), ensure_ascii=False, indent=1)),
                       (args.html_out, lambda: render_html(res))):
        if not path:
            continue
        try:
            _write(path, text())
            print(f"Zapisano: {Path(path).resolve()}")
        except OSError as exc:
            print(f"Błąd zapisu {safe(path)}: {type(exc).__name__}", file=sys.stderr)
            failed = True
    return res.exit_code or (1 if failed else 0)


if __name__ == "__main__":
    sys.exit(main())
