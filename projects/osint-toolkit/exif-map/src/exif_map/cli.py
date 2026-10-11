from __future__ import annotations

import argparse
import sys
from pathlib import Path

from . import __version__, mapview, report, reverse, strip
from .reader import iter_files, scan


def _write(dest: str, text: str) -> None:
    if dest == "-":
        sys.stdout.write(text + ("\n" if not text.endswith("\n") else ""))
    else:
        p = Path(dest)
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text, encoding="utf-8-sig" if p.suffix.lower() == ".csv" else "utf-8")


def build_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(
        prog="exif-map",
        description="Metadane i geotagi WLASNYCH zdjec/plikow (analiza lokalna, bez sieci, bez rozpoznawania twarzy).",
    )
    ap.add_argument("path", help="plik albo folder (rekurencyjnie: jpg, jpeg, png, heic*, tif, tiff)")
    ap.add_argument("--json", nargs="?", const="-", metavar="PLIK", help="wynik JSON (bez PLIK: na stdout)")
    ap.add_argument("--csv", nargs="?", const="-", metavar="PLIK", help="wynik CSV (bez PLIK: na stdout)")
    ap.add_argument("--map", metavar="PLIK.html", help="mapa HTML: znaczniki z miniaturami + trasa wg czasu")
    ap.add_argument("--no-tiles", action="store_true",
                    help="mapa bez kafelkow OpenStreetMap (sama siatka punktow i trasa); Leaflet nadal z CDN")
    ap.add_argument("--strip", metavar="FOLDER", help="zapisz KOPIE bez metadanych do FOLDER (oryginaly nietkniete)")
    ap.add_argument("--reverse", action="store_true",
                    help="instrukcja recznego wyszukiwania obrazem (TinEye, Google Lens, Bing, Yandex); nic nie wysyla")
    ap.add_argument("--no-exiftool", action="store_true", help="nie uzywaj exiftool, nawet jesli jest dostepny")
    ap.add_argument("--quiet", action="store_true", help="bez tabeli (tylko ostrzezenia i podsumowanie)")
    ap.add_argument("--version", action="version", version=f"exif-map {__version__}")
    return ap


def main(argv: list[str] | None = None) -> int:
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8")
        except Exception:
            pass
    args = build_parser().parse_args(argv)
    target = Path(args.path)
    if not target.exists():
        print(f"BLAD: nie istnieje: {target}", file=sys.stderr)
        return 2

    out_dir = Path(args.strip) if args.strip else None
    files = list(iter_files(target, exclude_dir=out_dir))
    if not files:
        print("Brak obslugiwanych plikow (jpg, jpeg, png, heic, tif).", file=sys.stderr)
        return 1

    items, exe = scan(files, use_exiftool=not args.no_exiftool)
    base = target if target.is_dir() else target.parent
    stdout_used = args.json == "-" or args.csv == "-"
    info = sys.stderr if stdout_used else sys.stdout  # dane na stdout nie moga mieszac sie z komentarzem

    if args.json:
        _write(args.json, report.to_json(items))
    if args.csv:
        _write(args.csv, report.to_csv(items))
    if not stdout_used and not args.quiet:
        print(report.render_table(items, base), file=info)
        print(file=info)
    warn = report.render_warnings(items, base)
    if warn:
        print(warn, file=info)
    print(report.render_summary(items, exe), file=info)

    if args.map:
        n = mapview.build_map(items, Path(args.map), tiles=not args.no_tiles)
        if n:
            print(f"Mapa: {args.map} ({n} znacznikow). Uwaga: zawiera lokalizacje, nie publikuj.", file=info)
            suspicious = mapview.count_suspicious(items)
            if suspicious > 0:
                print(f"  podejrzane wspolrzedne: {suspicious} (pomaranczowe znaczniki, mozliwy placeholder)", file=info)
        else:
            print("Mapa nie powstala: zaden plik nie ma GPS.", file=info)

    if out_dir is not None:
        results = strip.strip_all(target, out_dir)
        ok = [r for r in results if r.output and not r.error]
        print(f"\nStrip: {len(ok)}/{len(results)} plikow zapisanych w {out_dir} (oryginaly nietkniete).", file=info)
        for r in results:
            if r.error:
                print(f"  BLAD {r.source}: {r.error}", file=info)
            elif not r.verified:
                print(f"  UWAGA {r.output}: nadal zawiera: {', '.join(r.leftovers or [])}", file=info)
            else:
                usunieto = ", ".join(r.removed) if r.removed else "nic (brak metadanych)"
                print(
                    f"  OK {Path(r.output).name} [{r.method}], weryfikacja: brak metadanych; usunieto: {usunieto}",
                    file=info,
                )
        strip_failed = len(ok) != len(results) or any(not r.verified for r in ok)
    else:
        strip_failed = False

    if args.reverse:
        # po nieudanym strip nie wskazujemy folderu jako bezpiecznego do wgrania
        clean_dir = out_dir if out_dir is not None and not strip_failed else None
        print("\n" + reverse.render_guide(items, base, clean_dir), file=info)
    return 3 if strip_failed else 0
