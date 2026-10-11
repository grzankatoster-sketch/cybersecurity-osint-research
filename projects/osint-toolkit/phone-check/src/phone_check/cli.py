import argparse
import csv
import json
import os
import sys
import tempfile
from pathlib import Path
from typing import Callable, TextIO

import phonenumbers

from .core import DEFAULT_LANG, DEFAULT_REGION, PhoneInfo, analyze, format_text, normalize_region
from .dorks import DORK_IMPOSSIBLE, dork_result

CSV_FIELDS = [
    "input", "valid", "possible", "region", "country_name", "country_code", "geo_description",
    "line_type", "carrier", "carrier_note", "carrier_check_url", "timezones", "e164",
    "international", "national", "rfc3966", "error",
]
# Pola PhoneInfo celowo nieobecne w CSV (sa w JSON): techniczne/duplikaty. Test pilnuje spojnosci.
CSV_EXCLUDED = ("region_hint", "parsed", "line_type_code")

# Pierwszy znak, ktory arkusz (Excel/LibreOffice) moze zinterpretowac jako formule.
_FORMULA_TRIGGERS = ("=", "+", "-", "@", "\t", "\r")


def read_numbers(path: Path) -> list[str]:
    """Jeden numer na linie; puste linie i komentarze (#) sa pomijane. Wymaga UTF-8 (BOM dozwolony)."""
    out = []
    for line in path.read_text(encoding="utf-8-sig").splitlines():
        line = line.strip()
        if line and not line.startswith("#"):
            out.append(line)
    return out


def csv_safe(value: str) -> str:
    """Neutralizacja formul w CSV: tekst zaczynajacy sie od = + - @ TAB CR dostaje prefiks apostrofu.

    Dotyczy tez numerow w formacie +48...; w CSV maja wiec prefiks '. JSON nie jest zmieniany.
    """
    if value and value[0] in _FORMULA_TRIGGERS:
        return "'" + value
    return value


def _same_path(a: Path, b: Path) -> bool:
    if os.path.normcase(str(a.resolve())) == os.path.normcase(str(b.resolve())):
        return True
    try:
        return a.exists() and b.exists() and os.path.samefile(a, b)
    except OSError:
        return False


def find_path_collision(paths: list[tuple[str, Path | None]]) -> str | None:
    """Zwraca komunikat, gdy dwie z podanych (opcja, sciezka) wskazuja ten sam plik; inaczej None."""
    given = [(name, p) for name, p in paths if p is not None]
    for i, (name_a, a) in enumerate(given):
        for name_b, b in given[i + 1 :]:
            if _same_path(a, b):
                return f"{name_a} i {name_b} wskazują ten sam plik (ta sama ścieżka): {a}"
    return None


def _atomic_write(path: Path, write_fn: Callable[[TextIO], None], *, encoding: str, newline: str | None = None) -> None:
    """Zapis do pliku tymczasowego w tym samym katalogu, potem os.replace (atomowo)."""
    path = Path(path)
    fd, tmp = tempfile.mkstemp(dir=path.parent, prefix=f".{path.name}.", suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding=encoding, newline=newline) as fh:
            write_fn(fh)
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def write_json(path: Path, infos: list[PhoneInfo]) -> None:
    text = json.dumps([i.to_dict() for i in infos], ensure_ascii=False, indent=2)
    _atomic_write(path, lambda fh: fh.write(text), encoding="utf-8")


def _csv_row(info: PhoneInfo) -> dict[str, object]:
    d = info.to_dict()
    d["timezones"] = ",".join(info.timezones)
    row: dict[str, object] = {}
    for field in CSV_FIELDS:
        v = d[field]
        row[field] = "" if v is None else csv_safe(v) if isinstance(v, str) else v
    return row


def write_csv(path: Path, infos: list[PhoneInfo]) -> None:
    def _write(fh: TextIO) -> None:
        w = csv.DictWriter(fh, fieldnames=CSV_FIELDS, delimiter=";")
        w.writeheader()
        for i in infos:
            w.writerow(_csv_row(i))

    # BOM: Excel czyta polskie znaki
    _atomic_write(path, _write, encoding="utf-8-sig", newline="")


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="phone-check",
        description="Offline walidator numeru telefonu (plan numeracji). Bez zapytań do sieci.",
    )
    p.add_argument("number", nargs="?", help="numer w dowolnym formacie (w cudzysłowie, jeśli ze spacjami)")
    p.add_argument("--region", default=DEFAULT_REGION,
                   help=f"domyślny kraj dla numerów bez +, ISO (domyślnie {DEFAULT_REGION})")
    p.add_argument("--file", type=Path, help="plik: jeden numer na linię (tryb wsadowy)")
    p.add_argument("--json", type=Path, dest="json_out", help="zapisz wynik do pliku JSON")
    p.add_argument("--csv", type=Path, dest="csv_out", help="zapisz wynik do pliku CSV (separator ;)")
    p.add_argument("--dorks", action="store_true",
                   help="wypisz warianty zapisu w cudzysłowie do ręcznego wyszukania (nic nie wysyła)")
    p.add_argument("--lang", default=DEFAULT_LANG, help=f"język opisów geograficznych (domyślnie {DEFAULT_LANG})")
    return p


def main(argv: list[str] | None = None) -> int:
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8")
        except (AttributeError, ValueError):
            pass
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.number and args.file:
        parser.error("numer pozycyjny i --file wykluczają się wzajemnie: podaj jedno z nich.")

    region = normalize_region(args.region)
    if region not in phonenumbers.SUPPORTED_REGIONS:
        print(
            f"Błąd: nieznany region --region {region}: podaj dwuliterowy kod ISO kraju, np. PL, DE, GB. "
            "Nic nie sprawdzono.",
            file=sys.stderr,
        )
        return 2

    collision = find_path_collision([("--file", args.file), ("--json", args.json_out), ("--csv", args.csv_out)])
    if collision:
        print(f"Błąd: {collision}. Nic nie zapisano.", file=sys.stderr)
        return 2

    if args.file:
        try:
            numbers = read_numbers(args.file)
        except UnicodeError:
            print(f"Błąd odczytu pliku {args.file}: wymagane kodowanie UTF-8 (z BOM lub bez).", file=sys.stderr)
            return 2
        except OSError as exc:
            print(f"Błąd odczytu pliku: {exc}", file=sys.stderr)
            return 2
        if not numbers:
            print(f"Błąd: plik {args.file} nie zawiera żadnych numerów (puste linie i # są pomijane).",
                  file=sys.stderr)
            return 2
    elif args.number:
        numbers = [args.number]
    else:
        parser.print_usage(sys.stderr)
        print("Podaj numer albo --file.", file=sys.stderr)
        return 2

    infos = [analyze(n, args.region, args.lang) for n in numbers]
    batch = args.file is not None

    for info in infos:
        if batch and (args.json_out or args.csv_out):
            if info.valid:
                status, detail = "OK  ", info.e164
            else:
                status = "BLAD"
                detail = f"{info.error} (E.164: {info.e164})" if info.e164 else info.error
            print(f"[{status}] {info.input} -> {detail}")
        else:
            print(format_text(info))
            print()
        if args.dorks:
            res = dork_result(info.input, args.region)
            if res.variants:
                print("Warianty do ręcznego wyszukania:")
            elif res.reason == DORK_IMPOSSIBLE:
                print("Brak wariantów (numer sparsowany, ale niemożliwa długość).")
            else:
                print("Brak wariantów (numer nie do sparsowania).")
            for v in res.variants:
                print(f"  {v}")
            print()

    saved: list[str] = []
    failed: list[str] = []
    for label, path, writer in (("JSON", args.json_out, write_json), ("CSV", args.csv_out, write_csv)):
        if not path:
            continue
        try:
            writer(path, infos)
        except OSError as exc:
            failed.append(label)
            print(f"Błąd zapisu {label} ({path}): {exc}", file=sys.stderr)
        else:
            saved.append(label)
            print(f"Zapisano {label}: {path}")
    if batch:
        ok = sum(1 for i in infos if i.valid)
        print(f"Razem: {len(infos)}, poprawnych: {ok}, niepoprawnych: {len(infos) - ok}")
    if failed:
        if saved:
            print(f"Eksport częściowy: zapisano {', '.join(saved)}; nie zapisano {', '.join(failed)}.",
                  file=sys.stderr)
        else:
            print("Błąd: żaden eksport nie został zapisany.", file=sys.stderr)
        return 2
    return 0 if all(i.valid for i in infos) else 1
