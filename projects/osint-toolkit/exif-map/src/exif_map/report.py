"""Wyjscia: tabela tekstowa, JSON, CSV."""

from __future__ import annotations

import csv
import io
import json
import os
import unicodedata
from pathlib import Path

from .gps import format_coords
from .models import GPS_WARNING, PhotoMeta

CSV_FIELDS = ["path", "taken", "taken_field", "camera", "make", "model", "software", "lat", "lon", "altitude",
              "direction", "width", "height", "has_gps", "source", "error"]


def _rel(path: str, base: Path | None) -> str:
    if base is None:
        return Path(path).name
    try:
        return os.path.relpath(path, base)
    except ValueError:
        return path


_BIDI = set(range(0x202A, 0x202F)) | set(range(0x2066, 0x206A))  # kierunkowe znaki sterujace Unicode (spoofing)
_FORMULA_PREFIXES = ("=", "+", "-", "@", "\t", "\r")


def safe_text(s: str) -> str:
    """Znaki sterujace (Unicode Cc, w tym ESC, CR, LF, TAB, C1) i znaki kierunkowe -> widoczne \\xNN / \\uNNNN.

    Dane z EXIF i nazwy plikow sa niezaufane: nie moga zmieniac wygladu terminala ani lamac tabeli.
    """
    out = []
    for ch in s:
        o = ord(ch)
        if unicodedata.category(ch) == "Cc":
            out.append(f"\\x{o:02x}")
        elif o in _BIDI:
            out.append(f"\\u{o:04x}")
        else:
            out.append(ch)
    return "".join(out)


def csv_safe(v):
    """Neutralizacja formul arkusza (CSV injection): tekst zaczynajacy sie od = + - @ TAB CR dostaje apostrof.

    Dotyczy tylko napisow; liczby (takze ujemne) zostaja bez zmian.
    """
    if isinstance(v, str) and v.startswith(_FORMULA_PREFIXES):
        return "'" + v
    return v


def _cut(s: str, n: int) -> str:
    return s if len(s) <= n else s[: n - 1] + "~"


def render_table(items: list[PhotoMeta], base: Path | None = None) -> str:
    headers = ["Plik", "Czas wykonania", "Aparat", "Oprogramowanie", "GPS (lat, lon)", "Wys. [m]", "Kier. [deg]"]
    rows = []
    for m in items:
        if m.error:
            rows.append([_rel(m.path, base), "BLAD: " + m.error, "", "", "", "", ""])
            continue
        rows.append([
            _rel(m.path, base),
            (m.taken or "-").replace("T", " "),
            m.camera or "-",
            m.software or "-",
            format_coords(m.lat, m.lon) if m.has_gps else "-",
            f"{m.altitude:.1f}" if m.altitude is not None else "-",
            f"{m.direction:.0f}" if m.direction is not None else "-",
        ])
    limits = [38, 19, 26, 24, 22, 8, 11]
    rows = [[safe_text(c) for c in r] for r in rows]
    rows = [[_cut(c, limits[i]) if not c.startswith("BLAD") else c for i, c in enumerate(r)] for r in rows]
    widths = [max(len(h), *(len(r[i]) for r in rows)) if rows else len(h) for i, h in enumerate(headers)]
    line = lambda cells: "  ".join(c.ljust(widths[i]) for i, c in enumerate(cells)).rstrip()
    out = [line(headers), "  ".join("-" * w for w in widths)]
    out += [line(r) for r in rows]
    return "\n".join(out)


def render_warnings(items: list[PhotoMeta], base: Path | None = None) -> str:
    gps = [m for m in items if m.has_gps]
    if not gps:
        return ""
    lines = [f"UWAGA: {len(gps)} z {len(items)} plikow ujawnia lokalizacje (GPS w metadanych):"]
    lines += [f"  - {safe_text(_rel(m.path, base))}: {GPS_WARNING} ({format_coords(m.lat, m.lon)})" for m in gps]
    lines.append("  Przed publikacja usun metadane: exif-map <sciezka> --strip <folder_wyjsciowy>")
    return "\n".join(lines)


def render_summary(items: list[PhotoMeta], exiftool: str | None) -> str:
    n_gps = sum(1 for m in items if m.has_gps)
    n_err = sum(1 for m in items if m.error)
    engine = f"exiftool ({exiftool})" if exiftool else "Pillow (exiftool niedostepny)"
    return f"Plikow: {len(items)}, z GPS: {n_gps}, z bledem: {n_err}. Silnik: {engine}."


def to_json(items: list[PhotoMeta]) -> str:
    return json.dumps([m.to_dict() for m in items], ensure_ascii=False, indent=2)


def to_csv(items: list[PhotoMeta]) -> str:
    buf = io.StringIO()
    w = csv.DictWriter(buf, fieldnames=CSV_FIELDS, extrasaction="ignore", lineterminator="\n")
    w.writeheader()
    for m in items:
        w.writerow({k: csv_safe(v) for k, v in m.to_dict().items()})
    return buf.getvalue()
