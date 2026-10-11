"""Instrukcja recznego wyszukiwania obrazem (reverse image search).

Narzedzie niczego nie wysyla: tylko wypisuje strony wyszukiwarek i zasady.
Celowo bez wyszukiwarek twarzy (PimEyes itp.): to dane biometryczne (art. 9 RODO).
"""
from __future__ import annotations

from pathlib import Path

from .models import PhotoMeta
from .report import safe_text

# (nazwa, strona do recznego wgrania pliku, uwaga)
ENGINES: tuple[tuple[str, str, str], ...] = (
    ("TinEye", "https://tineye.com/", "dokladne kopie i przerobki; deklaruje, ze nie przechowuje wgranych obrazow"),
    ("Google Lens", "https://lens.google.com/", "podobne obrazy i obiekty; obraz trafia do Google"),
    ("Bing Visual Search", "https://www.bing.com/visualsearch", "podobne obrazy; obraz trafia do Microsoft"),
    ("Yandex Images", "https://yandex.com/images/", "dobry w miejscach i budynkach; serwery poza UE (Rosja), nie wgrywaj nic wrazliwego"),
)

# Porownanie miejsca z GPS ze zdjeciem satelitarnym: operator recznie wpisuje wspolrzedne, narzedzie nic nie wysyla.
SATELLITE: tuple[str, str, str] = (
    "Copernicus Browser", "https://browser.dataspace.copernicus.eu/",
    "zdjecia satelitarne Sentinel; reczne porownanie terenu i daty z GPS, nie identyfikuje osob",
)


def render_guide(items: list[PhotoMeta], base: Path, strip_dir: Path | None) -> str:
    lines = [
        "Wyszukiwanie obrazem (recznie, narzedzie niczego nie wysyla):",
        *(f"  - {name}: {url}  ({note})" for name, url, note in ENGINES),
        "Cel: skad pochodzi zdjecie, czy krazy w sieci, czy jest przerobione. Bez wyszukiwania po twarzy.",
        "Miejsce z GPS (recznie): {}: {}  ({})".format(*SATELLITE),
    ]
    gps = [it for it in items if it.has_gps]
    if strip_dir is not None:
        lines.append(f"Wgrywaj kopie bez metadanych z: {strip_dir}")
    else:
        lines.append("Najpierw zrob kopie bez metadanych (--strip FOLDER) i wgrywaj tylko je.")
        if gps:
            lines.append(f"UWAGA: {len(gps)} plik(i) maja GPS; wgranie oryginalu ujawni lokalizacje:")
            for it in gps:
                lines.append(f"  - {safe_text(_rel(Path(it.path), base))}")
    return "\n".join(lines)


def _rel(p: Path, base: Path) -> str:
    try:
        return str(p.relative_to(base))
    except ValueError:
        return str(p)
