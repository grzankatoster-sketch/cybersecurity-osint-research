"""Odczyt metadanych: Pillow (zawsze) + exiftool (opcjonalnie, pelniejsze dane)."""

from __future__ import annotations

import json
import os
import shutil
import subprocess
from datetime import datetime
from pathlib import Path
from typing import Any, Iterable, Iterator

from PIL import Image, UnidentifiedImageError

from .gps import dms_to_decimal, to_float, valid_coordinates
from .models import PhotoMeta

try:  # opcjonalne: obsluga HEIC/HEIF
    import pillow_heif  # type: ignore

    pillow_heif.register_heif_opener()
    HEIF_SUPPORT = True
except Exception:  # pragma: no cover - zalezy od srodowiska
    HEIF_SUPPORT = False

EXTENSIONS = {".jpg", ".jpeg", ".png", ".heic", ".heif", ".tif", ".tiff"}

# OSINT/narzedzia (rodzenstwo folderu projektu); tu moze lezec exiftool
TOOLS_DIR = Path(__file__).resolve().parents[3] / "narzedzia"

# Tagi EXIF
IFD_EXIF = 0x8769
IFD_GPS = 0x8825
TAG_MAKE, TAG_MODEL, TAG_SOFTWARE = 0x010F, 0x0110, 0x0131
TAG_DATETIME = 0x0132
TAG_DT_ORIGINAL, TAG_DT_DIGITIZED = 0x9003, 0x9004
TAG_LENS_MODEL = 0xA434


def iter_files(target: Path, exclude_dir: Path | None = None) -> Iterator[Path]:
    """Plik albo folder (rekurencyjnie), posortowane. exclude_dir: pomijany (np. katalog wyjsciowy --strip)."""
    target = Path(target)
    if target.is_file():
        yield target
        return
    excl = exclude_dir.resolve() if exclude_dir else None
    for p in sorted(target.rglob("*")):
        if not p.is_file() or p.suffix.lower() not in EXTENSIONS:
            continue
        if excl is not None and (p.resolve() == excl or excl in p.resolve().parents):
            continue
        yield p


def parse_exif_time(value: Any) -> str | None:
    """'2024:05:01 10:00:00' (takze z ulamkiem sekundy/strefa) -> '2024-05-01T10:00:00'."""
    if value is None:
        return None
    if isinstance(value, bytes):
        value = value.decode("ascii", "ignore")
    s = str(value).strip().strip("\x00").strip()
    head = s[:19]
    for fmt in ("%Y:%m:%d %H:%M:%S", "%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%S"):
        try:
            return datetime.strptime(head, fmt).isoformat(timespec="seconds")
        except ValueError:
            continue
    return None


def _clean_str(v: Any) -> str | None:
    if v is None:
        return None
    if isinstance(v, bytes):
        v = v.decode("utf-8", "ignore")
    s = str(v).strip().strip("\x00").strip()
    return s or None


# ----------------------------------------------------------------- Pillow

def read_pillow(path: Path) -> PhotoMeta:
    meta = PhotoMeta(path=str(path), source="pillow")
    try:
        with Image.open(path) as im:
            meta.width, meta.height = im.size
            exif = im.getexif()
            if not exif:
                return meta
            meta.make = _clean_str(exif.get(TAG_MAKE))
            meta.model = _clean_str(exif.get(TAG_MODEL))
            meta.software = _clean_str(exif.get(TAG_SOFTWARE))
            try:
                sub = dict(exif.get_ifd(IFD_EXIF))
            except Exception:
                sub = {}
            candidates = [
                ("DateTimeOriginal", sub.get(TAG_DT_ORIGINAL)),
                ("DateTimeDigitized", sub.get(TAG_DT_DIGITIZED)),
                ("DateTime", exif.get(TAG_DATETIME)),
            ]
            for name, raw in candidates:
                iso = parse_exif_time(raw)
                if iso:
                    meta.taken, meta.taken_field = iso, name
                    break
            try:
                gps = dict(exif.get_ifd(IFD_GPS))
            except Exception:
                gps = {}
            if gps:
                _apply_gps(meta, gps)
            lens = _clean_str(sub.get(TAG_LENS_MODEL))
            if lens:
                meta.extra["LensModel"] = lens
    except (UnidentifiedImageError, OSError, ValueError, SyntaxError) as e:
        hint = ""
        if path.suffix.lower() in (".heic", ".heif") and not HEIF_SUPPORT:
            hint = " (HEIC wymaga: pip install pillow-heif albo exiftool)"
        meta.error = f"nie mozna odczytac obrazu: {e.__class__.__name__}{hint}"
    return meta


def _apply_gps(meta: PhotoMeta, gps: dict[int, Any]) -> None:
    lat = dms_to_decimal(gps.get(2), gps.get(1))
    lon = dms_to_decimal(gps.get(4), gps.get(3))
    if valid_coordinates(lat, lon):
        meta.lat, meta.lon = lat, lon
    alt = to_float(gps.get(6))
    if alt is not None and meta.has_gps:
        ref = gps.get(5)
        if isinstance(ref, bytes):
            ref = ref[0] if ref else 0
        meta.altitude = -abs(alt) if ref == 1 else alt
    direction = to_float(gps.get(17))
    if direction is not None and 0.0 <= direction <= 360.0:
        meta.direction = direction


# --------------------------------------------------------------- exiftool

def find_exiftool() -> str | None:
    """exiftool z PATH albo z OSINT/narzedzia/ (takze 'exiftool(-k).exe' w podfolderach)."""
    found = shutil.which("exiftool")
    if found:
        return found
    if TOOLS_DIR.is_dir():
        names = {"exiftool.exe", "exiftool(-k).exe"}
        for root, dirs, files in os.walk(TOOLS_DIR):
            dirs[:] = [d for d in dirs if d not in ("maigret-venv", "wyniki", "__pycache__")]
            for fn in files:
                if fn.lower() in names:
                    return str(Path(root) / fn)
    return None


def _first(d: dict[str, Any], *keys: str) -> Any:
    for k in keys:
        if k in d and d[k] not in (None, ""):
            return d[k]
    return None


def meta_from_exiftool(row: dict[str, Any], path: str) -> PhotoMeta:
    meta = PhotoMeta(path=path, source="exiftool")
    meta.make = _clean_str(row.get("Make"))
    meta.model = _clean_str(row.get("Model"))
    meta.software = _clean_str(row.get("Software"))
    for name in ("DateTimeOriginal", "CreateDate", "DateTimeDigitized", "MediaCreateDate", "DateTime", "ModifyDate"):
        iso = parse_exif_time(row.get(name))
        if iso:
            meta.taken, meta.taken_field = iso, name
            break
    lat, lon = to_float(row.get("GPSLatitude")), to_float(row.get("GPSLongitude"))
    if valid_coordinates(lat, lon):
        meta.lat, meta.lon = lat, lon
        alt = to_float(row.get("GPSAltitude"))
        if alt is not None:
            if row.get("GPSAltitudeRef") in (1, "1") and alt > 0:
                alt = -alt
            meta.altitude = alt
    direction = to_float(_first(row, "GPSImgDirection", "GPSDestBearing"))
    if direction is not None and 0.0 <= direction <= 360.0:
        meta.direction = direction
    w, h = row.get("ImageWidth"), row.get("ImageHeight")
    meta.width = int(w) if isinstance(w, (int, float)) else None
    meta.height = int(h) if isinstance(h, (int, float)) else None
    for key in ("LensModel", "LensID", "ISO", "ExposureTime", "FNumber", "FocalLength", "OffsetTimeOriginal",
                "SerialNumber", "BodySerialNumber", "OwnerName", "Artist", "Copyright", "LensSerialNumber",
                "GPSSpeed", "GPSDateTime"):
        v = row.get(key)
        if v not in (None, ""):
            meta.extra[key] = v
    return meta


def _norm(p: str | Path) -> str:
    return os.path.normcase(os.path.abspath(str(p)))


def build_exiftool_cmd(exe: str, files: list[Path]) -> list[str]:
    """Polecenie exiftool (tylko odczyt) z utwardzonymi argumentami.

    - `-config ""` jako PIERWSZY argument: wylacza ladowanie pliku konfiguracyjnego. Hardening: exiftool i tak
      szuka .ExifTool_config w HOME, a nie w biezacym katalogu (CWD), ale pusta konfiguracja wyklucza wykonanie
      cudzego kodu Perl takze przy innym srodowisku uruchomienia.
    - `--` przed lista plikow i sciezki absolutne: nazwa pliku zaczynajaca sie od `-` nie jest opcja
      (np. `-overwrite_original`), wiec odczyt nie moze niczego zmodyfikowac.
    """
    return [exe, "-config", "", "-json", "-n", "-charset", "filename=utf8", "--", *[os.path.abspath(str(p)) for p in files]]


def run_exiftool(exe: str, files: list[Path]) -> dict[str, dict[str, Any]]:
    """Zwraca {znormalizowana sciezka: wiersz JSON}. Blad -> brak wyniku (wtedy zadziala Pillow)."""
    out: dict[str, dict[str, Any]] = {}
    for i in range(0, len(files), 40):
        chunk = files[i : i + 40]
        cmd = build_exiftool_cmd(exe, chunk)
        try:
            proc = subprocess.run(cmd, capture_output=True, timeout=120, check=False)
            rows = json.loads(proc.stdout.decode("utf-8", "replace") or "[]")
        except (OSError, subprocess.SubprocessError, json.JSONDecodeError):
            continue
        for row in rows:
            src = row.get("SourceFile")
            if src:
                out[_norm(src)] = row
    return out


def scan(files: Iterable[Path], use_exiftool: bool = True) -> tuple[list[PhotoMeta], str | None]:
    """Zwraca (lista PhotoMeta, sciezka uzytego exiftool albo None). Pojedynczy plik bez wyniku exiftool -> Pillow."""
    files = list(files)
    exe = find_exiftool() if use_exiftool else None
    rows = run_exiftool(exe, files) if exe else {}
    results: list[PhotoMeta] = []
    for f in files:
        row = rows.get(_norm(f))
        if row is not None and not row.get("Error"):
            m = meta_from_exiftool(row, str(f))
            if m.width is None:
                p = read_pillow(f)
                m.width, m.height = p.width, p.height
            results.append(m)
        else:
            results.append(read_pillow(f))
    return results, exe
