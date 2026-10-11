"""Zapis kopii plikow BEZ metadanych (OPSEC przed publikacja wlasnych zdjec). Nigdy nie nadpisuje oryginalow."""

from __future__ import annotations

import struct
from dataclasses import dataclass, field
from pathlib import Path

from PIL import ExifTags, Image, ImageOps

from .reader import IFD_GPS, iter_files

ORIENTATION = 0x0112
IFD_EXIF = 0x8769
ICC_MAGIC = b"ICC_PROFILE\x00"
MAX_INPUT_BYTES = 200 * 1024 * 1024  # wiekszy plik wejsciowy jest pomijany (JPEG jest czytany do pamieci)


@dataclass
class StripResult:
    source: str
    output: str | None = None
    method: str | None = None  # "bezstratnie (JPEG)" | "ponowne kodowanie"
    verified: bool = False
    leftovers: list[str] | None = None
    error: str | None = None
    removed: list[str] = field(default_factory=list)


def unique_target(target: Path, source: Path) -> Path:
    """Zwraca sciezke, ktora nie istnieje i nie jest oryginalem (dopisuje _clean, _clean2...)."""
    src = source.resolve()
    if not target.exists() and target.resolve() != src:
        return target
    n = 1
    while True:
        suffix = "_clean" if n == 1 else f"_clean{n}"
        cand = target.with_name(f"{target.stem}{suffix}{target.suffix}")
        if not cand.exists() and cand.resolve() != src:
            return cand
        n += 1


def _parse_jpeg(data: bytes) -> tuple[list[tuple[int, int, int]], int]:
    """Parsuje CALY strumien JPEG: zwraca ([(marker, start, koniec)], pozycja_za_EOI).

    start/koniec obejmuja marker (0xFF xx), naglowek dlugosci, tresc, a dla SOS takze dane entropijne
    skanu (do nastepnego markera innego niz RSTn / 0xFF00 / wypelniacz 0xFF). Brak EOI = blad.
    """
    if data[:2] != b"\xff\xd8":
        raise ValueError("to nie jest JPEG")
    segs: list[tuple[int, int, int]] = []
    i, n = 2, len(data)
    while i < n:
        if data[i] != 0xFF:
            raise ValueError("uszkodzona struktura JPEG")
        start = i
        while i < n and data[i] == 0xFF:  # wypelniacze 0xFF
            i += 1
        if i >= n:
            break
        marker = data[i]
        i += 1
        if marker == 0xD9:  # EOI: wszystko dalej to dane spoza obrazu
            return segs, i
        if marker == 0x00:
            raise ValueError("uszkodzona struktura JPEG")
        if marker == 0x01 or 0xD0 <= marker <= 0xD8:  # markery bez dlugosci
            segs.append((marker, start, i))
            continue
        if i + 2 > n:
            raise ValueError("uciety JPEG")
        (length,) = struct.unpack(">H", data[i : i + 2])
        if length < 2 or i + length > n:
            raise ValueError("uszkodzona dlugosc segmentu JPEG")
        i += length
        if marker == 0xDA:  # SOS: dane entropijne do nastepnego markera
            while i < n:
                if data[i] == 0xFF and i + 1 < n:
                    nxt = data[i + 1]
                    if nxt == 0x00 or 0xD0 <= nxt <= 0xD7:  # bajt stuffing / restart: dalej dane skanu
                        i += 2
                        continue
                    if nxt == 0xFF:  # wypelniacz przed markerem
                        i += 1
                        continue
                    break
                i += 1
        segs.append((marker, start, i))
    raise ValueError("brak znacznika EOI (uciety JPEG)")


def _payload_start(data: bytes, start: int) -> int:
    """Pozycja tresci segmentu: pomija wypelniacze 0xFF przed markerem (FF xx LL LL -> tresc po LL LL)."""
    i = start
    while data[i] == 0xFF:
        i += 1
    return i + 3


def _segment_label(marker: int, payload: bytes) -> str | None:
    """None = segment dozwolony; w przeciwnym razie nazwa metadanych (do usuniecia / zgloszenia)."""
    if marker == 0xFE:
        return "segment COM (komentarz)"
    if marker == 0xE1:
        return "segment APP1 (Exif/XMP)"
    if marker == 0xE0 and not payload.startswith(b"JFIF\x00"):
        return "segment APP0 (nie JFIF)"
    if marker == 0xE2 and not payload.startswith(ICC_MAGIC):
        return "segment APP2 (MPF/FlashPix, nie ICC)"
    if marker == 0xEE and not payload.startswith(b"Adobe"):
        return "segment APP14 (nie Adobe)"
    if 0xE3 <= marker <= 0xED or marker == 0xEF:
        return f"segment APP{marker - 0xE0}"
    return None


def _jpeg_lossless_strip(data: bytes) -> bytes:
    """Usuwa metadane JPEG w CALYM strumieniu (takze miedzy skanami progressive) i dane za EOI.

    Zostawia JFIF, ICC i Adobe APP14. Dane skanow kopiowane bez zmian (bezstratnie).
    """
    segs, _ = _parse_jpeg(data)
    out = bytearray(b"\xff\xd8")
    for marker, start, end in segs:
        if 0xE0 <= marker <= 0xEF or marker == 0xFE:
            payload = data[_payload_start(data, start) : end]  # po FF xx LL LL (z pominieciem wypelniaczy)
            if _segment_label(marker, payload):
                continue
        out += data[start:end]
    out += b"\xff\xd9"
    return bytes(out)


def _clean_copy(im: Image.Image) -> Image.Image:
    """Swieza kopia pikseli bez info/exif/tekstow."""
    if im.mode == "P":
        im = im.convert("RGBA" if "transparency" in im.info else "RGB")
    return Image.frombytes(im.mode, im.size, im.tobytes())


def _needs_orientation_bake(path: Path) -> bool:
    try:
        with Image.open(path) as im:
            return im.getexif().get(ORIENTATION, 1) not in (None, 1)
    except Exception:
        return False


def leftover_metadata(path: Path) -> list[str]:
    """Co zostalo z metadanych w pliku (pusta lista = czysto). Do weryfikacji po strip."""
    left: list[str] = []
    with Image.open(path) as im:
        exif = im.getexif()
        if len(exif):
            left.append("EXIF")
        try:
            if exif.get_ifd(IFD_GPS):
                left.append("GPS")
        except Exception:
            pass
        text = getattr(im, "text", None)
        if text:
            left.append("tekst PNG")
        for key in ("xmp", "XML:com.adobe.xmp", "comment"):
            if key in im.info:
                left.append(key)
    if path.suffix.lower() in (".jpg", ".jpeg"):
        raw = path.read_bytes()  # CALY plik, nie tylko poczatek
        try:
            segs, eoi_end = _parse_jpeg(raw)
        except ValueError as e:
            left.append(f"nieprawidlowa struktura JPEG ({e})")
        else:
            for marker, start, end in segs:
                if 0xE0 <= marker <= 0xEF or marker == 0xFE:
                    label = _segment_label(marker, raw[_payload_start(raw, start) : end])
                    if label:
                        left.append(label)
            if eoi_end < len(raw):
                left.append("dane za EOI")
    return sorted(set(left))


def metadata_fields(path: Path) -> list[str]:
    """Nazwy pol metadanych obecnych w pliku: etykiety z leftover_metadata + nazwy tagow EXIF/GPS.

    Tagi IFD0 i Exif IFD sa nazywane wedlug PIL.ExifTags.TAGS (nieznany tag jako '0x%04X').
    Wskazniki ExifOffset/GPSInfo sa pominiete; GPS jest raportowany jako pojedyncza etykieta 'GPS'.
    """
    fields: set[str] = set(leftover_metadata(path))
    try:
        with Image.open(path) as im:
            exif = im.getexif()
            for tag_id in exif:
                if tag_id in (IFD_EXIF, IFD_GPS):
                    continue
                fields.add(ExifTags.TAGS.get(tag_id, "0x%04X" % tag_id))
            try:
                exif_ifd = exif.get_ifd(IFD_EXIF)
            except Exception:
                exif_ifd = {}
            for tag_id in exif_ifd:
                fields.add(ExifTags.TAGS.get(tag_id, "0x%04X" % tag_id))
            try:
                gps_ifd = exif.get_ifd(IFD_GPS)
            except Exception:
                gps_ifd = {}
            if gps_ifd:
                fields.add("GPS")
    except Exception:
        pass
    return sorted(fields)


def strip_file(source: Path, target: Path) -> StripResult:
    res = StripResult(source=str(source))
    try:
        size = source.stat().st_size
        if size > MAX_INPUT_BYTES:
            raise ValueError(
                f"plik pominiety: przekracza limit rozmiaru ({size // (1024 * 1024)} MB > {MAX_INPUT_BYTES // (1024 * 1024)} MB)"
            )
        target.parent.mkdir(parents=True, exist_ok=True)
        before = metadata_fields(source)
        ext = source.suffix.lower()
        if ext in (".jpg", ".jpeg") and not _needs_orientation_bake(source):
            target.write_bytes(_jpeg_lossless_strip(source.read_bytes()))
            res.method = "bezstratnie (JPEG)"
        else:
            with Image.open(source) as im:
                fmt = im.format or {".jpg": "JPEG", ".jpeg": "JPEG", ".png": "PNG", ".tif": "TIFF",
                                    ".tiff": "TIFF", ".heic": "HEIF", ".heif": "HEIF"}.get(ext, "PNG")
                icc = im.info.get("icc_profile")
                im = ImageOps.exif_transpose(im)  # zachowaj wyglad (orientacja zostanie zapieczona w pikselach)
                clean = _clean_copy(im)
                kwargs: dict = {}
                if icc:
                    kwargs["icc_profile"] = icc
                if fmt == "JPEG":
                    kwargs["quality"] = 95
                clean.save(target, format=fmt, **kwargs)
            res.method = "ponowne kodowanie"
        res.output = str(target)
        res.leftovers = leftover_metadata(target)
        res.verified = not res.leftovers
        res.removed = sorted(set(before) - set(metadata_fields(target)))
    except Exception as e:  # jeden zly plik nie przerywa calosci
        res.error = f"{e.__class__.__name__}: {e}"
        if target.exists() and res.output is None:
            try:
                target.unlink()
            except OSError:
                pass
    return res


def strip_all(target: Path, out_dir: Path) -> list[StripResult]:
    """Kopiuje pliki (plik lub folder rekurencyjnie) do out_dir bez metadanych. Oryginaly nietkniete."""
    target = Path(target)
    out_dir = Path(out_dir)
    base = target if target.is_dir() else target.parent
    results = []
    for f in iter_files(target, exclude_dir=out_dir):
        rel = f.relative_to(base) if target.is_dir() else Path(f.name)
        results.append(strip_file(f, unique_target(out_dir / rel, f)))
    return results
