"""Specyfikacja: strip zwraca raport pol metadanych faktycznie usunietych (StripResult.removed) i pokazuje go w CLI."""

from __future__ import annotations

import struct
from pathlib import Path

from PIL import Image

from exif_map import strip as strip_mod
from exif_map.cli import main
from exif_map.reader import read_pillow
from exif_map.strip import metadata_fields, strip_all

IFD_EXIF, IFD_GPS = 0x8769, 0x8825
WARSAW = ((52, 13, 56.2), "N", (21, 0, 30.9), "E")


def _img(path: Path, *, gps=None, make="TestCam", orientation=None, size=(64, 48)) -> Path:
    im = Image.new("RGB", size, (200, 30, 30))
    exif = Image.Exif()
    exif[0x010F] = make
    exif[0x0110] = "TC-1"
    exif[0x0131] = "Test 1.0"
    if orientation:
        exif[0x0112] = orientation
    exif.get_ifd(IFD_EXIF)[0x9003] = "2024:05:01 10:00:00"
    if gps:
        g = exif.get_ifd(IFD_GPS)
        g[1], g[2], g[3], g[4] = gps[1], gps[0], gps[3], gps[2]
    im.save(path, exif=exif)
    return path


def _plain_jpeg(path: Path) -> Path:
    Image.new("RGB", (32, 32), (10, 120, 10)).save(path)
    return path


def test_report_lists_gps_make_and_they_are_gone_from_output(tmp_path):
    src = _img(tmp_path / "a.jpg", gps=WARSAW)
    res = strip_all(src, tmp_path / "o")[0]
    assert res.verified and not res.error, res
    assert isinstance(res.removed, list) and all(isinstance(x, str) for x in res.removed)
    for name in ("GPS", "Make", "Model", "Software", "DateTimeOriginal"):
        assert name in res.removed, res.removed
    assert res.removed == sorted(set(res.removed))  # posortowane, bez duplikatow
    assert "GPSInfo" not in res.removed and "ExifOffset" not in res.removed  # same wskazniki nie sa polami
    # po strip naprawde ich nie ma
    out = Path(res.output)
    m = read_pillow(out)
    assert not m.has_gps and m.camera == "" and m.taken is None
    with Image.open(out) as im:
        assert len(im.getexif()) == 0
    left = metadata_fields(out)
    assert not set(res.removed) & set(left)


def test_metadata_fields_of_source_contains_names(tmp_path):
    src = _img(tmp_path / "a.jpg", gps=WARSAW)
    f = metadata_fields(src)
    assert {"GPS", "Make", "Model", "DateTimeOriginal"} <= set(f)
    assert f == sorted(set(f))


def test_clean_file_reports_nothing_removed(tmp_path):
    src = _plain_jpeg(tmp_path / "czysty.jpg")
    res = strip_all(src, tmp_path / "o")[0]
    assert res.verified and not res.error
    assert res.removed == []


def test_report_includes_comment_segment_and_trailing_data(tmp_path):
    base = _plain_jpeg(tmp_path / "b.jpg").read_bytes()
    payload = b"komentarz GPS 52.2,21.0"
    com = b"\xff\xfe" + struct.pack(">H", len(payload) + 2) + payload
    dirty = base[:2] + com + base[2:] + b"PK\x03\x04 ukryte"
    p = tmp_path / "dirty.jpg"
    p.write_bytes(dirty)
    res = strip_all(p, tmp_path / "o")[0]
    assert res.method == "bezstratnie (JPEG)" and res.verified, res
    assert "segment COM (komentarz)" in res.removed
    assert "dane za EOI" in res.removed
    assert b"komentarz" not in Path(res.output).read_bytes()


def test_reencode_path_reports_orientation(tmp_path):
    src = _img(tmp_path / "r.jpg", orientation=6, size=(64, 32))
    res = strip_all(src, tmp_path / "o")[0]
    assert res.method == "ponowne kodowanie" and res.verified
    assert "Orientation" in res.removed and "Make" in res.removed


def test_png_exif_reported(tmp_path):
    exif = Image.Exif()
    exif[0x010F] = "Cam"
    p = tmp_path / "t.png"
    Image.new("RGB", (8, 8)).save(p, exif=exif)
    res = strip_all(p, tmp_path / "o")[0]
    assert res.verified
    assert "Make" in res.removed


def test_fields_not_actually_removed_are_not_reported(tmp_path, monkeypatch):
    # strip, ktory niczego nie usuwa: raport ma byc pusty, a weryfikacja negatywna
    src = _img(tmp_path / "a.jpg", gps=WARSAW)
    monkeypatch.setattr(strip_mod, "_jpeg_lossless_strip", lambda data: data)
    res = strip_all(src, tmp_path / "o")[0]
    assert not res.verified
    assert res.removed == []


def test_error_leaves_empty_report(tmp_path, monkeypatch):
    src = _img(tmp_path / "big.jpg", gps=WARSAW)
    monkeypatch.setattr(strip_mod, "MAX_INPUT_BYTES", 100)
    res = strip_all(src, tmp_path / "o")[0]
    assert res.error and res.output is None
    assert res.removed == []


def test_cli_shows_removed_fields(tmp_path, capsys):
    src = _img(tmp_path / "a.jpg", gps=WARSAW)
    rc = main([str(src), "--no-exiftool", "--quiet", "--strip", str(tmp_path / "o")])
    out = capsys.readouterr().out
    assert rc == 0
    line = next(l for l in out.splitlines() if l.strip().startswith("OK "))
    assert "usunieto:" in line
    tail = line.split("usunieto:", 1)[1]
    assert "GPS" in tail and "Make" in tail and "DateTimeOriginal" in tail


def test_cli_clean_file_says_nothing_removed(tmp_path, capsys):
    src = _plain_jpeg(tmp_path / "czysty.jpg")
    rc = main([str(src), "--no-exiftool", "--quiet", "--strip", str(tmp_path / "o")])
    out = capsys.readouterr().out
    assert rc == 0
    line = next(l for l in out.splitlines() if l.strip().startswith("OK "))
    assert "usunieto: nic" in line
