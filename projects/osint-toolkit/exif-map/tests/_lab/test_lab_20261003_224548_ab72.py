from pathlib import Path

from exif_map.models import PhotoMeta
from exif_map.reverse import render_guide


def _gps(path):
    return PhotoMeta(path=str(path), lat=52.2297, lon=21.0122)


def test_reverse_guide_escapes_ansi_in_filename(tmp_path):
    out = render_guide([_gps(tmp_path / "x\x1b[2J.jpg")], tmp_path, None)
    assert "\x1b" not in out
    assert "\\x1b" in out  # nazwa nadal widoczna, ale znak sterujacy jako tekst


def test_reverse_guide_newline_in_filename_does_not_forge_lines(tmp_path):
    out = render_guide([_gps(tmp_path / "a.jpg\r\n  - inny.jpg")], tmp_path, None)
    assert "\r" not in out
    listed = [ln for ln in out.split("ujawni lokalizacje:")[1].split("\n") if ln.strip()]
    assert len(listed) == 1  # jeden plik z GPS = jeden wiersz listy


def test_reverse_guide_escapes_bidi_in_filename(tmp_path):
    out = render_guide([_gps(tmp_path / "zdj\u202egpj.exe")], tmp_path, None)
    assert "\u202e" not in out


def test_reverse_guide_plain_name_unchanged(tmp_path):
    out = render_guide([_gps(tmp_path / "a.jpg")], tmp_path, None)
    assert "  - a.jpg" in out
