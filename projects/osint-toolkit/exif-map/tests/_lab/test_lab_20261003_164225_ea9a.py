from pathlib import Path

from PIL import Image

from exif_map.strip import leftover_metadata, strip_file


def _clean_jpeg_with_fill_byte(path: Path) -> Path:
    """Czysty JPEG (tylko JFIF APP0, bez EXIF) z dozwolonym bajtem wypelnienia 0xFF przed markerem APP0."""
    import io

    buf = io.BytesIO()
    Image.new("RGB", (16, 16), (10, 120, 200)).save(buf, format="JPEG")
    data = buf.getvalue()
    assert data[2:4] == b"\xff\xe0" and data[6:11] == b"JFIF\x00"  # warunek wstepny fixtury
    path.write_bytes(data[:2] + b"\xff" + data[2:])  # FF D8 | FF(wypelnienie) FF E0 ... JFIF
    return path


def test_fill_byte_before_jfif_is_not_reported_as_metadata(tmp_path):
    src = _clean_jpeg_with_fill_byte(tmp_path / "czysty.jpg")
    with Image.open(src) as im:  # plik poprawny dla dekodera
        im.load()
    assert leftover_metadata(src) == []


def test_lossless_strip_keeps_jfif_after_fill_byte(tmp_path):
    src = _clean_jpeg_with_fill_byte(tmp_path / "czysty.jpg")
    res = strip_file(src, tmp_path / "out" / "czysty.jpg")
    assert res.error is None and res.method == "bezstratnie (JPEG)"
    out = Path(res.output).read_bytes()
    assert b"JFIF\x00" in out  # dozwolony segment JFIF nie moze zostac wyciety
    assert res.verified
