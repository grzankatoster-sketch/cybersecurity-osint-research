from pathlib import Path

from PIL import Image

from exif_map.reader import read_pillow
from exif_map.strip import _jpeg_lossless_strip, leftover_metadata, strip_all

from conftest import WARSAW, make_image


def test_strip_removes_exif_and_keeps_original(photos, tmp_path):
    out = tmp_path / "czyste"
    before = {p: p.read_bytes() for p in photos.rglob("*") if p.is_file()}
    results = strip_all(photos, out)
    assert len(results) == 3
    assert all(r.verified and not r.error for r in results), results
    for r in results:
        m = read_pillow(__import__("pathlib").Path(r.output))
        assert not m.has_gps and m.camera == "" and m.taken is None
        with Image.open(r.output) as im:
            assert len(im.getexif()) == 0
    # oryginaly bez zmian
    assert {p: p.read_bytes() for p in before} == before
    assert read_pillow(photos / "a.jpg").has_gps


def test_jpeg_strip_is_lossless(tmp_path):
    src = make_image(tmp_path / "s.jpg", gps=WARSAW)
    res = strip_all(src, tmp_path / "o")[0]
    assert res.method == "bezstratnie (JPEG)"
    with Image.open(src) as a, Image.open(res.output) as b:
        assert a.tobytes() == b.tobytes()


def test_orientation_is_baked_in(tmp_path):
    src = make_image(tmp_path / "r.jpg", orientation=6, size=(64, 32))  # obrot o 90 stopni
    res = strip_all(src, tmp_path / "o")[0]
    assert res.verified
    with Image.open(res.output) as im:
        assert im.size == (32, 64)
        assert 0x0112 not in im.getexif()


def test_png_text_chunks_removed(tmp_path):
    from PIL.PngImagePlugin import PngInfo

    info = PngInfo()
    info.add_text("Author", "Jan")
    exif = Image.Exif()
    exif[0x010F] = "Cam"
    p = tmp_path / "t.png"
    Image.new("RGB", (8, 8)).save(p, pnginfo=info, exif=exif)
    res = strip_all(p, tmp_path / "o")[0]
    assert res.verified, res.leftovers
    with Image.open(res.output) as im:
        assert not getattr(im, "text", {}) and len(im.getexif()) == 0


def test_never_overwrites(tmp_path):
    src = make_image(tmp_path / "x.jpg", gps=WARSAW)
    # katalog wyjsciowy = katalog zrodla: musi powstac nowa nazwa, oryginal nietkniety
    original = src.read_bytes()
    res = strip_all(src, tmp_path)[0]
    assert res.output != str(src) and res.verified
    assert src.read_bytes() == original
    # drugi przebieg nie nadpisuje pierwszej kopii
    res2 = strip_all(src, tmp_path)[0]
    assert res2.output not in (str(src), res.output)


def test_out_dir_inside_scanned_folder_is_not_rescanned(photos):
    out = photos / "czyste"
    strip_all(photos, out)
    second = strip_all(photos, out)
    assert len(second) == 3  # pliki z out nie sa traktowane jako zrodla


def test_lossless_helper_rejects_non_jpeg():
    import pytest

    with pytest.raises(ValueError):
        _jpeg_lossless_strip(b"PNG....")


# ---------------------------------------------------------------- strip: pelny parser strumienia JPEG

def _split_jpeg_segments(data: bytes):
    """Pomocniczo (niezalezny od implementacji): lista (marker, bajty) az do EOI + reszta za EOI."""
    import struct

    segs, i = [], 2
    while i < len(data):
        assert data[i] == 0xFF
        while data[i] == 0xFF:
            i += 1
        mk = data[i]
        i += 1
        if mk == 0xD9:
            return segs, data[i:]
        if mk in (0x01, *range(0xD0, 0xD8)):
            segs.append((mk, b""))
            continue
        (ln,) = struct.unpack(">H", data[i : i + 2])
        segs.append((mk, data[i + 2 : i + ln]))
        i += ln
        if mk == 0xDA:  # dane entropijne do nastepnego markera != RSTn/stuffing
            while i < len(data):
                if data[i] == 0xFF and data[i + 1] not in (0x00, *range(0xD0, 0xD8)) and data[i + 1] != 0xFF:
                    break
                i += 1
    return segs, b""


def _progressive_with_injections(tmp_path):
    """Progressive JPEG: APP1/COM wstrzykniete MIEDZY skanami + ZIP/tekst z GPS za EOI."""
    src = tmp_path / "p.jpg"
    Image.effect_noise((96, 96), 60).convert("RGB").save(src, progressive=True, quality=80)
    data = src.read_bytes()
    # pozycje kazdego SOS
    sos, i = [], 2
    segs_raw = data
    import struct

    i = 2
    while i < len(data):
        while data[i] == 0xFF:
            i += 1
        mk = data[i]
        i += 1
        if mk == 0xD9:
            break
        if mk in (0x01, *range(0xD0, 0xD8)):
            continue
        (ln,) = struct.unpack(">H", data[i : i + 2])
        if mk == 0xDA:
            sos.append(i - 2)
            i += ln
            while i < len(data):
                if data[i] == 0xFF and data[i + 1] not in (0x00, 0xFF) and not 0xD0 <= data[i + 1] <= 0xD7:
                    break
                i += 1
        else:
            i += ln
    assert len(sos) >= 3, "Pillow nie zrobil progressive z wieloma skanami"

    def seg(marker, payload):
        return bytes([0xFF, marker]) + struct.pack(">H", len(payload) + 2) + payload

    exif = seg(0xE1, b"Exif\x00\x00GPSMARKER_APP1")
    com = seg(0xFE, b"komentarz GPS 52.2,21.0")
    xmp = seg(0xE1, b"http://ns.adobe.com/xap/1.0/\x00<x:xmpmeta>GPS</x:xmpmeta>")
    out = data[: sos[1]] + exif + data[sos[1] : sos[2]] + com + xmp + data[sos[2] :]
    assert out.rstrip().endswith(b"\xff\xd9")
    out += b"PK\x03\x04 ukryty zip GPS: 52.2297N 21.0122E"
    p = tmp_path / "prog.jpg"
    p.write_bytes(out)
    return p


def test_lossless_strip_removes_metadata_between_scans_and_trailing_data(tmp_path):
    p = _progressive_with_injections(tmp_path)
    cleaned = _jpeg_lossless_strip(p.read_bytes())
    assert b"GPSMARKER_APP1" not in cleaned and b"komentarz" not in cleaned
    assert b"GPS" not in cleaned and b"PK\x03\x04" not in cleaned
    assert cleaned.endswith(b"\xff\xd9")
    segs, tail = _split_jpeg_segments(cleaned)
    assert tail == b""
    assert not [m for m, _ in segs if m in (0xE1, 0xFE) or 0xE3 <= m <= 0xED or m == 0xEF]
    # piksele nietkniete
    with Image.open(p) as a, Image.open(__import__("io").BytesIO(cleaned)) as b:
        assert a.tobytes() == b.tobytes()
    assert sum(1 for m, _ in segs if m == 0xDA) >= 3  # wszystkie skany zachowane


def test_strip_all_progressive_verified_and_clean(tmp_path):
    p = _progressive_with_injections(tmp_path)
    res = strip_all(p, tmp_path / "o")[0]
    assert res.method == "bezstratnie (JPEG)" and res.verified, res
    assert b"GPS" not in Path(res.output).read_bytes()


def test_verifier_checks_whole_file_not_only_first_64k(tmp_path):
    # JPEG z czystym poczatkiem, a APP1 (i dane za EOI) PO 64 KiB
    p = _progressive_with_injections(tmp_path)
    data = p.read_bytes()
    import struct

    big = bytes([0xFF, 0xE1]) + struct.pack(">H", 20) + b"Exif\x00\x00GPSxxxxxxxxxx"
    # rozdmuchany COM pchnie dalsze segmenty poza 64 KiB; weryfikator ma i tak zlapac
    pad = bytes([0xFF, 0xFE]) + struct.pack(">H", 65000) + b"\x00" * 64998
    dirty = data[:2] + pad + pad + data[2:]
    q = tmp_path / "dirty.jpg"
    q.write_bytes(dirty)
    left = leftover_metadata(q)
    assert left, "weryfikator pominal metadane / dane za EOI"
    assert any("COM" in x or "APP" in x or "EOI" in x for x in left)


def test_verifier_flags_trailing_data_after_eoi(tmp_path):
    src = make_image(tmp_path / "t.jpg")
    q = tmp_path / "t2.jpg"
    q.write_bytes(_jpeg_lossless_strip(src.read_bytes()) + b"GPS 52.1 21.0")
    assert any("EOI" in x for x in leftover_metadata(q))


def test_strip_size_limit(tmp_path, monkeypatch):
    from exif_map import strip as strip_mod

    src = make_image(tmp_path / "big.jpg", gps=WARSAW)
    monkeypatch.setattr(strip_mod, "MAX_INPUT_BYTES", 100)
    res = strip_all(src, tmp_path / "o")[0]
    assert res.error and "limit" in res.error.lower()
    assert res.output is None and not (tmp_path / "o" / "big.jpg").exists()


def test_cli_strip_size_limit_exit_3(tmp_path, monkeypatch, capsys):
    from exif_map import strip as strip_mod
    from exif_map.cli import main

    src = make_image(tmp_path / "big.jpg", gps=WARSAW)
    monkeypatch.setattr(strip_mod, "MAX_INPUT_BYTES", 100)
    rc = main([str(src), "--no-exiftool", "--quiet", "--strip", str(tmp_path / "o")])
    out = capsys.readouterr().out
    assert rc == 3 and "limit" in out.lower()
