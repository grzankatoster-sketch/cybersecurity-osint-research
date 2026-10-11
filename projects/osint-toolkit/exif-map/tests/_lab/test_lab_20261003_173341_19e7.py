import re

from exif_map.cli import main
from exif_map.mapview import build_map, count_suspicious
from exif_map.gps import suspicious_reason
from exif_map.reader import scan

from conftest import WARSAW, make_image

WHOLE = ((52, 0, 0), "N", (21, 0, 0), "E")  # 52.0, 21.0 - pelne stopnie
ZERO_LAT = ((0, 0, 0), "N", (21, 0, 30.9), "E")  # 0.0, 21.0086 - zerowa szerokosc

_ORANGE = re.compile(r"markerColor[\"']?\s*:\s*[\"']orange")


def _map(tmp_path, specs):
    paths = [make_image(tmp_path / name, gps=gps) for name, gps in specs]
    items, _ = scan(paths, use_exiftool=False)
    out = tmp_path / "m.html"
    n = build_map(items, out, thumbnails=False)
    return n, out.read_text(encoding="utf-8"), items


# ------------------------------------------------------------ gps.suspicious_reason

def test_reason_whole_degrees():
    r = suspicious_reason(52.0, 21.0)
    assert r is not None and "pelne stopnie" in r and "placeholder" in r


def test_reason_zero_axis():
    for lat, lon in ((0.0, 21.0086), (52.23, 0.0)):
        r = suspicious_reason(lat, lon)
        assert r is not None and "zerowa" in r and "placeholder" in r


def test_reason_normal_and_edge_cases_none():
    assert suspicious_reason(52.232278, 21.008583) is None
    assert suspicious_reason(52.0, 21.008583) is None  # tylko jedna os w pelnych stopniach
    assert suspicious_reason(None, 21.0) is None
    assert suspicious_reason(52.0, None) is None


# ------------------------------------------------------------ mapa

def test_map_marks_suspicious_point_orange_with_reason(tmp_path):
    n, text, items = _map(tmp_path, [("ok.jpg", WARSAW), ("ph.jpg", WHOLE)])
    assert n == 2  # podejrzany punkt nadal jest na mapie
    assert len(_ORANGE.findall(text)) == 1  # tylko jeden znacznik wyrozniony
    assert "UWAGA: pelne stopnie bez minut i sekund - mozliwy placeholder" in text  # popup
    assert "[?] ph.jpg" in text  # tooltip
    assert "[?] ok.jpg" not in text
    assert count_suspicious(items) == 1


def test_map_marks_zero_axis_point(tmp_path):
    n, text, items = _map(tmp_path, [("z.jpg", ZERO_LAT)])
    assert n == 1
    assert len(_ORANGE.findall(text)) == 1
    assert "zerowa szerokosc lub dlugosc - mozliwy placeholder" in text
    assert count_suspicious(items) == 1


def test_map_only_normal_points_unchanged(tmp_path):
    n, text, items = _map(tmp_path, [("ok.jpg", WARSAW)])
    assert n == 1
    assert not _ORANGE.search(text)
    assert "placeholder" not in text and "[?]" not in text
    assert count_suspicious(items) == 0


def test_count_suspicious_ignores_items_without_gps(tmp_path):
    p = make_image(tmp_path / "n.jpg")
    items, _ = scan([p], use_exiftool=False)
    assert count_suspicious(items) == 0


def test_suspicious_marker_keeps_js_escaping(tmp_path):
    p = make_image(tmp_path / "a${alert(1)}`b.jpg", gps=WHOLE, make="M${alert(2)}`x\\")
    items, _ = scan([p], use_exiftool=False)
    build_map(items, tmp_path / "m.html", thumbnails=False)
    text = (tmp_path / "m.html").read_text(encoding="utf-8")
    assert _ORANGE.search(text)
    assert "${alert" not in text
    assert "}`b" not in text and "x\\" not in text
    assert "[?] a&#36;{alert(1)}&#96;b.jpg" in text  # tooltip z prefiksem nadal escapowany


# ------------------------------------------------------------ CLI

def test_cli_reports_suspicious_count(tmp_path, capsys):
    d = tmp_path / "z"
    d.mkdir()
    make_image(d / "ok.jpg", gps=WARSAW)
    make_image(d / "ph.jpg", gps=WHOLE)
    make_image(d / "z.jpg", gps=ZERO_LAT)
    rc = main([str(d), "--no-exiftool", "--quiet", "--map", str(tmp_path / "m.html")])
    out = capsys.readouterr().out
    assert rc == 0
    assert "Mapa:" in out and "(3 znacznikow)" in out
    assert "podejrzane wspolrzedne: 2" in out


def test_cli_no_suspicious_line_when_all_ok(tmp_path, capsys):
    d = tmp_path / "z"
    d.mkdir()
    make_image(d / "ok.jpg", gps=WARSAW)
    rc = main([str(d), "--no-exiftool", "--quiet", "--map", str(tmp_path / "m.html")])
    out = capsys.readouterr().out
    assert rc == 0
    assert "Mapa:" in out
    assert "podejrzane" not in out
