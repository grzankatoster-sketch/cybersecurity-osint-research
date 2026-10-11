import json

from exif_map.cli import main
from exif_map.mapview import build_map
from exif_map.reader import iter_files, scan


def test_map_generates_html_with_markers_and_route(photos, tmp_path):
    items, _ = scan(iter_files(photos), use_exiftool=False)
    out = tmp_path / "mapa.html"
    n = build_map(items, out)
    assert n == 2
    html = out.read_text(encoding="utf-8")
    assert "leaflet" in html.lower()
    assert "a.jpg" in html and "b.jpg" in html
    assert "data:image/jpeg;base64" in html  # miniatury
    assert "L.polyline" in html  # trasa wg czasu (2 punkty z czasem)
    assert "c.png" not in html  # bez GPS: brak znacznika


def test_map_without_gps_creates_nothing(tmp_path):
    from conftest import make_image

    p = make_image(tmp_path / "n.jpg")
    items, _ = scan([p], use_exiftool=False)
    assert build_map(items, tmp_path / "m.html") == 0
    assert not (tmp_path / "m.html").exists()


def test_map_escapes_html_in_names(tmp_path):
    from conftest import WARSAW, make_image

    p = make_image(tmp_path / "x&y.jpg", gps=WARSAW)
    items, _ = scan([p], use_exiftool=False)
    build_map(items, tmp_path / "m.html")
    assert "x&amp;y.jpg" in (tmp_path / "m.html").read_text(encoding="utf-8")


def test_cli_table_json_csv_map_strip(photos, tmp_path, capsys):
    out = tmp_path / "out"
    rc = main([str(photos), "--no-exiftool", "--csv", str(tmp_path / "w.csv"), "--map", str(tmp_path / "m.html"),
               "--strip", str(out)])
    text = capsys.readouterr().out
    assert rc == 0
    assert "UWAGA: 2 z 3" in text and "TestCam TC-1" in text
    assert "Mapa:" in text and "Strip: 3/3" in text
    assert (tmp_path / "m.html").exists() and (tmp_path / "w.csv").exists()
    assert len(list(out.rglob("*.*"))) == 3


def test_cli_json_stdout_is_clean(photos, capsys):
    rc = main([str(photos), "--no-exiftool", "--json"])
    cap = capsys.readouterr()
    assert rc == 0
    data = json.loads(cap.out)  # stdout = czysty JSON
    assert len(data) == 3
    assert "UWAGA" in cap.err


def test_cli_missing_path(tmp_path, capsys):
    assert main([str(tmp_path / "nie_ma")]) == 2


# ---------------------------------------------------------------- bezpieczenstwo mapy (folium: literaly szablonowe JS)

def _evil_map(tmp_path, **kw):
    from conftest import WARSAW, make_image

    p = make_image(tmp_path / "a${alert(1)}b.jpg", gps=WARSAW, make="M${alert(2)}`x\\", model="Mo`d${alert(3)}")
    items, _ = scan([p], use_exiftool=False)
    build_map(items, tmp_path / "m.html", **kw)
    return (tmp_path / "m.html").read_text(encoding="utf-8")


def test_map_neutralizes_js_template_literals(tmp_path):
    text = _evil_map(tmp_path)
    assert "${alert" not in text  # brak interpolacji ${...} z danych uzytkownika
    assert "M&#36;{alert(2)}" in text  # tresc nadal widoczna (jako encja HTML)
    # surowy backtick/backslash z danych nie moga zamknac ani zmienic literalu
    assert "Mo`d" not in text and r"Mo\`d" not in text
    assert "x`" not in text and "x\\" not in text


def test_map_no_tiles_option(tmp_path):
    text = _evil_map(tmp_path, tiles=False)
    assert "tile.openstreetmap.org" not in text
    assert "L.tileLayer" not in text
    assert "L.marker" in text


def test_map_default_has_tiles_and_banner_warns_network(tmp_path):
    text = _evil_map(tmp_path)
    assert "tile.openstreetmap.org" in text
    assert "OpenStreetMap" in text and "CDN" in text  # baner ostrzega o laczeniu z siecia


def test_map_no_tiles_banner(tmp_path):
    text = _evil_map(tmp_path, tiles=False)
    assert "CDN" in text  # Leaflet dalej z CDN: baner nie klamie
    assert "kafelk" in text.lower()


def test_cli_no_tiles_flag(photos, tmp_path):
    rc = main([str(photos), "--no-exiftool", "--quiet", "--map", str(tmp_path / "m.html"), "--no-tiles"])
    assert rc == 0
    assert "tile.openstreetmap.org" not in (tmp_path / "m.html").read_text(encoding="utf-8")
