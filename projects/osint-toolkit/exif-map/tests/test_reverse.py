from exif_map.cli import main
from exif_map.reverse import ENGINES, SATELLITE


def test_reverse_guide_lists_engines_and_warns_about_gps(photos, capsys):
    assert main([str(photos), "--quiet", "--no-exiftool", "--reverse"]) == 0
    out = capsys.readouterr().out
    for name, url, _ in ENGINES:
        assert name in out and url in out
    assert SATELLITE[0] in out and SATELLITE[1] in out  # Copernicus: tylko link do recznego porownania
    assert "--strip" in out
    assert "a.jpg" in out and "b.jpg" in out  # maja GPS
    assert "c.png" not in out.split("wgranie oryginalu ujawni lokalizacje")[1]  # bez GPS: nie na liscie


def test_reverse_after_strip_points_to_clean_copies(photos, tmp_path, capsys):
    out_dir = tmp_path / "czyste"
    assert main([str(photos), "--quiet", "--no-exiftool", "--strip", str(out_dir), "--reverse"]) == 0
    out = capsys.readouterr().out
    assert f"Wgrywaj kopie bez metadanych z: {out_dir}" in out
    assert "wgranie oryginalu ujawni lokalizacje" not in out


def test_no_face_search_engines():
    names = " ".join(n.lower() for n, _, _ in ENGINES)
    assert "pimeyes" not in names and "facecheck" not in names
