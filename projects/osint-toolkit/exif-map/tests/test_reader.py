import math

from exif_map import report
from exif_map.reader import iter_files, read_pillow, scan

from conftest import WARSAW, make_image


def test_reads_gps_camera_time(photos):
    m = read_pillow(photos / "a.jpg")
    assert m.error is None
    assert math.isclose(m.lat, 52 + 13 / 60 + 56.2 / 3600, abs_tol=1e-6)
    assert math.isclose(m.lon, 21 + 0 / 60 + 30.9 / 3600, abs_tol=1e-6)
    assert m.altitude == 110.5
    assert m.direction == 90.0
    assert m.taken == "2024-05-01T10:00:00"
    assert m.camera == "TestCam TC-1"
    assert m.software == "Test 1.0"
    assert m.has_gps and m.warning


def test_southern_western_hemisphere(photos):
    m = read_pillow(photos / "pod" / "b.jpg")
    assert m.lat < 0 and m.lon < 0


def test_below_sea_level(tmp_path):
    p = make_image(tmp_path / "x.jpg", gps=WARSAW + (30.0, 1))
    assert read_pillow(p).altitude == -30.0


def test_no_gps(photos):
    m = read_pillow(photos / "c.png")
    assert not m.has_gps and m.warning is None
    assert m.taken == "2024-05-02T12:00:00"
    assert m.lat is None


def test_image_without_exif(tmp_path):
    from PIL import Image

    Image.new("RGB", (10, 10)).save(tmp_path / "n.jpg")
    m = read_pillow(tmp_path / "n.jpg")
    assert m.error is None and m.taken is None and m.camera == ""


def test_corrupt_file_reports_error(tmp_path):
    p = tmp_path / "bad.jpg"
    p.write_bytes(b"to nie jest obraz")
    assert read_pillow(p).error


def test_iter_files_recursive_and_filters(photos):
    (photos / "notatka.txt").write_text("x")
    names = sorted(p.name for p in iter_files(photos))
    assert names == ["a.jpg", "b.jpg", "c.png"]


def test_scan_without_exiftool_uses_pillow(photos):
    items, exe = scan(iter_files(photos), use_exiftool=False)
    assert exe is None and len(items) == 3
    assert all(m.source == "pillow" for m in items)


def test_exiftool_row_mapping():
    from exif_map.reader import meta_from_exiftool

    m = meta_from_exiftool(
        {"Make": "Apple", "Model": "iPhone 15", "DateTimeOriginal": "2024:05:01 10:00:00.12+02:00",
         "GPSLatitude": -33.865, "GPSLongitude": 151.21, "GPSAltitude": 12.0, "GPSAltitudeRef": 1,
         "GPSImgDirection": 45.5, "LensModel": "x"},
        "f.heic",
    )
    assert m.lat == -33.865 and m.altitude == -12.0 and m.direction == 45.5
    assert m.taken == "2024-05-01T10:00:00" and m.extra["LensModel"] == "x"


def test_report_outputs(photos):
    import csv
    import io
    import json

    items, _ = scan(iter_files(photos), use_exiftool=False)
    table = report.render_table(items, photos)
    assert "TestCam TC-1" in table and "52.232" in table
    warn = report.render_warnings(items, photos)
    assert "2 z 3" in warn and "ujawnia lokalizacje" in warn
    data = json.loads(report.to_json(items))
    assert len(data) == 3 and sum(d["has_gps"] for d in data) == 2
    rows = list(csv.DictReader(io.StringIO(report.to_csv(items))))
    assert len(rows) == 3 and {"lat", "lon", "taken"} <= set(rows[0])


def test_exiftool_cmd_hardened(tmp_path):
    from pathlib import Path

    from exif_map.reader import build_exiftool_cmd

    files = [Path("-overwrite_original"), Path("sub") / "-x.jpg"]
    cmd = build_exiftool_cmd("exiftool.exe", files)
    assert cmd[:3] == ["exiftool.exe", "-config", ""]  # config pierwszy
    i = cmd.index("--")
    assert cmd[3:i] == ["-json", "-n", "-charset", "filename=utf8"]  # przed "--" tylko opcje
    paths = cmd[i + 1 :]
    assert len(paths) == 2
    import os

    assert all(os.path.isabs(p) for p in paths)  # absolutne: nazwa z minusem nie jest opcja
    assert not any(p.startswith("-") for p in paths)


def test_exiftool_runs_with_hardened_cmd(monkeypatch, tmp_path):
    import json
    import subprocess

    from exif_map import reader

    seen = {}

    def fake_run(cmd, **kw):
        seen["cmd"] = cmd
        return subprocess.CompletedProcess(cmd, 0, stdout=json.dumps([]).encode(), stderr=b"")

    monkeypatch.setattr(reader.subprocess, "run", fake_run)
    reader.run_exiftool("x", [tmp_path / "-a.jpg"])
    assert seen["cmd"][1:3] == ["-config", ""] and "--" in seen["cmd"]


def test_csv_neutralizes_formulas_in_text_fields_only():
    import csv
    import io

    from exif_map.models import PhotoMeta

    m = PhotoMeta(path="=HYPERLINK(\"x\").jpg", make="=cmd|' /C calc'!A0", model="+1", software="@SUM(A1)",
                  taken="2024-05-01T10:00:00", lat=-33.5, lon=151.2, altitude=-12.0, width=10, height=5)
    rows = list(csv.DictReader(io.StringIO(report.to_csv([m]))))
    r = rows[0]
    assert r["path"].startswith("'=")
    assert r["make"].startswith("'=")
    assert r["model"] == "'+1"
    assert r["software"].startswith("'@")
    # liczby (takze ujemne) i daty nietkniete
    assert r["lat"] == "-33.5" and r["altitude"] == "-12.0" and r["lon"] == "151.2"
    assert r["taken"] == "2024-05-01T10:00:00"


def test_csv_neutralizes_tab_cr_prefix_and_error():
    import csv
    import io

    from exif_map.models import PhotoMeta

    m = PhotoMeta(path="a.jpg", make="\tx", model="\rx", software="-2+3", error="@err")
    r = list(csv.DictReader(io.StringIO(report.to_csv([m]))))[0]
    assert r["make"] == "'\tx" and r["model"].startswith("'\r") and r["software"] == "'-2+3" and r["error"] == "'@err"


def test_table_escapes_control_chars():
    from exif_map.models import PhotoMeta

    m = PhotoMeta(path="a.jpg", make="Ca\x1b[2Jm", model="X", software="So\r\nFAKE\x07\x9b", error=None)
    out = report.render_table([m])
    assert "\x1b" not in out and "\r" not in out and "\x07" not in out and "\x9b" not in out
    assert "\\x1b" in out and "\\x0d" in out and "\\x0a" in out
    assert len(out.splitlines()) == 3  # naglowek, kreski, jeden wiersz: LF w polu nie lamie tabeli


def test_table_escapes_control_chars_in_filename_and_error():
    from exif_map.models import PhotoMeta

    m = PhotoMeta(path="x\x1b[31m.jpg", error="bad\x1b[0m")
    out = report.render_table([m])
    assert "\x1b" not in out
