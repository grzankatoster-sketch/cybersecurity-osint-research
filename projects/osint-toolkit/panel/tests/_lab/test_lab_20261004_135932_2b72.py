"""Archiwum raportow: GET /api/raporty (lista + teczki celow) i zakladka Raporty w panelu."""
import json
import os
import sys
import threading
import time
import urllib.error
import urllib.request
from http.server import ThreadingHTTPServer
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
import app  # noqa: E402

SCAN = "20261003T120000Z-ab12"
UN = "un_mozilla_20261003-120000-0a0b0c0d.html"
META = "meta_threads_profile_Mozilla_20261002-090000-11223344.html"
DNS = "dns_example.com_20261001-100000-a1b2c3d4.html"
OLD = "dns_x_20260101-000000.html"
MAPA = "mapa_20261004-080000-deadbeef.html"


def _meta_json(out, html, status, label):
    (out / (html[:-5] + ".json")).write_text(json.dumps({
        "tool": "meta-search", "status": status, "status_label": label,
        "source": {"kind": "api"}, "items": []}), encoding="utf-8")


@pytest.fixture
def archiwum(tmp_path, monkeypatch):
    monkeypatch.setattr(app, "OUT", tmp_path)
    (tmp_path / SCAN).mkdir()
    (tmp_path / SCAN / UN).write_bytes(b"u" * 1234)
    (tmp_path / META).write_bytes(b"m" * 10)
    _meta_json(tmp_path, META, "not_configured", "wymaga konfiguracji")
    (tmp_path / DNS).write_bytes(b"d" * 77)
    (tmp_path / OLD).write_bytes(b"o")
    (tmp_path / MAPA).write_bytes(b"<html>mapa</html>")
    return tmp_path


def test_lista_raportow_najnowsze_na_gorze(archiwum):
    raporty = app.list_reports()["raporty"]
    assert [x["plik"] for x in raporty] == [
        "/wyniki/" + MAPA, f"/wyniki/{SCAN}/{UN}", "/wyniki/" + META, "/wyniki/" + DNS, "/wyniki/" + OLD]
    by = {x["plik"]: x for x in raporty}
    un = by[f"/wyniki/{SCAN}/{UN}"]
    assert (un["narzedzie"], un["cel"], un["data"], un["rozmiar"]) == \
        ("username", "mozilla", "2026-10-03 12:00:00", 1234)
    dns = by["/wyniki/" + DNS]
    assert (dns["narzedzie"], dns["cel"], dns["data"], dns["rozmiar"]) == \
        ("dns", "example.com", "2026-10-01 10:00:00", 77)
    old = by["/wyniki/" + OLD]
    assert (old["narzedzie"], old["cel"], old["data"]) == ("dns", "x", "2026-01-01 00:00:00")
    meta = by["/wyniki/" + META]
    assert (meta["narzedzie"], meta["cel"], meta["data"]) == ("meta", "Mozilla", "2026-10-02 09:00:00")
    mapa = by["/wyniki/" + MAPA]
    assert (mapa["narzedzie"], mapa["cel"], mapa["data"]) == ("exif", None, "2026-10-04 08:00:00")
    # kazdy plik z listy otwiera sie w podgladzie przez istniejaca, bezpieczna sciezke /wyniki/
    for x in raporty:
        assert app.safe_report_path(x["plik"][len("/wyniki/"):]) is not None, x["plik"]


def test_teczki_celow_lacza_narzedzia(archiwum):
    cele = app.list_reports()["cele"]
    assert [c["cel"] for c in cele] == ["mozilla", "example.com", "x"]
    moz = cele[0]
    assert moz["narzedzia"] == ["meta", "username"] and moz["liczba"] == 2
    assert moz["ostatni"] == "2026-10-03 12:00:00"
    ex = cele[1]
    assert (ex["narzedzia"], ex["liczba"], ex["ostatni"]) == (["dns"], 1, "2026-10-01 10:00:00")


def test_brak_katalogu_i_smieci_pomijane(tmp_path, monkeypatch):
    monkeypatch.setattr(app, "OUT", tmp_path / "brak")
    assert app.list_reports() == {"raporty": [], "cele": []}
    monkeypatch.setattr(app, "OUT", tmp_path)
    (tmp_path / "x.json").write_text("{}", encoding="utf-8")
    (tmp_path / "zla nazwa.html").write_text("x", encoding="utf-8")
    (tmp_path / "a" / "b").mkdir(parents=True)
    (tmp_path / "a" / "b" / "c.html").write_text("x", encoding="utf-8")
    (tmp_path / "katalog.html").mkdir()
    note = tmp_path / "notatka.html"
    note.write_bytes(b"n")
    ts = time.mktime((2025, 5, 6, 7, 8, 9, 0, 0, -1))
    os.utime(note, (ts, ts))
    r = app.list_reports()
    assert [x["plik"] for x in r["raporty"]] == ["/wyniki/notatka.html"]
    x = r["raporty"][0]
    assert (x["narzedzie"], x["cel"], x["data"], x["rozmiar"]) == ("inne", None, "2025-05-06 07:08:09", 1)
    assert r["cele"] == []


def test_status_meta_z_json_bez_zamiany_bledu_na_brak(archiwum):
    rl = "meta_instagram_profile_natgeo_20261004-090000-0f0f0f0f.html"
    (archiwum / rl).write_bytes(b"r")
    _meta_json(archiwum, rl, "rate_limited", "limit zapytań")
    zly = "meta_facebook_page_natgeo_20261004-100000-abababab.html"
    (archiwum / zly).write_bytes(b"z")
    (archiwum / (zly[:-5] + ".json")).write_text("{uszkodzony", encoding="utf-8")
    r = app.list_reports()
    by = {x["plik"]: x for x in r["raporty"]}
    assert by["/wyniki/" + rl]["meta"]["status"] == "rate_limited"
    assert by["/wyniki/" + rl]["meta"]["label"] == "limit zapytań"
    assert by["/wyniki/" + META]["meta"]["status"] == "not_configured"
    assert by["/wyniki/" + zly]["meta"] is None and by["/wyniki/" + zly]["cel"] == "natgeo"
    assert by["/wyniki/" + DNS]["meta"] is None
    assert not any(str(f.name).endswith(".json") for f in [Path(x["plik"]) for x in r["raporty"]])
    nat = [c for c in r["cele"] if c["cel"] == "natgeo"][0]
    assert nat["narzedzia"] == ["meta"] and nat["liczba"] == 2
    assert [c["cel"] for c in r["cele"]][0] == "natgeo"


@pytest.fixture
def server(archiwum):
    srv = ThreadingHTTPServer(("127.0.0.1", 0), app.Handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    yield f"http://127.0.0.1:{srv.server_address[1]}"
    srv.shutdown()
    srv.server_close()


def _get(url, headers=None):
    req = urllib.request.Request(url, headers=headers or {})
    try:
        with urllib.request.urlopen(req) as r:
            return r.status, r.headers, r.read()
    except urllib.error.HTTPError as e:
        return e.code, e.headers, e.read()


def test_http_api_raporty_token_filtr_i_host(server):
    status, _, _ = _get(server + "/api/raporty")
    assert status == 403
    status, h, body = _get(server + "/api/raporty", {"X-Panel-Token": app.TOKEN})
    assert status == 200 and h.get("Content-Type", "").startswith("application/json")
    assert "default-src 'none'" in (h.get("Content-Security-Policy") or "")
    data = json.loads(body)
    assert len(data["raporty"]) == 5 and data["raporty"][0]["plik"] == "/wyniki/" + MAPA
    status, _, body = _get(server + "/api/raporty?cel=MOZILLA", {"X-Panel-Token": app.TOKEN})
    assert status == 200
    data = json.loads(body)
    assert [x["plik"] for x in data["raporty"]] == [f"/wyniki/{SCAN}/{UN}", "/wyniki/" + META]
    assert [c["cel"] for c in data["cele"]] == ["mozilla", "example.com", "x"]
    status, _, _ = _get(server + "/api/raporty", {"X-Panel-Token": app.TOKEN, "Host": "evil.example"})
    assert status == 403
    status, _, body = _get(server + f"/wyniki/{SCAN}/{UN}")
    assert status == 200 and body == b"u" * 1234


def test_index_ma_zakladke_raporty():
    html = (Path(app.__file__).parent / "index.html").read_text(encoding="utf-8")
    assert 'data-tab="raporty"' in html and 'id="tab-raporty"' in html
    assert "Raporty" in html
    script = html.split("<script nonce=", 1)[1]
    assert "/api/raporty" in script and "X-Panel-Token" in script
    assert 'data-action="raporty"' not in html
    assert html.count('data-action="meta"') == 6
    assert "allow-same-origin" not in html
