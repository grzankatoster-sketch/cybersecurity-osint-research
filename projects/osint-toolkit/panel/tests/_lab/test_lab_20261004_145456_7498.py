"""Specyfikacja: 'Nastepny krok' - podpowiedzi kolejnych sprawdzen z wyniku narzedzia, tylko w zakresie celu."""
import json
import subprocess
import sys
import threading
import urllib.error
import urllib.request
from http.server import ThreadingHTTPServer
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))
import app  # noqa: E402

HARVESTER_OUT = "\n".join([
    "[*] Target: example.com",
    "[*] Searching Crtsh.",
    "certspotter: http-503 sklep.example.com",
    "[*] IPs found: 1",
    "-------------------",
    "93.184.215.14",
    "[*] Emails found: 3",
    "----------------------",
    "admin@example.com",
    "kontakt@poczta.example.com",
    "jan@gmail.com",
    "[*] Hosts found: 6",
    "---------------------",
    "www.example.com:93.184.215.14",
    "WWW.Example.com",
    "mail.example.com",
    "example.com",
    "cdn.evil-example.org:1.2.3.4",
    "example.com.evil.net:5.6.7.8",
    "",
])

APEX_HARVESTER = {("dns", "example.com"), ("hibp_domain", "example.com")}


def _pairs(pivots):
    return [(p["action"], p["params"].get("domain") or p["params"].get("username")) for p in pivots]


def _fake_run(stdout, code=0):
    def run(cmd, *a, **k):
        return subprocess.CompletedProcess(cmd, code, stdout, "")
    return run


@pytest.fixture
def server():
    srv = ThreadingHTTPServer(("127.0.0.1", 0), app.Handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    yield f"http://127.0.0.1:{srv.server_address[1]}"
    srv.shutdown()


def test_harvester_run_returns_scoped_pivots(tmp_path, monkeypatch):
    monkeypatch.setattr(app, "OUT", tmp_path)
    monkeypatch.setattr(app.subprocess, "run", _fake_run(HARVESTER_OUT))
    r = app.run_tool("harvester", {"domain": "Example.com", "source": "crtsh"})
    pairs = _pairs(r["pivots"])
    assert set(pairs) == APEX_HARVESTER | {("dns", "www.example.com"), ("dns", "mail.example.com"),
                                           ("dns", "poczta.example.com")}
    assert len(pairs) == len(set(pairs))  # bez duplikatow (WWW.Example.com, example.com)
    assert r["poza_zakresem"] == ["cdn.evil-example.org", "example.com.evil.net", "gmail.com"]
    assert r["obciete"] == 0
    dumped = json.dumps(r["pivots"]) + json.dumps(r["poza_zakresem"])
    assert "93.184" not in dumped and "jan@" not in dumped and "sklep" not in dumped
    assert r["code"] == 0 and r["stdout"] == HARVESTER_OUT and r["report"] is None
    for p in r["pivots"]:
        assert p["params"]["domain"] in p["label"]


def test_failed_source_lines_and_timeout_do_not_become_pivots(tmp_path, monkeypatch):
    monkeypatch.setattr(app, "OUT", tmp_path)
    out = ("[*] Searching Certspotter.\ncertspotter: http-503 sklep.example.com\n"
           "[*] Hosts found: 1\n---------------------\nwww.example.com\n")
    monkeypatch.setattr(app.subprocess, "run", _fake_run(out, code=1))
    r = app.run_tool("harvester", {"domain": "example.com"})
    assert r["code"] == 1
    assert set(_pairs(r["pivots"])) == APEX_HARVESTER | {("dns", "www.example.com")}

    def boom(*a, **k):
        raise app.subprocess.TimeoutExpired("x", 1)
    monkeypatch.setattr(app.subprocess, "run", boom)
    r = app.run_tool("harvester", {"domain": "example.com"})
    assert r["code"] == -1 and "limit czasu" in r["stderr"]
    assert set(_pairs(r["pivots"])) == APEX_HARVESTER
    assert r["poza_zakresem"] == [] and r["obciete"] == 0


def test_params_pivots_for_username_and_domain_tools():
    res = app.pivots("username", {"username": " mozilla "}, "")
    assert [(p["action"], p["params"]) for p in res["pivots"]] == [("meta", {"op": "links", "username": "mozilla"})]
    assert app.pivots("username", {"username": "Jan Kowalski"}, "")["pivots"] == []
    assert _pairs(app.pivots("dns", {"domain": "Example.com"}, "")["pivots"]) == \
        [("harvester", "example.com"), ("hibp_domain", "example.com")]
    assert _pairs(app.pivots("hibp_domain", {"domain": "example.com"}, "")["pivots"]) == \
        [("dns", "example.com"), ("harvester", "example.com")]


@pytest.mark.parametrize("action,params", [
    ("phone", {"number": "+48 22 123 45 67"}),
    ("exif", {"path": "."}),
    ("hibp_catalog", {}),
    ("meta", {"op": "links", "username": "natgeo"}),
    ("harvester", {"domain": "a..pl"}),
    ("dns", {"domain": {"x": 1}}),
    ("username", {"username": ["x"]}),
])
def test_no_pivots_for_phone_photos_and_invalid_params(action, params):
    text = "biuro@example.com https://www.example.com\n[*] Hosts found: 1\n---\nwww.example.com\n"
    assert app.pivots(action, params, text) == {"pivots": [], "poza_zakresem": [], "obciete": 0}


def test_pivots_capped_and_each_is_valid_command():
    hosts = "\n".join(f"h{i:02d}.example.com" for i in range(60))
    res = app.pivots("harvester", {"domain": "example.com"}, "[*] Hosts found: 60\n-----\n" + hosts + "\n")
    assert 0 < app.MAX_PIVOTS < 60
    assert len(res["pivots"]) == app.MAX_PIVOTS and res["obciete"] == 62 - app.MAX_PIVOTS
    pairs = _pairs(res["pivots"])
    assert pairs[:3] == [("dns", "example.com"), ("hibp_domain", "example.com"), ("dns", "h00.example.com")]
    for p in res["pivots"]:
        tool, _, _ = app.build_command(p["action"], p["params"])
        assert tool in ("dns", "hibp")


def test_pivots_reach_panel_over_http_and_index_renders_them(server, tmp_path, monkeypatch):
    monkeypatch.setattr(app, "OUT", tmp_path)
    monkeypatch.setattr(app.subprocess, "run", _fake_run(HARVESTER_OUT))
    req = urllib.request.Request(server + "/api/harvester", method="POST",
                                 data=json.dumps({"domain": "example.com", "source": "crtsh"}).encode(),
                                 headers={"Content-Type": "application/json", "X-Panel-Token": app.TOKEN})
    try:
        with urllib.request.urlopen(req) as resp:
            status, body = resp.status, json.loads(resp.read())
    except urllib.error.HTTPError as e:
        status, body = e.code, json.loads(e.read())
    assert status == 200, body
    assert ("dns", "www.example.com") in _pairs(body["pivots"])
    assert "gmail.com" in body["poza_zakresem"]
    html = (Path(app.__file__).parent / "index.html").read_text(encoding="utf-8")
    assert "r.pivots" in html and "Następny krok" in html and "r.poza_zakresem" in html
    assert html.count('data-action="meta"') == 6
