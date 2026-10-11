"""Zakładka Sprawa: panel jako cienka warstwa nad entity-graph. Dane syntetyczne, bez sieci."""
import json
import re
import sys
import threading
import urllib.error
import urllib.request
from http.server import ThreadingHTTPServer
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import app  # noqa: E402

PURPOSE = "due diligence kontrahenta na zlecenie klienta, sprawa 2026/41"


@pytest.fixture
def roots(tmp_path, monkeypatch):
    out = tmp_path / "wyniki"
    (out / "sprawy").mkdir(parents=True)
    monkeypatch.setattr(app, "OUT", out)
    monkeypatch.setattr(app, "SPRAWY", out / "sprawy")
    return out


def _fake_case(roots, name="s1"):
    d = roots / "sprawy" / name
    d.mkdir()
    (d / "graph.json").write_text("{}", encoding="utf-8")
    (d / "audit.jsonl").write_text("", encoding="utf-8")
    return d


@pytest.fixture(scope="module")
def server():
    srv = ThreadingHTTPServer(("127.0.0.1", 0), app.Handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    yield f"http://127.0.0.1:{srv.server_address[1]}"
    srv.shutdown()


@pytest.fixture
def no_tools(monkeypatch):
    calls = []
    monkeypatch.setattr(app.subprocess, "run", lambda *a, **k: calls.append(a) or pytest.fail("narzedzie wystartowalo"))
    return calls


def _post(url, raw: bytes, token=None):
    req = urllib.request.Request(url, data=raw, method="POST",
                                 headers={"Content-Type": "application/json", "X-Panel-Token": token or app.TOKEN})
    try:
        with urllib.request.urlopen(req) as r:
            return r.status, json.loads(r.read())
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read())


# --- polecenia: lista argumentów, bez powłoki, tylko katalogi z wyniki/sprawy ---------------------------

def test_case_commands(roots):
    d = _fake_case(roots)
    tool, args, report = app.build_command("sprawa", {"sprawa": "s1"})
    assert (tool, args, report) == ("sprawa", ["sprawa", str(d)], "sprawy/s1/report.html")
    _, args, _ = app.build_command("sprawa_relacja", {
        "sprawa": "s1", "osoba": "Anna Kowalska", "typ": "rodzic", "druga_osoba": "Jan Kowalski",
        "zrodlo": "dokument:dokumenty/akt.pdf", "dowod": "akt wskazuje matkę", "fragment": "", "opis": "",
        "dodaj": True})
    assert args == ["relacja", str(d), "--person", "Anna Kowalska", "--typ", "rodzic", "--druga-osoba", "Jan Kowalski",
                    "--zrodlo", "dokument:dokumenty/akt.pdf", "--dowod", "akt wskazuje matkę", "--dodaj"]
    _, args, _ = app.build_command("sprawa_relacja_decyzja", {"sprawa": "s1", "id": "r-0123456789",
                                                              "decyzja": "odrzuc", "dowod": "inna osoba w akcie"})
    assert args[-1] == "--odrzuc" and args[:2] == ["relacja-potwierdz", str(d)]
    _, args, _ = app.build_command("sprawa_profil_decyzja", {"sprawa": "s1", "osoba": "Jan Kowalski", "decyzja":
                                                             "potwierdz", "profil": "https://x.example/jk",
                                                             "dowod": "zdjęcie i firma zgodne"})
    assert args[0] == "potwierdz" and "--odrzuc" not in args
    _, args, _ = app.build_command("sprawa_telefon_reczny", {"sprawa": "s1", "numer": "+48 603 123 456",
                                                             "operator_aktualny": "Play", "data": "2026-10-01",
                                                             "zrodlo": "https://numeracja.uke.gov.pl/"})
    assert args[-6:] == ["--operator-aktualny", "Play", "--zrodlo", "https://numeracja.uke.gov.pl/", "--data", "2026-10-01"]
    tool, args, _ = app.build_command("sprawa_kandydaci", {"sprawa": "s1", "osoba": "Jan Kowalski", "nazwa": "",
                                                           "max_zapytan": "2", "tags": "social", "limit": ""})
    assert tool == "sprawa_kandydaci" and tool in app.LONG_TOOLS
    assert args[:4] == ["kandydaci", str(d), "--person", "Jan Kowalski"] and "--max-queries" in args
    assert args[args.index("--max-queries") + 1] == "2" and args[-2:] == ["--ue-tags", "social"]
    tool, args, _ = app.build_command("sprawa_nowa", {"sprawa": "nowa-1", "cel": PURPOSE, "osoba": "Jan Kowalski"})
    assert args[:3] == ["run", "--purpose", PURPOSE] and "--offline" in args and args[-1] == str(roots / "sprawy" / "nowa-1")
    cmd, env = app.launch("sprawa", ["sprawa", str(d)])
    assert cmd[-4:] == ["-m", "entity_graph", "sprawa", str(d)] and env["PYTHONPATH"].startswith(str(app.ROOT / "entity-graph"))


@pytest.mark.parametrize("name", ["..", "../wyniki", "..\\..", "a/b", "C:\\Windows", "-x", "s 1", "", "s1/../s1",
                                  ".ukryta", "x" * 65])
def test_case_dir_rejects_paths_outside_root(roots, name):
    _fake_case(roots)
    with pytest.raises(ValueError):
        app.build_command("sprawa", {"sprawa": name})


def test_case_dir_requires_case_files_and_new_case_must_not_exist(roots):
    (roots / "sprawy" / "pusta").mkdir()
    with pytest.raises(ValueError, match="nie ma sprawy"):
        app.build_command("sprawa", {"sprawa": "pusta"})
    _fake_case(roots)
    with pytest.raises(ValueError, match="istnieje"):
        app.build_command("sprawa_nowa", {"sprawa": "s1", "cel": PURPOSE, "osoba": "Jan Kowalski"})


def test_case_dir_rejects_junction_outside_root(roots, tmp_path):
    winapi = pytest.importorskip("_winapi")
    target = tmp_path / "poza"
    target.mkdir()
    (target / "graph.json").write_text("{}", encoding="utf-8")
    (target / "audit.jsonl").write_text("", encoding="utf-8")
    try:
        winapi.CreateJunction(str(target), str(roots / "sprawy" / "skrot"))
    except (OSError, AttributeError):
        pytest.skip("nie można utworzyć junction")
    with pytest.raises(ValueError, match="poza"):
        app.build_command("sprawa", {"sprawa": "skrot"})
    assert "skrot" not in [c["nazwa"] for c in app.list_cases()]


@pytest.mark.parametrize("action,params", [
    ("sprawa_relacja", {"osoba": "--help", "typ": "rodzic", "druga_osoba": "B b", "zrodlo": "https://a.example/x", "dowod": "dowód dowód"}),
    ("sprawa_relacja", {"osoba": "A a", "typ": "kuzyn", "druga_osoba": "B b", "zrodlo": "https://a.example/x", "dowod": "dowód dowód"}),
    ("sprawa_relacja", {"osoba": "A a", "typ": "rodzic", "druga_osoba": "B b", "zrodlo": "javascript:alert(1)", "dowod": "dowód dowód"}),
    ("sprawa_relacja", {"osoba": "A a", "typ": "rodzic", "druga_osoba": "B b", "zrodlo": "dokument:../../app.py", "dowod": "dowód dowód"}),
    ("sprawa_relacja", {"osoba": "A a", "typ": "rodzic", "druga_osoba": "B b", "zrodlo": "file:///C:/x", "dowod": "dowód dowód"}),
    ("sprawa_relacja", {"osoba": "A a", "typ": "rodzic", "druga_osoba": "B b", "zrodlo": "https://a.example/x", "dowod": "-x dowód"}),
    ("sprawa_relacja", {"osoba": "A a", "typ": "rodzic", "druga_osoba": "B b", "zrodlo": "https://a.example/x", "dowod": "a\nb"}),
    ("sprawa_relacja_decyzja", {"id": "../x", "decyzja": "potwierdz", "dowod": "dowód dowód"}),
    ("sprawa_relacja_decyzja", {"id": "r-0123456789", "decyzja": "auto", "dowod": "dowód dowód"}),
    ("sprawa_profil_decyzja", {"osoba": "A a", "profil": "javascript:x", "decyzja": "potwierdz", "dowod": "d d"}),
    ("sprawa_telefon", {"numer": "-603"}),
    ("sprawa_telefon", {"numer": "603; rm", "region": "PL"}),
    ("sprawa_telefon_reczny", {"numer": "603123456", "operator_aktualny": "Play", "zrodlo": "https://u.example", "data": "jutro"}),
    ("sprawa_kandydaci", {"osoba": "A a", "nazwa": "x"}),
    ("sprawa_kandydaci", {}),
    ("sprawa_kandydaci", {"osoba": "A a", "max_zapytan": "11"}),
    ("sprawa_kandydaci", {"osoba": "A a", "max_koszt": "500"}),
    ("sprawa_kandydaci", {"osoba": "A a", "max_sekund": "99999"}),
    ("sprawa_kandydaci", {"osoba": "A a", "nazwy": "--all"}),
])
def test_bad_case_input_rejected(roots, action, params):
    _fake_case(roots)
    with pytest.raises(ValueError):
        app.build_command(action, {"sprawa": "s1", **params})


# --- serwer: JSON, typy, token, traversal: nic nie startuje -------------------------------------------------

@pytest.mark.parametrize("raw", [b"{", b"[]", b"null", b'"s1"', b'{"sprawa": "s1"' + b"}" * 2])
def test_case_invalid_json_is_400_without_tool(server, roots, no_tools, raw):
    _fake_case(roots)
    status, body = _post(server + "/api/sprawa", raw)
    assert status in (400, 500) and not no_tools
    assert status == 400 or "JSONDecodeError" in body["error"]


@pytest.mark.parametrize("doc", [{"sprawa": 1}, {"sprawa": ["s1"]}, {"sprawa": {"x": 1}},
                                 {"sprawa": "s1", "osoba": "A a", "typ": "rodzic", "druga_osoba": "B b",
                                  "zrodlo": "https://a.example/x", "dowod": "dowód dowód", "dodaj": "true"},
                                 {"sprawa": "s1", "osoba": "A a", "max_zapytan": 2.5}])
def test_case_wrong_types_are_422_without_tool(server, roots, no_tools, doc):
    _fake_case(roots)
    action = "sprawa_kandydaci" if "max_zapytan" in doc else ("sprawa_relacja" if "typ" in doc else "sprawa")
    status, body = _post(server + "/api/" + action, json.dumps(doc).encode())
    assert status == 422 and body["error"].startswith("pole ") and not no_tools


@pytest.mark.parametrize("name", ["../../..", "..", "C:/Windows", "s1/../../x", "-h"])
def test_case_traversal_is_400_without_tool(server, roots, no_tools, name):
    _fake_case(roots)
    status, _ = _post(server + "/api/sprawa", json.dumps({"sprawa": name}).encode())
    assert status == 400 and not no_tools


def test_case_token_required(server, roots, no_tools):
    _fake_case(roots)
    assert _post(server + "/api/sprawa", b'{"sprawa": "s1"}', token="zly")[0] == 403
    req = urllib.request.Request(server + "/api/sprawy")
    with pytest.raises(urllib.error.HTTPError) as e:
        urllib.request.urlopen(req)
    assert e.value.code == 403 and not no_tools
    req = urllib.request.Request(server + "/api/sprawy", headers={"X-Panel-Token": app.TOKEN})
    with urllib.request.urlopen(req) as r:
        assert [c["nazwa"] for c in json.loads(r.read())["sprawy"]] == ["s1"]


def test_case_report_path_only_report_html(roots):
    d = _fake_case(roots)
    (d / "report.html").write_text("<p>x</p>", encoding="utf-8")
    (d / "graph.html").write_text("<p>x</p>", encoding="utf-8")
    assert app.safe_report_path("sprawy/s1/report.html") == d / "report.html"
    for bad in ("sprawy/s1/graph.html", "inne/s1/report.html", "sprawy/../report.html", "sprawy/s1/x/report.html"):
        assert app.safe_report_path(bad) is None


# --- interfejs: dane sprawy tylko jako tekst -------------------------------------------------------------

def test_index_case_view_uses_text_only():
    html = (Path(app.PANEL) / "index.html").read_text(encoding="utf-8")
    assert 'data-tab="sprawa"' in html and 'id="tab-sprawa"' in html
    assert not re.search(r"innerHTML|outerHTML|insertAdjacentHTML|document\.write", html)
    lower = html.lower()
    for phrase in ("lokalizacja telefonu", "znaleziono osob", "ustalono rodzin"):
        assert phrase not in lower
    assert "region planu numeracyjnego" in lower and "wymaga" in lower


# --- koniec do końca: prawdziwy entity-graph jako podproces (offline) --------------------------------------

def test_case_end_to_end_with_entity_graph(server, roots):
    evil = "<script>alert(1)</script> Nowak"
    status, r = _post(server + "/api/sprawa_nowa", json.dumps(
        {"sprawa": "e2e", "cel": PURPOSE, "osoba": "Jan Kowalski"}).encode())
    assert status == 200 and r["code"] == 0, r
    case = roots / "sprawy" / "e2e"
    (case / "dokumenty").mkdir()
    (case / "dokumenty" / "akt.txt").write_text("syntetyczny dokument", encoding="utf-8")
    status, r = _post(server + "/api/sprawa_relacja", json.dumps({
        "sprawa": "e2e", "osoba": evil, "typ": "rodzic", "druga_osoba": "Jan Kowalski",
        "zrodlo": "dokument:dokumenty/akt.txt", "dowod": 'akt wskazuje "><img src=x onerror=alert(2)>',
        "fragment": "", "opis": "", "dodaj": True}).encode())
    assert status == 200 and r["code"] == 0, r
    status, r = _post(server + "/api/sprawa", b'{"sprawa": "e2e"}')
    assert status == 200 and r["code"] == 0, r
    view = r["sprawa"]
    claim = view["claims"][0]
    assert claim["decision"] == "oczekuje" and claim["confidence"] == 0.0 and claim["a"] == evil
    assert {p["value"] for p in view["people"]} == {"Jan Kowalski", evil}
    assert r["report"] == "/wyniki/sprawy/e2e/report.html"
    with urllib.request.urlopen(server + r["report"]) as resp:
        body = resp.read().decode("utf-8")
        assert "sandbox" in resp.headers["Content-Security-Policy"]
    assert "<script>alert(1)" not in body and "<img src=x" not in body and "Twierdzenia o relacjach" in body
    status, r = _post(server + "/api/sprawa_relacja_decyzja", json.dumps({
        "sprawa": "e2e", "id": claim["id"], "decyzja": "potwierdz", "dowod": "sprawdzono oryginał u klienta"}).encode())
    assert status == 200 and r["code"] == 0, r
    events = [json.loads(x)["event"] for x in (case / "audit.jsonl").read_text(encoding="utf-8").splitlines()]
    assert events.count("relation_claim") == 2 and events.count("relation_decision") == 2
