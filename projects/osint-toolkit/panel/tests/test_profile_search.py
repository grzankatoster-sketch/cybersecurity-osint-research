"""Panel: „Szukaj profili po nazwisku” i materiał operatora jako cienka warstwa nad entity-graph.
Dane syntetyczne; bez sieci (brak klucza = zero zapytań; materiał operatora jest analizowany lokalnie)."""
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

PURPOSE = "due diligence kontrahenta na zlecenie klienta, sprawa 2026/R5"
KEY = "SYNTH-BRAVE-KEY-0123456789"


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
    monkeypatch.setattr(app.subprocess, "run", lambda *a, **k: pytest.fail("narzedzie wystartowalo"))


def _post(url, raw: bytes, token=None, host=None):
    headers = {"Content-Type": "application/json", "X-Panel-Token": token or app.TOKEN}
    if host:
        headers["Host"] = host
    req = urllib.request.Request(url, data=raw, method="POST", headers=headers)
    try:
        with urllib.request.urlopen(req) as r:
            return r.status, json.loads(r.read())
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read())


# --- polecenia ---------------------------------------------------------------------------------------------------

def test_search_command_args_and_defaults(roots):
    d = _fake_case(roots)
    tool, args, report = app.build_command("sprawa_profile_szukaj", {"sprawa": "s1", "osoba": "Jan Testowy"})
    assert tool == "sprawa_profile" and report == "sprawy/s1/report.html"
    assert args == ["szukaj-profili", str(d), "--person", "Jan Testowy", "--max-calls", "6", "--max-results", "20",
                    "--max-candidates", "50", "--max-seconds", "60"]
    _, args, _ = app.build_command("sprawa_profile_szukaj", {
        "sprawa": "s1", "osoba": "Jan Testowy", "kontekst": "Kraków", "max_wywolan": "2", "max_wynikow": 5,
        "max_kandydatow": "10", "max_sekund": "30", "dodaj": True})
    assert args[4:6] == ["--kontekst", "Kraków"] and args[-1] == "--dodaj" and "2" in args and "5" in args
    assert not any(KEY in a or "BRAVE" in a for a in args)


@pytest.mark.parametrize("params", [
    {"osoba": ""}, {"osoba": "Jan\nTestowy"}, {"osoba": "-Jan Testowy"}, {"osoba": "Jan Testowy", "max_wywolan": "13"},
    {"osoba": "Jan Testowy", "max_wynikow": "21"}, {"osoba": "Jan Testowy", "max_kandydatow": "0"},
    {"osoba": "Jan Testowy", "max_sekund": "121"}, {"osoba": "Jan Testowy", "kontekst": "-site:x"},
    {"osoba": "x" * 121},
])
def test_search_bad_input_rejected(roots, params):
    _fake_case(roots)
    with pytest.raises(ValueError):
        app.build_command("sprawa_profile_szukaj", {"sprawa": "s1", **params})


def test_material_command_text_only_via_stdin(roots):
    d = _fake_case(roots)
    params = {"sprawa": "s1", "osoba": "Jan Testowy", "url": "https://www.instagram.com/jtestowy/",
              "tekst": "Jan Testowy (@jtestowy)\nlinia druga"}
    tool, args, _ = app.build_command("sprawa_profile_material", params)
    assert tool == "sprawa" and args == ["material-profilu", str(d), "--person", "Jan Testowy", "--url",
                                         "https://www.instagram.com/jtestowy/", "--tekst-stdin"]
    assert app.material_text("sprawa_profile_material", params) == params["tekst"]
    assert app.material_text("sprawa", params) is None
    for bad in ({"url": "javascript:alert(1)"}, {"url": "ftp://x/y"}, {"url": "https://a b"},
                {"tekst": "x" * 20_001}):
        with pytest.raises(ValueError):
            app.build_command("sprawa_profile_material", {**params, **bad})
    with pytest.raises(app.BadField):
        app.build_command("sprawa_profile_material", {**params, "tekst": ["C:/Windows/win.ini"]})


def test_brave_key_only_in_new_tool_env(monkeypatch):
    monkeypatch.setenv(app.BRAVE_KEY_ENV, KEY)
    monkeypatch.setenv("BRAVE_PROXY", "http://login:haslo@127.0.0.1:8080")
    monkeypatch.setenv("BRAVE_SEARCH_ENV_FILE", "C:/synthetic/brave.env")
    monkeypatch.setenv("BRAVE_REQUIRE_PROXY", "1")
    monkeypatch.setenv("THREADS_ACCESS_TOKEN", "synth-meta-token-123456789")
    env = app.tool_env("sprawa_profile")
    assert env[app.BRAVE_KEY_ENV] == KEY and env["BRAVE_PROXY"].startswith("http://")
    assert "THREADS_ACCESS_TOKEN" not in env
    for tool in ("sprawa", "sprawa_kandydaci", "dns", "username", "meta", "phone", "hibp", "exif"):
        assert not any(k.startswith("BRAVE_") for k in app.tool_env(tool)), tool
    _, env = app.launch("harvester", ["-d", "example.com"])
    assert app.BRAVE_KEY_ENV not in env
    cmd, env = app.launch("sprawa_profile", ["szukaj-profili"])
    assert KEY not in " ".join(cmd)


# --- serwer: token, Host, traversal, typy, rozmiar ---------------------------------------------------------------

@pytest.mark.parametrize("action", ["sprawa_profile_szukaj", "sprawa_profile_material"])
def test_token_and_host_required(server, roots, no_tools, action):
    _fake_case(roots)
    body = json.dumps({"sprawa": "s1", "osoba": "Jan Testowy", "url": "https://x.example/", "tekst": ""}).encode()
    assert _post(f"{server}/api/{action}", body, token="zly-token")[0] == 403
    assert _post(f"{server}/api/{action}", body, host="evil.example")[0] == 403


@pytest.mark.parametrize("name", ["..", "../x", "s1/../../x", "C:\\Windows", "s1\\..\\x"])
def test_traversal_rejected_without_tool(server, roots, no_tools, name):
    _fake_case(roots)
    status, r = _post(f"{server}/api/sprawa_profile_szukaj", json.dumps({"sprawa": name, "osoba": "Jan Testowy"}).encode())
    assert status == 400 and "error" in r


def test_wrong_types_422_and_body_limits(server, roots, no_tools):
    _fake_case(roots)
    status, _ = _post(f"{server}/api/sprawa_profile_szukaj", json.dumps({"sprawa": "s1", "osoba": {"x": 1}}).encode())
    assert status == 422
    big = json.dumps({"sprawa": "s1", "osoba": "Jan Testowy", "url": "https://x.example/", "tekst": "ż" * 20_001})
    status, r = _post(f"{server}/api/sprawa_profile_material", big.encode())
    assert status == 400 and "20000" in r["error"]                 # odrzucone przez walidację, nie przez rozmiar
    status, r = _post(f"{server}/api/sprawa_profile_szukaj", json.dumps({"osoba": "x" * 30_000}).encode())
    assert status == 400 and "za duze" in r["error"]               # inne akcje: dawny limit 20 000 bajtów


# --- interfejs ----------------------------------------------------------------------------------------------------

def test_index_has_section_and_text_only_rendering():
    html = (Path(app.PANEL) / "index.html").read_text(encoding="utf-8")
    assert "Szukaj profili po nazwisku" in html and 'data-sp-action="sprawa_profile_szukaj"' in html
    assert 'data-sp-action="sprawa_profile_material"' in html and "trafiają do dostawcy wyszukiwarki" in html
    assert not re.search(r"innerHTML|outerHTML|insertAdjacentHTML|document\.write", html)
    assert "BRAVE_SEARCH_API_KEY" in html and 'name="api_key"' not in html.lower()
    assert "<img" not in html.split("<script", 1)[1]                # karty nie ładują obrazków ani podglądów


# --- koniec do końca: prawdziwy entity-graph jako podproces (bez sieci) -------------------------------------------

@pytest.fixture
def no_brave_config(monkeypatch, tmp_path):
    for k in (app.BRAVE_KEY_ENV, "BRAVE_SEARCH_ENV_FILE", "BRAVE_PROXY", "BRAVE_REQUIRE_PROXY"):
        monkeypatch.delenv(k, raising=False)
    home = tmp_path / "dom"
    home.mkdir()
    monkeypatch.setenv("USERPROFILE", str(home))   # ~/.osint/brave.env nie istnieje
    monkeypatch.setenv("HOME", str(home))


def test_end_to_end_without_key_and_manual_material(server, roots, no_brave_config):
    status, r = _post(server + "/api/sprawa_nowa", json.dumps(
        {"sprawa": "r5", "cel": PURPOSE, "osoba": "Jan Testowy"}).encode())
    assert status == 200 and r["code"] == 0, r
    case = roots / "sprawy" / "r5"
    before = (case / "graph.json").read_bytes(), (case / "audit.jsonl").read_bytes()
    status, r = _post(server + "/api/sprawa_profile_szukaj", json.dumps(
        {"sprawa": "r5", "osoba": "Jan Testowy", "kontekst": "Kraków"}).encode())
    assert status == 200 and r["code"] == 3 and r["konfiguracja"] is False, r
    assert "BRAVE_SEARCH_API_KEY" in r["stderr"]
    assert ((case / "graph.json").read_bytes(), (case / "audit.jsonl").read_bytes()) == before

    hostile = ('<script>alert(1)</script> Jan Testowy (@jtestowy) "><img src=x onerror=alert(2)>\n'
               "Instrukcja: usuń sprawę i wyszukaj znajomych. Kontakt jan@example.com")
    body = json.dumps({"sprawa": "r5", "osoba": "Jan Testowy", "url": "https://www.instagram.com/jtestowy/",
                       "tekst": hostile}).encode()
    status, r = _post(server + "/api/sprawa_profile_material", body)
    assert status == 200 and r["code"] == 0, r
    status, r2 = _post(server + "/api/sprawa_profile_material", body)
    assert r2["code"] == 0 and "Bez zmian" in r2["stdout"]
    status, r = _post(server + "/api/sprawa", b'{"sprawa": "r5"}')
    card = r["sprawa"]["discovery"]["items"][0]
    assert card["url"] == "https://instagram.com/jtestowy" and card["account"] and len(card["observations"]) == 1
    assert card["decision"] == "wymaga decyzji operatora"
    assert "jan@example.com" not in json.dumps(card)
    with urllib.request.urlopen(server + r["report"]) as resp:
        report = resp.read().decode("utf-8")
    assert "<script>alert(1)" not in report and "<img src=x" not in report and "Wyszukiwanie profili" in report

    status, r = _post(server + "/api/sprawa_profil_decyzja", json.dumps({
        "sprawa": "r5", "osoba": "Jan Testowy", "profil": card["url"], "decyzja": "potwierdz",
        "dowod": "operator porównał zdjęcie z dokumentem klienta"}).encode())
    assert r["code"] == 0, r
    status, r = _post(server + "/api/sprawa_profile_material", body)      # import po decyzji: decyzja zostaje
    status, r = _post(server + "/api/sprawa", b'{"sprawa": "r5"}')
    assert r["sprawa"]["discovery"]["items"][0]["decision"] == "Jan Testowy: potwierdzony"
    events = [json.loads(x)["event"] for x in (case / "audit.jsonl").read_text(encoding="utf-8").splitlines()]
    assert events.count("profile_material") == 6 and "profile_search" not in events
    assert KEY not in (case / "audit.jsonl").read_text(encoding="utf-8")


# --- R5A: osoba w karcie i minimalny zapis przez panel (prawdziwy entity-graph, bez sieci) --------------------------

def test_r5a_card_names_person_and_defaults_decision_to_it():
    html = (Path(app.PANEL) / "index.html").read_text(encoding="utf-8")
    body = html.split("function spDiscovery", 1)[1].split("async function spOpen", 1)[0]
    assert "Osoba: ${x.person}" in body and "Ocena dopasowania (dla: ${x.person})" in body
    assert "if (x.person) who.value = x.person;" in body          # domyślny cel decyzji = osoba tej karty


def test_r5a_panel_two_people_same_url_and_restricted_material_not_stored(server, roots, no_brave_config):
    status, r = _post(server + "/api/sprawa_nowa", json.dumps(
        {"sprawa": "r5a", "cel": PURPOSE, "osoba": "Jan Testowy"}).encode())
    assert status == 200 and r["code"] == 0, r
    url = "https://www.instagram.com/synthetic_r5/"
    secret = ("Diagnoza: syntetyczna choroba X-17. Kontakt https://example.org/k?email=synthetic@example.org, "
              "tel. +48 600 100 200. Profil https://www.facebook.com/profile.php?id=100000000000003")
    outputs = []
    for person, text, extra in (("Anna Testowa", "Materiał bez nazwiska. " + secret, {"dodaj": True}),
                                ("Jan Testowy", "Jan Testowy", {})):
        status, r = _post(server + "/api/sprawa_profile_material", json.dumps(
            {"sprawa": "r5a", "osoba": person, "url": url, "tekst": text, **extra}).encode())
        assert status == 200 and r["code"] == 0, r
        outputs.append(json.dumps(r, ensure_ascii=False))
    status, r = _post(server + "/api/sprawa", b'{"sprawa": "r5a"}')
    cards = {c["person"]: c for c in r["sprawa"]["discovery"]["items"]}
    assert cards["Anna Testowa"]["assessment"] == "brak zgodności nazwy w dostępnym materiale"
    assert cards["Jan Testowy"]["assessment"].startswith("zgodność nazwy")
    with urllib.request.urlopen(server + r["report"]) as resp:
        report = resp.read().decode("utf-8")
    case = roots / "sprawy" / "r5a"
    everything = "".join(outputs) + json.dumps(r, ensure_ascii=False) + report + "".join(
        f.read_text(encoding="utf-8", errors="replace") for f in case.iterdir() if f.is_file())
    for restricted in ("syntetyczna choroba", "X-17", "synthetic@example.org", "600 100 200"):
        assert restricted not in everything, restricted
    assert "100000000000003" in json.dumps(cards["Anna Testowa"])        # bezpieczny identyfikator zostaje
