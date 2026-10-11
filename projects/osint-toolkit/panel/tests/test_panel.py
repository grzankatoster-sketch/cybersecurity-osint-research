import json
import json
import sys
import threading
import urllib.error
import urllib.request
from http.server import ThreadingHTTPServer
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import app  # noqa: E402


def test_dns_command_has_html_report():
    tool, args, report = app.build_command("dns", {"domain": "example.com", "selectors": "google,s1"})
    assert tool == "dns" and args[0] == "example.com"
    assert "--html" in args and report.endswith(".html")
    i = args.index("--selectors")
    assert args[i:i + 2] == ["--selectors", "google,s1"]
    assert args[-2:] == ["--proxy", app.PANEL_PROXY]   # OPSEC: DoH przez Tora domyslnie


def test_dns_channel_direct_and_invalid():
    _, args, _ = app.build_command("dns", {"domain": "example.com", "channel": "direct"})
    assert args[-1] == "--direct" and "--proxy" not in args
    with pytest.raises(ValueError):
        app.build_command("dns", {"domain": "example.com", "channel": "vpn"})


@pytest.mark.parametrize("action,params", [
    ("dns", {"domain": "--json"}),
    ("dns", {"domain": ""}),
    ("dns", {"domain": "a.pl", "selectors": "x;rm"}),
    ("phone", {"number": "603", "region": "POL"}),
    ("hibp_catalog", {"limit": "abc"}),
    ("exif", {"path": "Z:/nie/ma/takiej/sciezki"}),
    ("nieznana", {}),
])
def test_bad_input_rejected(action, params):
    with pytest.raises(ValueError):
        app.build_command(action, params)


def test_phone_and_hibp_commands():
    assert app.build_command("phone", {"number": "603 123 456"})[1] == ["603 123 456", "--region", "PL"]
    with pytest.raises(ValueError, match="plan numeracyjny"):  # telefon: bez wariantow do wyszukiwania
        app.build_command("phone", {"number": "603 123 456", "dorks": True})
    assert app.build_command("hibp_domain", {"domain": "adobe.com"})[1] == \
        ["breaches", "--domain", "adobe.com", "--no-save"]
    assert app.build_command("hibp_catalog", {"limit": 9999})[1][-1] == "500"


@pytest.fixture
def server():
    srv = ThreadingHTTPServer(("127.0.0.1", 0), app.Handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    yield f"http://127.0.0.1:{srv.server_address[1]}"
    srv.shutdown()


def _post(url, body, token):
    req = urllib.request.Request(url, data=json.dumps(body).encode(), method="POST",
                                 headers={"Content-Type": "application/json", "X-Panel-Token": token})
    try:
        with urllib.request.urlopen(req) as r:
            return r.status, json.loads(r.read())
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read())


def test_index_has_token_and_post_requires_it(server):
    with urllib.request.urlopen(server + "/") as r:
        page = r.read().decode()
        assert app.TOKEN in page and 'data-tab="lab"' in page
    assert _post(server + "/api/phone", {"number": "603123456"}, "zly")[0] == 403


def test_lab_status_requires_panel_token_and_has_safe_sections(server, monkeypatch):
    monkeypatch.setenv("BRAVE_SEARCH_API_KEY", "wartosc-sekretu-123")
    monkeypatch.setenv("HIBP_API_KEY", "drugi-sekret-456")
    req = urllib.request.Request(server + "/api/lab")
    with pytest.raises(urllib.error.HTTPError) as e:
        urllib.request.urlopen(req)
    assert e.value.code == 403
    req = urllib.request.Request(server + "/api/lab", headers={"X-Panel-Token": app.TOKEN})
    with urllib.request.urlopen(req) as r:
        status = json.loads(r.read())
    assert status["updated"] == "2026-10-05"
    assert {"ready", "findings", "blockers", "decisions", "guardrails", "statuses", "modules"} <= status.keys()
    # piec rodzajow wyniku; blad, blokada i wynik czesciowy sa osobno od braku wyniku
    assert [s["key"] for s in status["statuses"]] == ["found", "error", "no_result", "blocked", "partial"]
    assert {s["key"] for s in status["statuses"]} == set(app.RESULT_STATUS)
    env = status["environment"]   # zaleznosci i konfiguracja: tylko tak/nie, bez wartosci zmiennych
    assert env["dependencies"] and all(set(d) == {"name", "ok", "note"} for d in env["dependencies"])
    assert all(isinstance(c["ok"], bool) for c in env["config"])
    assert {m["state"] for m in status["modules"]} <= {"gotowe", "częściowo", "do zrobienia"}
    text = json.dumps(status, ensure_ascii=False)
    assert app.TOKEN not in text and "sk_" not in text
    assert "wartosc-sekretu-123" not in text and "drugi-sekret-456" not in text   # nazwa zmiennej tak, wartosc nigdy
    assert {c["name"]: c["ok"] for c in env["config"]}["BRAVE_SEARCH_API_KEY"] is True
    assert str(app.SPRAWY) not in text and "wyniki/sprawy" not in text  # bez sciezek i danych spraw


def test_bad_host_header_forbidden(server):
    req = urllib.request.Request(server + "/", headers={"Host": "evil.example"})
    with pytest.raises(urllib.error.HTTPError) as e:
        urllib.request.urlopen(req)
    assert e.value.code == 403


def test_wyniki_path_traversal_blocked(server):
    with pytest.raises(urllib.error.HTTPError) as e:
        urllib.request.urlopen(server + "/wyniki/..%5Capp.py")
    assert e.value.code == 404


def test_report_csp_blocks_network_except_map(server, tmp_path, monkeypatch):
    """Raport nie moze niczego pobrac z sieci przy otwarciu (OPSEC); mapa EXIF zachowuje stara polityke."""
    monkeypatch.setattr(app, "OUT", tmp_path)
    (tmp_path / "un_x_1.html").write_text("<html></html>", encoding="utf-8")
    (tmp_path / "mapa_1.html").write_text("<html></html>", encoding="utf-8")
    with urllib.request.urlopen(server + "/wyniki/un_x_1.html") as r:
        csp = r.headers["Content-Security-Policy"]
    assert "default-src 'none'" in csp and "img-src data:" in csp and "sandbox" in csp
    with urllib.request.urlopen(server + "/wyniki/mapa_1.html") as r:
        assert "default-src" not in r.headers["Content-Security-Policy"]


def test_phone_end_to_end(server):
    status, r = _post(server + "/api/phone", {"number": "+48 22 123 45 67"}, app.TOKEN)
    assert status == 200 and r["code"] in (0, 1), r
    assert "48" in r["stdout"]


# --- nazwa uzytkownika, theHarvester ---

def test_username_command_defaults():
    tool, args, report = app.build_command("username", {"username": "mozilla"})
    assert tool == "username" and args[0] == "mozilla"
    assert report.startswith("un_mozilla_") and report.endswith(".html")
    assert args[1] == "--report" and args[2] == report  # sama nazwa: username-engine odrzuca sciezki
    assert args[args.index("--results-dir") + 1] == str(app.OUT)
    for flag in ("--tags", "--no-variants", "--wayback", "--years", "--limit", "--direct"):
        assert flag not in args


def test_username_channel_tor_by_default_direct_explicit():
    """OPSEC: domyslnie Tor (fail-closed w silniku), bezposrednio tylko jawnie, inne wartosci odrzucane."""
    _, args, _ = app.build_command("username", {"username": "mozilla"})
    assert args[args.index("--proxy") + 1] == app.PANEL_PROXY
    assert app.PANEL_PROXY.startswith("socks5h://")
    _, args, _ = app.build_command("username", {"username": "mozilla", "channel": "direct"})
    assert "--direct" in args and "--proxy" not in args
    for bad in ("http", "socks5://evil:1", ["tor"]):
        with pytest.raises(ValueError):
            app.build_command("username", {"username": "mozilla", "channel": bad})


def test_tool_env_sets_proxy_for_indirect_username_engine(monkeypatch):
    monkeypatch.delenv("OSINT_PROXY", raising=False)
    assert app.tool_env("sprawa_kandydaci")["OSINT_PROXY"] == app.PANEL_PROXY
    monkeypatch.setenv("OSINT_PROXY", "socks5h://127.0.0.1:9050")
    assert app.tool_env("sprawa_kandydaci")["OSINT_PROXY"] == "socks5h://127.0.0.1:9050"


def test_tool_env_requires_proxy_for_meta(monkeypatch):
    monkeypatch.delenv("META_REQUIRE_PROXY", raising=False)
    assert app.tool_env("meta")["META_REQUIRE_PROXY"] == "1"


def test_username_proxy_timeout(monkeypatch):
    seen = {}

    def fake_run(cmd, **kw):
        seen["timeout"] = kw["timeout"]
        return app.subprocess.CompletedProcess(cmd, 0, "", "")
    monkeypatch.setattr(app.subprocess, "run", fake_run)
    app.run_tool("username", {"username": "mozilla"})       # domyslnie: Tor, poziom standard
    assert seen["timeout"] == app.USERNAME_TIMEOUTS["standard"]["proxy"]
    app.run_tool("username", {"username": "mozilla", "channel": "direct"})
    assert seen["timeout"] == app.USERNAME_TIMEOUTS["standard"]["direct"]
    # pelny skan przez Tora trwa ok. 82 min: limit musi to pomiescic (wczesniej 45 min ubijalo skan)
    app.run_tool("username", {"username": "mozilla", "level": "full"})
    assert seen["timeout"] >= 90 * 60


def test_username_level_default_standard_and_validated():
    _, args, _ = app.build_command("username", {"username": "mozilla"})
    assert args[args.index("--level") + 1] == "standard"
    for lvl in ("quick", "full"):
        _, args, _ = app.build_command("username", {"username": "mozilla", "level": lvl})
        assert args[args.index("--level") + 1] == lvl
    for bad in ("fast", "--direct", ["full"]):
        with pytest.raises(ValueError):
            app.build_command("username", {"username": "mozilla", "level": bad})


def test_username_command_all_options():
    _, args, _ = app.build_command("username", {
        "username": "Jan Kowalski", "tags": "social,pl", "only": True, "wayback": True,
        "years": "1990,90", "limit": "40"})
    assert args[0] == "Jan Kowalski"
    assert args[args.index("--tags") + 1] == "social,pl"
    assert args[args.index("--years") + 1] == "1990,90"
    assert args[args.index("--limit") + 1] == "40"
    assert "--no-variants" in args and "--wayback" in args


def test_username_empty_optionals_ignored():
    _, args, _ = app.build_command("username", {"username": "x1", "tags": "", "years": " ", "limit": ""})
    assert "--tags" not in args and "--years" not in args and "--limit" not in args


@pytest.mark.parametrize("action,params", [
    ("username", {"username": "-rf"}),
    ("username", {"username": ""}),
    ("username", {"username": "a;b"}),
    ("username", {"username": "a" * 101}),
    ("username", {"username": "ok", "tags": "social pl"}),
    ("username", {"username": "ok", "tags": "-x"}),
    ("username", {"username": "ok", "years": "19x0"}),
    ("username", {"username": "ok", "years": "-1"}),
    ("username", {"username": "ok", "limit": 0}),
    ("username", {"username": "ok", "limit": 10001}),
    ("username", {"username": "ok", "limit": "abc"}),
    ("harvester", {"domain": "-d"}),
    ("harvester", {"domain": "exa mple.com"}),
    ("harvester", {"domain": "a..pl"}),
    ("harvester", {"domain": "example.com;calc"}),
    ("harvester", {"domain": "example.com", "source": "shodan"}),
    ("harvester", {"domain": "example.com", "source": "crtsh,nieznane"}),
    ("harvester", {"domain": "example.com", "source": "crtsh", "limit": 0}),
    ("harvester", {"domain": "example.com", "source": "crtsh", "limit": 99999}),
])
def test_new_actions_bad_input_rejected(action, params):
    with pytest.raises(ValueError):
        app.build_command(action, params)


def test_maigret_removed():
    """Maigret wycofany z panelu (wlasny username-engine): akcja nieznana, brak zakladki."""
    with pytest.raises(ValueError):
        app.build_command("maigret", {"username": "mozilla"})
    assert "maigret" not in app.TIMEOUTS and "maigret" not in app.LONG_TOOLS
    assert "maigret" not in (app.PANEL / "index.html").read_text(encoding="utf-8").lower()


def test_harvester_command_and_defaults():
    tool, args, report = app.build_command("harvester", {"domain": "example.com", "source": "crtsh", "limit": 50})
    assert (tool, report) == ("harvester", None)
    assert args == ["-d", "example.com", "-b", "crtsh", "-l", "50"]
    assert app.build_command("harvester", {"domain": "example.com"})[1] == \
        ["-d", "example.com", "-b", "crtsh,certspotter,hackertarget", "-l", "100"]
    assert app.build_command("harvester", {"domain": "a.pl", "source": "crtsh,otx"})[1][3] == "crtsh,otx"


def test_harvester_launch_uses_dns_fix_and_verbose():
    """Bez ThreadedResolver kazde zrodlo theHarvestera na Windowsie konczy sie transport-error (0 hostow)."""
    cmd, env = app.launch("harvester", ["-d", "example.com", "-b", "crtsh", "-l", "100"])
    assert cmd[0] == str(app.HARVESTER_PY) and cmd[1] == "-c"
    assert "ThreadedResolver" in cmd[2] and "theHarvester.theHarvester import main" in cmd[2]
    assert cmd[3:] == ["-d", "example.com", "-b", "crtsh", "-l", "100", "-v"]
    assert env["PYTHONIOENCODING"] == "utf-8"


def test_username_launch_env_and_timeouts():
    cmd, env = app.launch("username", ["mozilla"])
    assert cmd[1:3] == ["-m", "username_engine"]
    assert env["PYTHONPATH"].split(app.os.pathsep)[0].endswith("src") and env["PYTHONUTF8"] == "1"
    assert app.TIMEOUTS["username"] == 900


def test_long_scan_lock_returns_409(server):
    assert app._LONG_LOCK.acquire(blocking=False)
    try:
        status, r = _post(server + "/api/username", {"username": "mozilla"}, app.TOKEN)
        assert status == 409 and r["busy"] and "dlugi skan" in r["error"]
        # walidacja ma pierwszenstwo przed lockiem, a krotkie narzedzia nie sa blokowane
        assert _post(server + "/api/username", {"username": "-x"}, app.TOKEN)[0] == 400
        assert _post(server + "/api/phone", {"number": "+48 22 123 45 67"}, app.TOKEN)[0] == 200
    finally:
        app._LONG_LOCK.release()
    assert not app._LONG_LOCK.locked()


def test_long_scan_lock_released_after_run(monkeypatch):
    def boom(*a, **k):
        raise app.subprocess.TimeoutExpired("x", 1)
    monkeypatch.setattr(app.subprocess, "run", boom)
    r = app.run_tool("username", {"username": "mozilla", "channel": "direct"})
    assert r["code"] == -1 and "limit czasu (900 s)" in r["stderr"] and r["report"] is None
    assert not app._LONG_LOCK.locked()


def test_long_scan_live_progress(monkeypatch):
    """Trafienia dlugiego skanu widac w /api/postep w trakcie; po skanie podglad znika, wynik ma pelne wyjscie."""
    seen = {}

    def fake_run(cmd, **kw):
        kw["stdout"].write("Kanał: Tor\r\n[+] GitHub: https://github.com/mozilla\r\n".encode("utf-8"))
        kw["stdout"].flush()
        kw["stderr"].write(b"  [100/300 33%] znalezione: 1\n")
        kw["stderr"].flush()
        seen["live"] = app.live_progress()
        seen["unbuffered"] = kw["env"].get("PYTHONUNBUFFERED")
        return app.subprocess.CompletedProcess(cmd, 0, None, None)
    monkeypatch.setattr(app.subprocess, "run", fake_run)
    assert app.live_progress() == {"aktywny": False}
    r = app.run_tool("username", {"username": "mozilla", "channel": "direct"})
    live = seen["live"]
    assert live["aktywny"] and live["narzedzie"] == "username" and seen["unbuffered"] == "1"
    assert "github.com/mozilla" in live["stdout"] and live["postep"] == "[100/300 33%] znalezione: 1"
    assert r["code"] == 0 and r["stdout"] == "Kanał: Tor\n[+] GitHub: https://github.com/mozilla"
    assert app.live_progress() == {"aktywny": False} and not app._LONG_LOCK.locked()


def test_long_scan_timeout_keeps_partial_hits(monkeypatch):
    def slow(cmd, **kw):
        kw["stdout"].write(b"[+] GitHub: https://github.com/mozilla\n")
        raise app.subprocess.TimeoutExpired("x", 1)
    monkeypatch.setattr(app.subprocess, "run", slow)
    r = app.run_tool("username", {"username": "mozilla", "channel": "direct"})
    assert r["code"] == -1 and "github.com/mozilla" in r["stdout"] and "limit czasu" in r["stderr"]


def test_live_progress_requires_token(server):
    req = urllib.request.Request(server + "/api/postep")
    with pytest.raises(urllib.error.HTTPError) as e:
        urllib.request.urlopen(req)
    assert e.value.code == 403
    req = urllib.request.Request(server + "/api/postep", headers={"X-Panel-Token": app.TOKEN})
    assert json.loads(urllib.request.urlopen(req).read()) == {"aktywny": False}


def test_exif_action_adds_reverse_guide(tmp_path):
    from app import build_command

    tool, args, _ = build_command("exif", {"path": str(tmp_path)})
    assert tool == "exif" and "--reverse" in args


# --- zakladka Meta ---

def test_meta_threads_profile_command_no_secret_in_args():
    tool, args, report = app.build_command("meta", {"op": "threads_profile", "username": "@meta"})
    assert tool == "meta" and args[0] == "threads-profile" and args[-2:] == ["--", "meta"]
    assert report.startswith("meta_threads_profile_meta_") and report.endswith(".html")
    assert not any("token" in a.lower() for a in args)


def test_meta_search_and_config_commands():
    _, args, report = app.build_command("meta", {"op": "threads_search", "query": "osint pl", "search_type": "recent",
                                                 "limit": "10", "author": "meta"})
    assert args[:5] == ["threads-search", "--type", "RECENT", "--limit", "10"] and args[-2:] == ["--", "osint pl"]
    assert "--author" in args and report.endswith(".html")
    assert app.build_command("meta", {"op": "config"})[1] == ["config"]


def test_meta_instagram_profile_command():
    tool, args, report = app.build_command("meta", {"op": "instagram_profile", "username": "@natgeo", "media": "3"})
    assert tool == "meta" and args[:3] == ["instagram-profile", "--media", "3"] and args[-2:] == ["--", "natgeo"]
    assert report.startswith("meta_instagram_profile_natgeo_") and report.endswith(".html")
    assert not any("token" in a.lower() for a in args)
    assert app.build_command("meta", {"op": "instagram_profile", "username": "natgeo"})[1][:3] ==         ["instagram-profile", "--media", "0"]


def test_meta_facebook_page_command():
    tool, args, report = app.build_command("meta", {"op": "facebook_page", "page": "@natgeo"})
    assert tool == "meta" and args[0] == "facebook-page" and args[-2:] == ["--", "natgeo"]
    assert report.startswith("meta_facebook_page_natgeo_") and not any("token" in a.lower() for a in args)


def test_meta_html_heuristic_check_is_gone():
    """Heurystyka HTML (Facebook/Instagram/Threads przez username-engine) usunieta: zostaja API i linki reczne."""
    assert not hasattr(app, "META_SITES") and "profiles" not in app.META_OPS
    with pytest.raises(ValueError):
        app.build_command("meta", {"op": "profiles", "username": "natgeo"})


@pytest.mark.parametrize("params", [
    {"op": "nieznana", "username": "a"},
    {"op": "threads_profile", "username": "ja kowalski"},
    {"op": "threads_profile", "username": "-x"},
    {"op": "threads_search", "query": ""},
    {"op": "threads_search", "query": "a", "search_type": "ALL"},
    {"op": "threads_search", "query": "a", "limit": "500"},
    {"op": "threads_search", "query": "a", "author": "zły nick"},
    {"op": "links", "username": "a" * 40},
    {"op": "instagram_profile", "username": "zły nick"},
    {"op": "instagram_profile", "username": "natgeo", "media": "51"},
    {"op": "instagram_profile", "username": "natgeo", "media": "x"},
    {"op": "facebook_page", "page": ""},
    {"op": "facebook_page", "page": "a/b"},
    {"op": "facebook_page", "page": "x?fields=email"},
    {"op": "facebook_page", "page": ".."},
    {"op": "facebook_page", "page": "-x"},
    {"op": "facebook_page", "page": "a" * 101},
])
def test_meta_bad_input(params):
    with pytest.raises(ValueError):
        app.build_command("meta", params)


def test_meta_run_without_token_is_not_configured(tmp_path, monkeypatch):
    """Prawdziwy podproces meta-search, bez tokenu: status 'wymaga konfiguracji', zero wynikow, zero sieci."""
    monkeypatch.setattr(app, "OUT", tmp_path)
    monkeypatch.delenv("THREADS_ACCESS_TOKEN", raising=False)
    monkeypatch.setenv("META_SEARCH_ENV_FILE", str(tmp_path / "brak.env"))
    res = app.run_tool("meta", {"op": "threads_profile", "username": "meta"})
    assert res["code"] == 3 and res["meta"]["status"] == "not_configured" and res["meta"]["items"] == 0
    assert res["meta"]["label"] == "wymaga konfiguracji" and res["report"]


@pytest.mark.parametrize("params,op", [({"op": "instagram_profile", "username": "natgeo"}, "instagram_profile"),
                                       ({"op": "facebook_page", "page": "natgeo"}, "facebook_page")])
def test_meta_graph_run_without_token_is_not_configured(tmp_path, monkeypatch, params, op):
    """Prawdziwy podproces, bez tokenow: wymaga konfiguracji, zero wynikow, zero sieci."""
    monkeypatch.setattr(app, "OUT", tmp_path)
    for k in ("INSTAGRAM_ACCESS_TOKEN", "INSTAGRAM_USER_ID", "FACEBOOK_ACCESS_TOKEN", "THREADS_ACCESS_TOKEN"):
        monkeypatch.delenv(k, raising=False)
    monkeypatch.setenv("META_SEARCH_ENV_FILE", str(tmp_path / "brak.env"))
    res = app.run_tool("meta", params)
    assert res["code"] == 3 and res["meta"]["status"] == "not_configured" and res["meta"]["items"] == 0
    assert res["meta"]["label"] == "wymaga konfiguracji" and res["report"]
    assert json.loads(next(tmp_path.glob("*.json")).read_text(encoding="utf-8"))["operation"] == op


def test_meta_config_shows_three_sources(tmp_path, monkeypatch):
    monkeypatch.setenv("META_SEARCH_ENV_FILE", str(tmp_path / "brak.env"))
    res = app.run_tool("meta", {"op": "config"})
    assert res["code"] == 0 and set(json.loads(res["stdout"])["sources"]) == {"threads", "instagram", "facebook"}


def test_meta_links_run(tmp_path, monkeypatch):
    monkeypatch.setattr(app, "OUT", tmp_path)
    res = app.run_tool("meta", {"op": "links", "username": "natgeo"})
    assert res["code"] == 0 and res["meta"] == {"status": "manual", "label": "do ręcznego sprawdzenia",
                                                "source": "manual", "items": 4}


def test_meta_summary_ignores_foreign_json(tmp_path, monkeypatch):
    monkeypatch.setattr(app, "OUT", tmp_path)
    (tmp_path / "x.json").write_text('{"tool": "inne", "status": "found"}', encoding="utf-8")
    assert app.meta_summary("x.html") is None and app.meta_summary(None) is None


def test_meta_summary_ignores_invalid_structure(tmp_path, monkeypatch):
    monkeypatch.setattr(app, "OUT", tmp_path)
    (tmp_path / "x.json").write_text(json.dumps({"tool": "meta-search", "source": [], "items": {}}), encoding="utf-8")
    assert app.meta_summary("x.html") is None


def test_reports_from_same_second_have_distinct_names(monkeypatch):
    monkeypatch.setattr(app.time, "strftime", lambda *args: "20261004-120000")
    params = {"op": "threads_profile", "username": "meta"}
    assert app.build_command("meta", params)[2] != app.build_command("meta", params)[2]


def test_index_has_meta_tab():
    html = (Path(app.__file__).parent / "index.html").read_text(encoding="utf-8")
    assert 'data-tab="meta"' in html and html.count('data-action="meta"') == 6
    for op in ("threads_profile", "threads_search", "instagram_profile", "facebook_page", "links", "config"):
        assert f'name="op" value="{op}"' in html
    assert 'value="profiles"' not in html and "Heurystyka HTML" not in html


# --- raporty username-engine w podkatalogu skanu (retencja 12 h) ---

def test_find_scan_report_in_scan_dir(tmp_path, monkeypatch):
    monkeypatch.setattr(app, "OUT", tmp_path)
    (tmp_path / "20261003T120000Z-ab12").mkdir()
    (tmp_path / "20261003T120000Z-ab12" / "un_x_1.html").write_text("ok", encoding="utf-8")
    assert app.find_scan_report("un_x_1.html") == "20261003T120000Z-ab12/un_x_1.html"
    assert app.find_scan_report("un_brak.html") == "un_brak.html"


@pytest.mark.parametrize("name", ["../app.py", "a/../x.html", "../x.html", "./x.html", "a/b/c.html",
                                  "a\b.html", "/x.html", "x.txt", "a/b.txt", ""])
def test_safe_report_path_rejects(tmp_path, monkeypatch, name):
    monkeypatch.setattr(app, "OUT", tmp_path)
    assert app.safe_report_path(name) is None


def test_safe_report_path_accepts(tmp_path, monkeypatch):
    monkeypatch.setattr(app, "OUT", tmp_path)
    (tmp_path / "scan1").mkdir()
    (tmp_path / "scan1" / "r.html").write_text("ok", encoding="utf-8")
    (tmp_path / "flat.html").write_text("ok", encoding="utf-8")
    assert app.safe_report_path("scan1/r.html") == tmp_path / "scan1" / "r.html"
    assert app.safe_report_path("flat.html") == tmp_path / "flat.html"
    assert app.safe_report_path("scan1/brak.html") is None


# --- R1-C: ksztalt dokumentu i typy pol przed startem narzedzia ---

def _post_raw(url, raw: bytes, token=None):
    req = urllib.request.Request(url, data=raw, method="POST",
                                 headers={"Content-Type": "application/json", "X-Panel-Token": token or app.TOKEN})
    try:
        with urllib.request.urlopen(req) as r:
            return r.status, json.loads(r.read())
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read())


@pytest.fixture(scope="module")
def shared_server():
    """Jeden serwer na wszystkie przypadki R1-C (zamykanie serwera trwa ~0,5 s)."""
    srv = ThreadingHTTPServer(("127.0.0.1", 0), app.Handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    yield f"http://127.0.0.1:{srv.server_address[1]}"
    srv.shutdown()


@pytest.fixture
def no_tools(monkeypatch):
    """Kazda proba uruchomienia podprocesu jest zapisywana; test sprawdza, ze nie bylo zadnej."""
    calls = []
    monkeypatch.setattr(app.subprocess, "run", lambda *a, **k: calls.append(a) or pytest.fail("narzedzie wystartowalo"))
    return calls


@pytest.mark.parametrize("action", ["phone", "dns", "username", "meta", "harvester", "hibp_catalog", "hibp_password"])
@pytest.mark.parametrize("raw", [b"[]", b"null", b'"tekst"', b"42", b"true", b"[" * 5000 + b"]" * 5000])
def test_non_object_document_is_400_without_tool(shared_server, no_tools, action, raw):
    status, body = _post_raw(shared_server + "/api/" + action, raw)
    assert status == 400 and ("obiektem" in body["error"] or "zagniezdzony" in body["error"])
    assert "Error" not in body["error"] and not no_tools


@pytest.mark.parametrize("action,doc", [
    ("phone", {"number": {"a": 1}}),
    ("phone", {"number": ["603123456"]}),
    ("phone", {"number": 603123456}),
    ("phone", {"number": "603123456", "dorks": "false"}),
    ("phone", {"number": "603123456", "region": ["PL"]}),
    ("dns", {"domain": "example.com", "selectors": {"x": 1}}),
    ("username", {"username": "x1", "limit": 3.5}),
    ("username", {"username": "x1", "limit": True}),
    ("username", {"username": "x1", "wayback": 1}),
    ("username", {"username": "x1", "tags": ["social"]}),
    ("harvester", {"domain": "example.com", "source": [1, 2]}),
    ("harvester", {"domain": "example.com", "source": {"crtsh": True}}),
    ("hibp_catalog", {"limit": float("1e300")}),
    ("hibp_catalog", {"limit": [5]}),
    ("meta", {"op": ["config"]}),
    ("meta", {"op": "threads_search", "query": "osint", "search_type": 1}),
    ("hibp_password", {"password": 12345678}),
    ("hibp_password", {"password": ["x"]}),
])
def test_wrong_field_type_is_422_without_tool(shared_server, no_tools, action, doc):
    status, body = _post(shared_server + "/api/" + action, doc, app.TOKEN)
    assert status == 422 and body["error"].startswith("pole ") and not no_tools


def test_nan_and_infinity_literals_do_not_crash(shared_server, no_tools):
    for raw in (b'{"limit": NaN}', b'{"limit": Infinity}'):
        status, body = _post_raw(shared_server + "/api/hibp_catalog", raw)
        assert status in (400, 422) and "Error" not in body["error"] and not no_tools


def test_token_still_checked_before_document(shared_server, no_tools):
    assert _post_raw(shared_server + "/api/phone", b"[]", token="zly")[0] == 403 and not no_tools


def test_form_shaped_documents_still_build_commands():
    # dokladnie to, co wysyla index.html: FormData (tekst) + pola wyboru (bool)
    assert app.build_command("phone", {"number": "603 123 456", "region": "PL", "dorks": False})[1] == \
        ["603 123 456", "--region", "PL"]
    _, args, _ = app.build_command("username", {"username": "x1", "tags": "", "years": "", "only": True,
                                                "wayback": False, "limit": ""})
    assert "--no-variants" in args and "--wayback" not in args
    assert app.build_command("hibp_catalog", {"limit": "15"})[1][-1] == "15"
    assert app.build_command("harvester", {"domain": "a.pl", "source": "crtsh", "limit": "100"})[1][3] == "crtsh"
    assert app.build_command("meta", {"op": "instagram_profile", "username": "natgeo", "media": "0"})[1][:3] == \
        ["instagram-profile", "--media", "0"]
