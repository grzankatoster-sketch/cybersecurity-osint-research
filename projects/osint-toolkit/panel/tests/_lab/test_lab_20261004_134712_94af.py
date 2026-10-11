import json
import sys
import threading
import urllib.error
import urllib.request
from http.server import ThreadingHTTPServer
from pathlib import Path
from types import SimpleNamespace

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
import app  # noqa: E402


def _tool_of(cmd):
    """Nazwa modulu narzedzia z polecenia (theHarvester startuje przez -c, bez -m)."""
    return cmd[cmd.index("-m") + 1] if "-m" in cmd else "harvester"


class FakeRun:
    """Atrapa subprocess.run: zapisuje wywolania i limity czasu, nic nie uruchamia, zero sieci."""

    def __init__(self, behaviour=None):
        self.calls = []
        self.behaviour = behaviour or {}

    def __call__(self, cmd, **kw):
        tool = _tool_of(cmd)
        self.calls.append((tool, list(cmd), kw.get("timeout")))
        if "--html" in cmd:
            Path(cmd[cmd.index("--html") + 1]).write_text("<html>czastkowy</html>", encoding="utf-8")
        b = self.behaviour.get(tool)
        if isinstance(b, BaseException):
            raise b
        if b is not None:
            return SimpleNamespace(returncode=b[0], stdout=b[1], stderr=b[2])
        return SimpleNamespace(returncode=0, stdout=f"wynik {tool}", stderr="")


@pytest.fixture
def out(tmp_path, monkeypatch):
    monkeypatch.setattr(app, "OUT", tmp_path)
    return tmp_path


@pytest.fixture
def server():
    srv = ThreadingHTTPServer(("127.0.0.1", 0), app.Handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    yield f"http://127.0.0.1:{srv.server_address[1]}"
    srv.shutdown()


def _post(url, body):
    req = urllib.request.Request(url, data=json.dumps(body).encode(), method="POST",
                                 headers={"Content-Type": "application/json", "X-Panel-Token": app.TOKEN})
    try:
        with urllib.request.urlopen(req) as r:
            return r.status, json.loads(r.read())
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read())


def test_plan_per_target_type_and_validation():
    plan = app.plan_scan("example.com", "domena")
    assert [a for a, _ in plan] == ["dns", "hibp_domain", "harvester"]
    assert all(p["domain"] == "example.com" for _, p in plan)

    plan = app.plan_scan("jan.kowalski@example.com", "email")
    assert [a for a, _ in plan] == ["dns", "hibp_domain"]
    assert all(p["domain"] == "example.com" for _, p in plan)
    # czesc lokalna adresu nie trafia do argumentow zadnego narzedzia
    for action, params in plan:
        assert not any("jan.kowalski" in a for a in app.build_command(action, params)[1])

    plan = app.plan_scan("mozilla", "login")
    assert [a for a, _ in plan] == ["username", "meta"]
    assert plan[0][1]["username"] == "mozilla" and plan[1][1] == {"op": "links", "username": "mozilla"}

    for cel, typ in [("example.com", "ip"), ("example.com", ""), ("-x", "domena"), ("a..pl", "domena"),
                     ("example.com;calc", "domena"), ("bez-malpy.pl", "email"), ("a@b@c.pl", "email"),
                     ("jan@a..pl", "email"), ("", "login"), ("a;b", "login")]:
        with pytest.raises(ValueError):
            app.plan_scan(cel, typ)


def test_http_domain_scan_runs_tools_in_order_with_own_timeouts(server, out, monkeypatch):
    fake = FakeRun({"dns_audit": (0, "SPF: ok", ""),
                    "hibp_monitor": (0, "example.com: brak nowych wyciekow (lacznie 0)", "")})  # realistyczny wynik HIBP
    monkeypatch.setattr(app.subprocess, "run", fake)
    status, r = _post(server + "/api/skan_celu", {"cel": "example.com", "typ": "domena"})
    assert status == 200, r
    assert r["cel"] == "example.com" and r["typ"] == "domena"
    assert [k["akcja"] for k in r["kroki"]] == ["dns", "hibp_domain", "harvester"]
    assert [k["status"] for k in r["kroki"]] == ["gotowe"] * 3
    assert r["podsumowanie"]["wynik"] == "pelny" and r["podsumowanie"]["gotowe"] == 3
    # kazde narzedzie z wlasnym limitem czasu, po kolei
    assert [(t, to) for t, _, to in fake.calls] == [
        ("dns_audit", app.TIMEOUTS.get("dns", app.TIMEOUT)),
        ("hibp_monitor", app.TIMEOUTS.get("hibp", app.TIMEOUT)),
        ("harvester", app.TIMEOUTS["harvester"]),
    ]
    assert r["kroki"][0]["report"].startswith("/wyniki/dns_")
    # raport zbiorczy w wyniki/, serwowany przez panel
    assert r["report"].startswith("/wyniki/skan_example.com_") and r["report"].endswith(".html")
    with urllib.request.urlopen(server + r["report"]) as resp:
        html = resp.read().decode("utf-8")
    for needle in ("example.com", "dns", "hibp_domain", "harvester", "SPF: ok", r["kroki"][0]["report"]):
        assert needle in html


def test_tool_errors_are_never_negative_and_scan_continues(out, monkeypatch):
    fake = FakeRun({"dns_audit": app.subprocess.TimeoutExpired("x", 1),
                    "hibp_monitor": (2, "", "HTTP 429 Too Many Requests"),
                    "harvester": (0, "", "")})
    monkeypatch.setattr(app.subprocess, "run", fake)
    r = app.run_scan("example.com", "domena")
    assert [t for t, _, _ in fake.calls] == ["dns_audit", "hibp_monitor", "harvester"]
    st = [k["status"] for k in r["kroki"]]
    assert st == ["blad", "blad", "gotowe"]  # pusty wynik bez bledu to 'gotowe', nie blad
    assert "limit czasu" in r["kroki"][0]["stderr"] and "429" in r["kroki"][1]["stderr"]
    assert r["podsumowanie"]["blad"] == 2 and r["podsumowanie"]["wynik"] == "niepelny"
    assert r["code"] != 0
    statuses = {k["status"] for k in r["kroki"]}
    assert not statuses & {"brak", "NOT_FOUND", "not_found"}
    html = (out / r["report"].removeprefix("/wyniki/")).read_text(encoding="utf-8")
    assert "niepelny" in html and "limit czasu" in html


def test_busy_long_scan_step_is_skipped_not_fatal(out, monkeypatch):
    fake = FakeRun({"meta_search": (0, "linki", "")})
    monkeypatch.setattr(app.subprocess, "run", fake)
    assert app._LONG_LOCK.acquire(blocking=False)
    try:
        r = app.run_scan("mozilla", "login")
    finally:
        app._LONG_LOCK.release()
    assert [k["akcja"] for k in r["kroki"]] == ["username", "meta"]
    assert r["kroki"][0]["status"] == "pominieto" and "dlugi skan" in r["kroki"][0]["blad"]
    assert r["kroki"][1]["status"] == "gotowe"
    assert [t for t, _, _ in fake.calls] == ["meta_search"]
    assert r["podsumowanie"]["pominieto"] == 1 and r["podsumowanie"]["wynik"] == "niepelny"
    assert not app._LONG_LOCK.locked()


def test_summary_report_escapes_tool_output(out, monkeypatch):
    evil = "<script>alert(1)</script>"
    monkeypatch.setattr(app.subprocess, "run", FakeRun({"dns_audit": (1, evil, ""), "hibp_monitor": (0, "example.com: brak nowych wyciekow (lacznie 0)", "")}))
    r = app.run_scan("jan@example.com", "email")
    assert [k["status"] for k in r["kroki"]] == ["uwagi", "gotowe"]
    assert r["podsumowanie"]["wynik"] == "pelny" and r["podsumowanie"]["uwagi"] == 1
    f = app.safe_report_path(r["report"].removeprefix("/wyniki/"))
    assert f is not None
    html = f.read_text(encoding="utf-8")
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in html and evil not in html


def test_index_has_target_scan_tab():
    html = (Path(app.__file__).parent / "index.html").read_text(encoding="utf-8")
    assert 'data-tab="skan"' in html and 'id="tab-skan"' in html
    assert 'data-action="skan_celu"' in html and 'name="cel"' in html and 'name="typ"' in html
    for typ in ("domena", "email", "login"):
        assert f'value="{typ}"' in html
    assert "r.kroki" in html and "podsumowanie" in html
    assert html.count('data-action="meta"') == 6
