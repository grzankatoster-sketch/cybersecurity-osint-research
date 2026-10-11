"""Testy poprawek z przeglądu bezpieczeństwa (Codex 03.10.2026). Offline: lokalne serwery 127.0.0.1 i fałszywe fetchery."""
import asyncio
import csv
import json
import os

import aiohttp
import pytest
from aiohttp import web
from aiohttp.client_reqrep import ConnectionKey

from username_engine import cli
from username_engine.correlate import Account, accounts_from, link_accounts
from username_engine.dorks import Snapshot, parse_cdx, wayback_targets
from username_engine.engine import check_site
from username_engine.geo import Evidence, Gazetteer, aggregate
from username_engine.http import Fetcher, is_public_address
from username_engine.models import Response, Result, Site, Status
from username_engine.report import render_html, write_csv


class FakeFetcher:
    def __init__(self, handler):
        self.handler, self.calls = handler, []

    async def fetch(self, method, url, headers=None, body=None):
        self.calls.append((method, url, body))
        return self.handler(url)


def run(coro):
    return asyncio.run(coro)


async def _with_servers(specs, coro_fn):
    """specs: [(routes, host)] -> coro_fn(*bases)"""
    runners, bases = [], []
    for routes, host in specs:
        app = web.Application()
        app.add_routes(routes)
        runner = web.AppRunner(app)
        await runner.setup()
        site = web.TCPSite(runner, host, 0)
        await site.start()
        runners.append(runner)
        bases.append(f"http://{host}:{site._server.sockets[0].getsockname()[1]}")
    try:
        return await coro_fn(*bases)
    finally:
        for r in runners:
            await r.cleanup()


# ---------------------------------------------------------------- XSS / CDX / linki

def test_parse_cdx_validates_schema():
    ok = '[["timestamp","original","statuscode"],["20200101000000","fo.com/a","200"]]'
    assert parse_cdx(ok)[0].timestamp == "20200101000000"
    bad = [
        '[null, []]',
        '[["timestamp","original"], null]',
        '[["timestamp","original"], {"timestamp": "20200101000000"}]',
        '[["timestamp","original"], ["2020", "fo.com/a"]]',                       # timestamp nie ma 14 cyfr
        '[["timestamp","original"], ["<script>alert(1)</script>", "fo.com/a"]]',
        '[["timestamp","original"], [20200101000000, "fo.com/a"]]',               # zły typ
        '[["timestamp","original"], ["20200101000000", ["x"]]]',
        '[["timestamp", 5], ["20200101000000", "fo.com/a"]]',                     # nagłówek nie z tekstów
        '[["timestamp","original"], ["20200101000000"]]',                         # za krótki wiersz
        'null',
        '{"a": 1}',
    ]
    for text in bad:
        with pytest.raises(ValueError):
            parse_cdx(text)


def test_html_escapes_snapshot_date():
    snap = Snapshot("<script>alert(1)</script>", "fo.com/a")      # obejście parse_cdx: render też musi być bezpieczny
    html = render_html("a", {"a": []}, {"a": {"checked": 0, "error": 0, "unsupported": 0}}, [],
                       wayback={"https://fo.com/a": [snap]})
    assert "<script>alert" not in html and "&lt;script&gt;" in html


def test_only_http_links_get_href():
    results = [Result("Ev", "javascript:alert(1)", Status.FOUND, 0.9, "tekst"),
               Result("Ev2", "data:text/html,<b>", Status.FOUND, 0.9, "tekst"),
               Result("Ok", "https://ok.com/a", Status.FOUND, 0.9, "tekst"),
               Result("Blk", " JavaScript:alert(2)", Status.ERROR, reason="dostęp zabroniony (403)")]
    html = render_html("a", {"a": results}, {"a": {"checked": 4, "error": 1, "unsupported": 0}}, [],
                       wayback={"javascript:alert(3)": []})
    assert "href='https://ok.com/a'" in html
    assert "href='javascript" not in html.lower() and "href='data:" not in html.lower()
    assert "javascript:alert(1)" in html                        # pokazany jako zwykły tekst
    assert "href='JavaScript" not in html


# ---------------------------------------------------------------- SSRF

def test_is_public_address():
    for bad in ("127.0.0.1", "10.1.2.3", "192.168.0.5", "172.16.0.1", "169.254.169.254", "224.0.0.1", "0.0.0.0",
                "240.0.0.1", "100.64.0.1", "::1", "fe80::1", "fc00::1", "ff02::1", "::ffff:127.0.0.1", "::"):
        assert not is_public_address(bad), bad
    for good in ("8.8.8.8", "1.1.1.1", "2606:4700:4700::1111"):
        assert is_public_address(good), good


def test_private_target_blocked_without_request():
    hits = {"n": 0}

    async def handler(request):
        hits["n"] += 1
        return web.Response(text="secret")

    async def go(base):
        async with Fetcher(retries=0) as f:
            return await f.fetch("GET", base + "/x")

    r = run(_with_servers([([web.get("/x", handler)], "127.0.0.1")], go))
    assert r.status is None and "zablokowan" in r.error and hits["n"] == 0


def test_redirect_to_internal_address_blocked():
    secret = {"n": 0}

    async def hop(request):
        raise web.HTTPFound(request.query["to"])

    async def sec(request):
        secret["n"] += 1
        return web.Response(text="secret")

    async def go(a, b):
        port_b = b.rsplit(":", 1)[1]
        out = []
        # allow_hosts zwalnia tylko pierwszy skok (127.0.0.1); cel przekierowania to literał 127.0.0.2 i „localhost”
        async with Fetcher(retries=0, allow_hosts=("127.0.0.1",)) as f:
            for target in (f"http://127.0.0.2:{port_b}/s", f"http://localhost:{port_b}/s"):
                out.append(await f.fetch("GET", f"{a}/hop?to={target}"))
        return out

    resps = run(_with_servers([([web.get("/hop", hop)], "127.0.0.1"), ([web.get("/s", sec)], "127.0.0.1")], go))
    assert all(r.status is None and "zablokowan" in r.error for r in resps), [r.error for r in resps]
    assert secret["n"] == 0


def test_only_safe_methods_allowed_and_redirect_limit():
    async def loop(request):
        raise web.HTTPFound("/loop")

    async def go(base):
        async with Fetcher(retries=0, allow_private=True) as f:
            d = await f.fetch("DELETE", base + "/loop")
            p = await f.fetch("PUT", base + "/loop", body="x")
            r = await f.fetch("GET", base + "/loop")
            return d, p, r

    d, p, r = run(_with_servers([([web.route("*", "/loop", loop)], "127.0.0.1")], go))
    assert d.status is None and "metod" in d.error and p.status is None and "metod" in p.error
    assert r.status is None and "przekierowa" in r.error


def test_redirect_followed_when_public_check_disabled():
    async def start(request):
        raise web.HTTPFound("/login")

    async def login(request):
        return web.Response(text="login")

    async def go(base):
        async with Fetcher(retries=0, allow_private=True) as f:
            return await f.fetch("GET", base + "/u")

    r = run(_with_servers([([web.get("/u", start), web.get("/login", login)], "127.0.0.1")], go))
    assert r.status == 200 and r.final_url.endswith("/login") and r.text == "login"


# ---------------------------------------------------------------- TLS

def _cert_error():
    key = ConnectionKey("x.test", 443, True, True, None, None, None)
    return aiohttp.ClientConnectorCertificateError(key, Exception("bad cert"))


def _tls_fetcher(strict):
    calls = []

    async def fake_request(method, url, headers, body, ssl):
        calls.append(ssl)
        if ssl:
            raise _cert_error()
        return Response(status=200, text="avatar", final_url=url)

    f = Fetcher(retries=0, strict_tls=strict)
    f._session = object()
    f._request = fake_request
    return f, calls


def test_tls_fallback_marks_insecure_and_strict_disables_it():
    f, calls = _tls_fetcher(strict=False)
    r = run(f.fetch("GET", "https://x.test/a"))
    assert r.status == 200 and r.insecure and calls == [True, False]
    f, calls = _tls_fetcher(strict=True)
    r = run(f.fetch("GET", "https://x.test/a"))
    assert r.status is None and "certyfikat" in r.error and not r.insecure and calls == [True]


def test_insecure_result_capped_marked_and_without_profile():
    page = '<meta property="og:title" content="Alice"><meta name="geo.placename" content="Kraków"> avatar'
    f = FakeFetcher(lambda url: Response(200, page, final_url=url, insecure=True) if url.endswith("/alice")
                    else Response(404, "", final_url=url, insecure=True))
    s = Site("Bad", "https://bad.test/{username}", e_strings=["avatar"])
    r = run(check_site(s, "alice", f))
    assert r.status is Status.FOUND and r.confidence <= 0.6 and r.insecure
    assert r.profile == {} and "certyfikat" in r.reason.lower()
    assert r.to_dict()["insecure"] is True
    secure = run(check_site(s, "alice", FakeFetcher(
        lambda url: Response(200, page, final_url=url) if url.endswith("/alice") else Response(404, "", final_url=url))))
    assert secure.confidence > 0.6 and secure.profile and not secure.insecure and "insecure" not in secure.to_dict()


def test_insecure_excluded_from_correlation_and_marked_in_report_and_csv(tmp_path):
    ins = Result("Bad", "https://bad.test/a", Status.FOUND, 0.6, "tekst obecności konta", insecure=True)
    ok = Result("Ok", "https://ok.test/a", Status.FOUND, 0.9, "tekst", profile={"name": "A"})
    assert [a.site for a in accounts_from({"a": [ins, ok]}, 0.5)] == ["Ok"]
    html = render_html("a", {"a": [ins, ok]}, {"a": {"checked": 2, "error": 0, "unsupported": 0}}, [])
    assert "bez weryfikacji TLS" in html
    p = tmp_path / "w.csv"
    write_csv(p, {"a": [ins, ok]})
    rows = list(csv.reader(open(p, encoding="utf-8-sig"), delimiter=";"))
    assert rows[0][-1] == "tls_niezweryfikowany" and rows[1][-1] == "tak" and rows[2][-1] == ""


def test_cli_strict_tls_flag_passed_to_fetcher(tmp_path, monkeypatch):
    from username_engine.sources import save_db
    db = tmp_path / "sites.json"
    save_db([Site("Gh", "https://gh.com/{username}", e_strings=["avatar"])], db)
    seen = {}

    class F:
        def __init__(self, *a, **k): seen.update(k)
        async def __aenter__(self): return self
        async def __aexit__(self, *e): pass
        async def fetch(self, method, url, headers=None, body=None): return Response(404, "", final_url=url)

    monkeypatch.setattr(cli, "Fetcher", F)
    cli.main(["alice", "--db", str(db), "--no-variants", "--strict-tls"])
    assert seen.get("strict_tls") is True
    cli.main(["alice", "--db", str(db), "--no-variants"])
    assert seen.get("strict_tls") is False


# ---------------------------------------------------------------- regex z bazy

def test_dangerous_or_oversized_regex_is_unsupported_without_request():
    f = FakeFetcher(lambda url: Response(200, "avatar", final_url=url))
    for rx in (r"^(a+)+$", r"^(a*)*$", r"^(a+)*$", r"^([a-z]+\d*)+$", "^" + "a" * 600 + "$"):
        s = Site("Rx", "https://rx.com/{username}", regex=rx, e_strings=["avatar"])
        r = run(check_site(s, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa!", f))
        assert r.status is Status.UNSUPPORTED, rx
    assert f.calls == []
    ok = Site("Ok", "https://ok.com/{username}", regex=r"^[a-z0-9_]{3,16}$", e_strings=["avatar"])
    assert run(check_site(ok, "alice", f, control="none")).status is Status.FOUND
    long_name = Site("Ln", "https://ln.com/{username}", regex=r"^[a-z]+$", e_strings=["avatar"])
    assert run(check_site(long_name, "a" * 300, f)).status is Status.UNSUPPORTED


# ---------------------------------------------------------------- CSV

def test_csv_neutralizes_formulas(tmp_path):
    evil = ["=HYPERLINK(\"http://x\")", "+1+1", "-2+3", "@SUM(A1)", "\tcmd", "\rcmd", " =1+1", "\x01=1+1"]
    results = [Result(e, "https://x.com/a", Status.ERROR, reason=e) for e in evil]
    p = tmp_path / "w.csv"
    write_csv(p, {evil[0]: results})
    rows = list(csv.reader(open(p, encoding="utf-8-sig", newline=""), delimiter=";"))[1:]
    assert rows[0][0].startswith("'=")
    for row, e in zip(rows, evil):
        assert row[1] == "'" + e and row[5] == "'" + e, e
    plain = Result("Github", "https://x.com/a", Status.FOUND, 0.9, "tekst obecności")
    write_csv(p, {"alice": [plain]})
    row = list(csv.reader(open(p, encoding="utf-8-sig"), delimiter=";"))[1]
    assert row[:3] == ["alice", "Github", "FOUND"] and row[3] == "0.90"


def test_csv_write_is_atomic(tmp_path, monkeypatch):
    p = tmp_path / "w.csv"
    p.write_text("STARE", encoding="utf-8")

    def boom(*a, **k):
        raise OSError("dysk pełny")

    monkeypatch.setattr(os, "replace", boom)
    with pytest.raises(OSError):
        write_csv(p, {"a": [Result("S", "https://s/a", Status.FOUND, 0.9)]})
    assert p.read_text(encoding="utf-8") == "STARE"
    assert [x.name for x in tmp_path.iterdir()] == ["w.csv"]       # brak osieroconego pliku tymczasowego


# ---------------------------------------------------------------- niepoprawne URL-e

def test_bad_urls_do_not_break_correlation_or_dorks():
    a = Account("x", "A", "https://a.com/x", {"links": ["http://[bad", "https://b.com/x"], "website": "http://[bad"})
    b = Account("y", "B", "https://b.com/x", {"website": "http://[also-bad", "bio": "http://[bad"})
    link = link_accounts(a, b)
    assert link.score >= 0.7                                  # dobry link nadal liczy się
    bad_site = Site("Bad", "http://[bad/{username}")
    good = Site("Good", "https://good.com/{username}")
    assert wayback_targets([bad_site, good], "alice") == ["https://good.com/alice"]


def test_cli_analysis_and_exports_isolated(tmp_path, monkeypatch, capsys):
    from username_engine.sources import save_db
    db = tmp_path / "sites.json"
    save_db([Site("Gh", "https://gh.com/{username}", e_strings=["avatar"])], db)

    class F:
        def __init__(self, *a, **k): pass
        async def __aenter__(self): return self
        async def __aexit__(self, *e): pass
        async def fetch(self, method, url, headers=None, body=None):
            return Response(200 if url.endswith("/alice") else 404, "avatar", final_url=url)

    def boom(*a, **k):
        raise RuntimeError("awaria")

    monkeypatch.setattr(cli, "Fetcher", F)
    monkeypatch.setattr(cli, "analyze", boom)
    monkeypatch.setattr(cli, "render_html", boom)
    out_dir = tmp_path / "wyniki"
    rc = cli.main(["alice", "--db", str(db), "--no-variants", "--results-dir", str(out_dir), "--report", "o.html",
                   "--csv", "o.csv", "--json", "o.json"])
    (scan_dir,) = [d for d in out_dir.iterdir() if d.is_dir()]
    csv_p, json_p, html_p = scan_dir / "o.csv", scan_dir / "o.json", scan_dir / "o.html"
    captured = capsys.readouterr()
    assert rc == 1
    assert csv_p.exists() and json_p.exists() and not html_p.exists()
    assert "awaria" in captured.err
    assert json.loads(json_p.read_text(encoding="utf-8"))["results"]["alice"][0]["status"] == "FOUND"
    assert [x.name for x in scan_dir.iterdir() if x.suffix == ".tmp"] == []


# ---------------------------------------------------------------- wypisywanie w terminalu

def test_terminal_output_neutralizes_control_chars():
    r = Result("Ev\x1b[2Jil\nFAKE", "https://x/\x07a", Status.FOUND, 0.9, "tekst\x1b]0;x\x07")
    line = cli.format_result(r)
    assert "\x1b" not in line and "\x07" not in line and "\n" not in line
    assert "\\x1b" in line and "\\x07" in line and "\\x0a" in line
    err = cli.format_result(Result("S\x1b", "u", Status.ERROR, reason="r\x00"))
    assert "\x1b" not in err and "\x00" not in err


def test_personal_profile_data_in_stdout_only_with_details(capsys):
    ev = [Evidence("PL", 1.0, 'GitHub: location "Kraków, tajna ulica"', personal=True),
          Evidence("PL", 0.15, "GitHub: domena .pl")]
    analysis = {"country": aggregate(ev), "profiles_with_data": 1, "variant_links": {}, "pairs": [
        {"a": "A (x)", "b": "B (y)", "score": 0.6, "reasons": ['ta sama lokalizacja "Kraków"', "A linkuje do B"]}]}
    cli.print_analysis(analysis)
    out = capsys.readouterr().out
    assert "Kraków" not in out and "tajna" not in out and "domena .pl" in out and "A linkuje do B" in out
    cli.print_analysis(analysis, details=True)
    out = capsys.readouterr().out
    assert "tajna ulica" in out and 'lokalizacja "Kraków"' in out
