"""E7 bezpiecznik (martwe proxy w trakcie skanu) i E8 poziomy skanu (quick/standard/full) + lista "do ręcznego
sprawdzenia". Zero prawdziwej sieci: atrapy Fetchera, atrapa preflightu, port bez nasłuchu."""
import asyncio
import json
import socket
from urllib.parse import urlsplit

import pytest

from username_engine import cli
from username_engine.engine import ABORT_REASON, PROXY_ABORT_AFTER, ScanResults, rescan_errors, scan
from username_engine.http import PROXY_DOWN, PreflightResult
from username_engine.models import Response, Result, Site, Status
from username_engine.report import render_html
from username_engine.sources import save_db


def run(coro):
    return asyncio.run(coro)


def _sites(n, tags=("social",)):
    return [Site(f"S{i}", f"http://s{i}.test/{{username}}", e_strings=["avatar"], tags=list(tags)) for i in range(n)]


class DyingFetcher:
    """Pierwsze `ok` zapytań działa, potem każde kończy się błędem martwego proxy."""

    def __init__(self, ok):
        self.ok, self.calls = ok, 0

    async def fetch(self, method, url, headers=None, body=None):
        self.calls += 1
        if self.calls > self.ok:
            return Response(None, error=PROXY_DOWN)
        await asyncio.sleep(0)
        return Response(200, "nic", final_url=url)


# ---------------------------------------------------------------- E7: bezpiecznik w silniku

def test_breaker_stops_scan_and_marks_rest_as_error_never_not_found():
    sites, f = _sites(300), DyingFetcher(ok=20)
    res = run(scan("alice", sites, f, control="none", concurrency=5, channel="proxy"))
    assert isinstance(res, ScanResults) and isinstance(res, list) and res.aborted is True
    assert len(res) == len(sites) and f.calls < 60            # daleko mniej zapytań niż serwisów
    skipped = [r for r in res if r.reason == ABORT_REASON]
    assert skipped and res.skipped == len(skipped)
    assert all(r.status is Status.ERROR and r.channel == "proxy" for r in skipped)
    assert not any(r.status is Status.NOT_FOUND for r in res[20 + PROXY_ABORT_AFTER:])
    assert [r.site for r in res] == [s.name for s in sites]    # kolejność jak w wejściu


def test_breaker_streak_must_be_consecutive():
    class Flaky(DyingFetcher):
        async def fetch(self, method, url, headers=None, body=None):
            self.calls += 1
            if self.calls % 3:      # co trzeci OK: seria nigdy nie dojdzie do 15
                return Response(None, error=PROXY_DOWN)
            return Response(200, "nic", final_url=url)

    res = run(scan("alice", _sites(80), Flaky(0), control="none", concurrency=1, channel="proxy"))
    assert res.aborted is False and all(r.reason != ABORT_REASON for r in res)


def test_breaker_threshold_is_a_parameter_and_can_be_disabled():
    res = run(scan("alice", _sites(100), DyingFetcher(0), control="none", concurrency=1, channel="proxy",
                   abort_after=3))
    assert res.aborted and sum(r.reason != ABORT_REASON for r in res) == 3
    f = DyingFetcher(0)
    res = run(scan("alice", _sites(40), f, control="none", concurrency=1, channel="proxy", abort_after=None))
    assert not res.aborted and f.calls == 40


def test_breaker_inactive_in_direct_mode():
    f = DyingFetcher(0)
    res = run(scan("alice", _sites(100), f, control="none", concurrency=1))      # kanał "direct"
    assert res.aborted is False and f.calls == 100 and all(r.reason != ABORT_REASON for r in res)


def test_unsupported_sites_stay_unsupported_after_abort():
    sites = _sites(30) + [Site("Regex", "http://rx.test/{username}", regex="^[0-9]+$", e_strings=["x"])]
    res = run(scan("alice", sites, DyingFetcher(0), control="none", concurrency=1, channel="proxy"))
    assert res.aborted and res[-1].status is Status.UNSUPPORTED


def test_rescan_after_abort_makes_no_calls():
    sites = _sites(60)
    res = run(scan("alice", sites, DyingFetcher(0), control="none", concurrency=1, channel="proxy"))
    assert res.aborted
    made = []

    class Ctx:
        async def __aenter__(self):
            made.append(1)
            return DyingFetcher(10 ** 6)

        async def __aexit__(self, *e):
            pass

    out = run(rescan_errors("alice", sites, res, Ctx, Ctx, retries=3, control="none"))
    assert made == [] and out.aborted and [r.reason for r in out] == [r.reason for r in res]


def test_rescan_round_that_finds_dead_proxy_aborts_and_skips_fallback():
    sites = _sites(60)
    first = [Result(s.name, s.profile_url("alice"), Status.ERROR, reason="timeout") for s in sites]
    made, fetchers = [], []

    def fresh():
        class Ctx:
            async def __aenter__(self_):
                made.append(1)
                fetchers.append(DyingFetcher(0))
                return fetchers[-1]

            async def __aexit__(self_, *e):
                pass
        return Ctx()

    out = run(rescan_errors("alice", sites, first, fresh, fresh, retries=3, control="none", concurrency=1))
    assert out.aborted and len(made) == 1 and fetchers[0].calls < 30
    assert all(r.status is Status.ERROR and r.reason == "timeout" for r in out)     # oryginalne błędy zostają


# ---------------------------------------------------------------- E7: CLI od początku do końca

def _free_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _db(tmp_path, sites):
    db = tmp_path / "sites.json"
    save_db(sites, db)
    return db


def _run_cli(tmp_path, db, *extra):
    return cli.main(["alice", "--db", str(db), "--no-variants", "--include-broken",
                     "--results-dir", str(tmp_path / "wyniki"), *extra])


def _scan_dir(tmp_path):
    (d,) = [d for d in (tmp_path / "wyniki").iterdir() if d.is_dir()]
    return d


def test_cli_proxy_dies_mid_scan_exit_3_partial_report_with_banner(tmp_path, capsys, monkeypatch):
    monkeypatch.delenv("OSINT_PROXY", raising=False)
    monkeypatch.delenv("OSINT_PROXY_FALLBACK", raising=False)

    async def ok_preflight(url, *a, **k):          # kontrola kanału przechodzi, potem proxy "znika"
        return PreflightResult(True, True, "185.220.x.x")

    monkeypatch.setattr(cli, "preflight", ok_preflight)
    db = _db(tmp_path, _sites(150))
    # prawdziwy Fetcher + port bez nasłuchu: każde połączenie z proxy jest odrzucane (PROXY_DOWN)
    code = _run_cli(tmp_path, db, "--proxy", f"socks5h://127.0.0.1:{_free_port()}", "--report", "r.html",
                    "--json", "w.json", "--csv", "w.csv")
    cap = capsys.readouterr()
    assert code == 3
    assert "Proxy przestało działać w trakcie skanu (sprawdzono" in cap.err and "z 150 serwisów" in cap.err
    assert "zero ruchu bezpośredniego. Raport częściowy zapisany." in cap.err
    d = _scan_dir(tmp_path)
    assert (d / "w.csv").exists()
    html = (d / "r.html").read_text(encoding="utf-8")
    assert "Raport częściowy: proxy przestało działać" in html and "Do ręcznego sprawdzenia" in html
    data = json.loads((d / "w.json").read_text(encoding="utf-8"))
    assert data["meta"]["aborted"] is True and data["meta"]["abort"]["total"] == 150
    assert data["meta"]["sites_checked"] < 150 and data["meta"]["manual_check_aborted_count"] > 0
    results = data["results"]["alice"]
    assert len(results) == 150 and not any(r["status"] == "NOT_FOUND" for r in results)
    assert any(r["reason"] == ABORT_REASON for r in results)
    assert "przerwano: proxy" in cap.out        # lista do ręcznego sprawdzenia w terminalu liczy niesprawdzone osobno


def test_cli_direct_never_aborts(tmp_path, capsys, monkeypatch):
    class F:
        calls = 0

        def __init__(self, *a, **k): pass
        async def __aenter__(self): return self
        async def __aexit__(self, *e): pass

        async def fetch(self, method, url, headers=None, body=None):
            F.calls += 1
            return Response(None, error=PROXY_DOWN)

    monkeypatch.setattr(cli, "Fetcher", F)
    db = _db(tmp_path, _sites(120))
    assert _run_cli(tmp_path, db, "--direct", "--json", "w.json") == 0
    data = json.loads((_scan_dir(tmp_path) / "w.json").read_text(encoding="utf-8"))
    assert F.calls == 120 and data["meta"]["aborted"] is False
    assert data["meta"]["sites_checked"] == 120


# ---------------------------------------------------------------- E8: poziomy

class HostLog:
    """Fetcher-atrapa: zapisuje hosty; Wayback CDX odpowiada jednym zrzutem."""
    log: list[str] = []

    def __init__(self, *a, **k): pass
    async def __aenter__(self): return self
    async def __aexit__(self, *e): pass

    async def fetch(self, method, url, headers=None, body=None):
        host = urlsplit(url).hostname
        HostLog.log.append(host)
        if host == "web.archive.org":
            return Response(200, '[["timestamp","original","statuscode"],["20200101000000","x","200"]]', final_url=url)
        return Response(200, "avatar" if url.endswith("/alice") and host == "soc.test" else "nic", final_url=url)


@pytest.fixture
def host_log(monkeypatch):
    HostLog.log = []
    monkeypatch.setattr(cli, "Fetcher", HostLog)
    monkeypatch.delenv("OSINT_PROXY", raising=False)
    monkeypatch.delenv("OSINT_PROXY_FALLBACK", raising=False)
    return HostLog.log


def _level_db(tmp_path):
    sites = [Site("Soc", "http://soc.test/{username}", e_strings=["avatar"], tags=["social"]),
             Site("Pl", "http://pl.test/{username}", e_strings=["avatar"], tags=["pl"]),
             Site("Foro", "http://foro.test/{username}", e_strings=["avatar"], tags=["forum"]),
             Site("Gra", "http://gra.test/{username}", e_strings=["avatar"], tags=["gaming"])]
    return _db(tmp_path, sites)


def _targets(log):
    return {h for h in log if h != "web.archive.org"}


def test_default_level_is_full_and_unchanged(tmp_path, host_log):
    assert cli.build_parser().parse_args(["alice"]).level == "full"
    assert _run_cli(tmp_path, _level_db(tmp_path), "--json", "w.json") == 0
    assert _targets(host_log) == {"soc.test", "pl.test", "foro.test", "gra.test"}
    assert "web.archive.org" not in host_log                 # full: Wayback tylko z --wayback
    meta = json.loads((_scan_dir(tmp_path) / "w.json").read_text(encoding="utf-8"))["meta"]
    assert meta["level"] == "full" and meta["sites_checked"] == 4 and meta["aborted"] is False
    assert meta["priority_tags"] == ["pl", "social"]


def test_standard_selects_union_of_priority_tags_and_tags_option(tmp_path, host_log, capsys):
    db = _level_db(tmp_path)
    assert _run_cli(tmp_path, db, "--level", "standard") == 0
    out = capsys.readouterr().out
    assert _targets(host_log) == {"soc.test", "pl.test"}
    assert "Poziom standard: 2 serwisów priorytetowych" in out
    assert "web.archive.org" in host_log                      # standard włącza Wayback sam
    host_log.clear()
    assert _run_cli(tmp_path, db, "--level", "standard", "--tags", "forum") == 0
    assert _targets(host_log) == {"soc.test", "pl.test", "foro.test"}        # suma, nie przecięcie
    assert "Poziom standard: 3 serwisów" in capsys.readouterr().out


def test_quick_makes_zero_requests_to_target_sites_only_wayback(tmp_path, host_log, capsys):
    db = _level_db(tmp_path)
    assert _run_cli(tmp_path, db, "--level", "quick", "--report", "r.html", "--json", "w.json", "--csv", "w.csv") == 0
    cap = capsys.readouterr()
    assert host_log and set(host_log) == {"web.archive.org"}              # zero zapytań do serwisów docelowych
    assert len(host_log) == 2                                              # Soc + Pl (tagi priorytetowe)
    assert "ślad w archiwum (nie dowód istnienia konta)" in cap.out
    assert "google.com/search" in cap.out                                  # dorki zawsze w trybie pasywnym
    d = _scan_dir(tmp_path)
    html = (d / "r.html").read_text(encoding="utf-8")
    assert "Tryb szybki: tylko źródła pasywne" in html and "Ślad w archiwum (nie dowód istnienia konta)" in html
    assert "Brak trafień" not in html
    data = json.loads((d / "w.json").read_text(encoding="utf-8"))
    assert data["meta"]["level"] == "quick" and data["meta"]["sites_checked"] == 0
    assert len(data["wayback"]) == 2


def test_quick_through_proxy_runs_preflight_fail_closed(tmp_path, capsys, monkeypatch):
    async def bad(url, *a, **k):
        return PreflightResult(False, error="proxy: brak połączenia z proxy")

    class NoFetcher:
        def __init__(self, *a, **k): raise AssertionError("ruch mimo nieudanej kontroli kanału")

    monkeypatch.setattr(cli, "preflight", bad)
    monkeypatch.setattr(cli, "Fetcher", NoFetcher)
    assert _run_cli(tmp_path, _level_db(tmp_path), "--level", "quick", "--proxy", "socks5h://127.0.0.1:9") == 3
    assert "Proxy niedostępne" in capsys.readouterr().err


# ---------------------------------------------------------------- lista "do ręcznego sprawdzenia"

def _errors(n):
    return [Result(f"Site{i}", f"https://e{i}.test/u?x=1&y=<2>", Status.ERROR, reason=f"timeout <{i}>")
            for i in range(n)]


def test_manual_list_in_html_is_complete_and_escaped():
    rows = _errors(60) + [Result("<b>Zły</b>", "javascript:alert(1)", Status.ERROR, reason="błąd & <script>")]
    html = render_html("a", {"a": rows}, {"a": {"checked": 61, "error": 61, "unsupported": 0}}, [], level="full")
    assert "Do ręcznego sprawdzenia" in html
    assert "Otwórz w Tor Browserze; serwis zablokował automatyczne sprawdzenie (błąd ≠ brak konta)." in html
    assert "<b>Zły</b>" not in html and "&lt;b&gt;Zły&lt;/b&gt;" in html and "<script>" not in html
    assert "href='javascript:" not in html
    assert html.count("rel='noreferrer noopener' target='_blank'") == 60      # wszystkie 60 (bez limitu), tylko http(s)
    assert "x=1&amp;y=&lt;2&gt;" in html
    assert "Sprawdź ręcznie:" not in html                                      # zastępuje starsze dwie listy


def test_manual_list_counts_aborted_separately_in_html():
    rows = _errors(2) + [Result("Nie", "https://n.test/a", Status.ERROR, reason=ABORT_REASON)]
    html = render_html("a", {"a": rows}, {"a": {"checked": 3, "error": 3, "unsupported": 0}}, [], level="full",
                       aborted={"checked": 2, "total": 3})
    assert "2 błędów skanu + 1 niesprawdzonych (skan przerwany)" in html
    assert "Raport częściowy: proxy przestało działać" in html and "sprawdzono 2 z 3 serwisów" in html


def test_manual_list_text_is_capped_at_50(capsys):
    cli.print_manual_list(_errors(60), has_report=True)
    out = capsys.readouterr().out
    assert out.count("\n  - ") == 50 and "i 10 więcej w raporcie" in out
    assert "Otwórz w Tor Browserze" in out and "(60 błędów skanu)" in out
    cli.print_manual_list([], has_report=True)
    assert capsys.readouterr().out == ""


def test_legacy_render_html_without_level_keeps_old_sections():
    html = render_html("a", {"a": _errors(1)}, {"a": {"checked": 1, "error": 1, "unsupported": 0}}, [])
    assert "Nie udało się sprawdzić: 1" in html and "Do ręcznego sprawdzenia" not in html


def test_manual_summary_separates_preskipped_sites():
    """Serwisy pominięte z góry (kontrola bazy) to nie błędy skanu: osobna pozycja w opisie listy."""
    from username_engine.models import Result, Status
    from username_engine.report import PRESKIPPED_REASON, manual_summary
    rs = [Result("A", "https://a.test/x", Status.ERROR, reason="timeout"),
          Result("B", "https://b.test/x", Status.ERROR, reason=PRESKIPPED_REASON),
          Result("C", "https://c.test/x", Status.NOT_FOUND)]
    assert manual_summary(rs) == "1 błędów skanu + 1 pominiętych (blokują automaty wg kontroli bazy)"


def test_wayback_via_proxy_retries_on_fresh_circuits(monkeypatch):
    """archive.org dławi wyjścia Tora (503): każda próba na NOWYM Fetcherze, do WAYBACK_ATTEMPTS prób; martwe proxy
    przerywa ponawianie od razu."""
    import asyncio
    from username_engine import cli
    from username_engine.http import PROXY_DOWN
    from username_engine.models import Response
    monkeypatch.setattr(cli, "WAYBACK_BACKOFF", 0)
    made, plan = [], {"https://a.test/x": [503, 503, 200], "https://b.test/x": ["down"]}
    calls = {u: 0 for u in plan}

    class Fake:
        async def __aenter__(self):
            made.append(self)
            return self

        async def __aexit__(self, *a):
            return None

        async def fetch(self, method, url, *a, **k):
            target = next(u for u in plan if u.split("//")[1].split("/")[0] in url)
            step = plan[target][min(calls[target], len(plan[target]) - 1)]
            calls[target] += 1
            if step == "down":
                return Response(status=None, error=PROXY_DOWN)
            return Response(status=step, text="[]" if step == 200 else "busy")

    out = asyncio.run(cli.check_wayback(None, list(plan), fresh=Fake))
    assert calls["https://a.test/x"] == 3 and isinstance(out["https://a.test/x"], list)
    assert calls["https://b.test/x"] == 1 and out["https://b.test/x"].startswith("błąd archiwum")
    assert len(made) == 4          # każda próba = nowy obwód
