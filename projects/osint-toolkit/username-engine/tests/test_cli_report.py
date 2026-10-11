import csv

from username_engine import cli
from username_engine.models import Response, Result, Site, Status
from username_engine.report import render_html, write_csv
from username_engine.sources import save_db


def test_show_variants_needs_no_db(capsys):
    assert cli.main(["Jan Kowalski", "--show-variants", "--max-variants", "3"]) == 0
    out = capsys.readouterr().out.split()
    assert out == ["jankowalski", "jan.kowalski", "jan_kowalski"]


def test_dorks_only_needs_no_db_or_network(capsys):
    assert cli.main(["Jan Kowalski", "--dorks-only", "--max-variants", "3"]) == 0
    out = capsys.readouterr().out
    assert "Wyszukiwarki" in out
    assert "site:facebook.com" in out


def _args(*argv):
    return cli.build_parser().parse_args(list(argv))


def test_variants_on_by_default_with_dots_and_typed_case_first():
    assert cli.names_to_scan(_args("JanKowalski")) == [
        "JanKowalski", "jan.kowalski", "jan_kowalski", "jan-kowalski", "jkowalski", "j.kowalski"]
    assert cli.names_to_scan(_args("Sampler51"))[:4] == ["Sampler51", "sampler.51", "sampler_51", "sampler-51"]


def test_no_variants_and_full_name_input():
    assert cli.names_to_scan(_args("JanKowalski", "--no-variants")) == ["JanKowalski"]
    assert "Jan Kowalski" not in cli.names_to_scan(_args("Jan Kowalski"))     # spacja to nie nazwa konta
    assert len(cli.names_to_scan(_args("JanKowalski", "--max-variants", "3"))) == 3


def test_variant_pool_uses_best_rules_only():
    from username_engine.models import Site
    sites = [Site("A", "https://a/{username}", source="custom"),
             Site("B", "https://b/{username}", source="wmn", tags=["social"]),
             Site("C", "https://c/{username}", source="wmn", tags=["misc"]),
             Site("D", "https://d/{username}", source="maigret", tags=["social"])]
    assert [s.name for s in cli.variant_pool(sites, None)] == ["A", "B"]
    assert len(cli.variant_pool(sites, "social")) == 4                         # --tags = pełna kontrola


def test_missing_db_returns_2(tmp_path, capsys):
    assert cli.main(["alice", "--db", str(tmp_path / "none.json")]) == 2


def test_html_escapes_and_links():
    results = [Result("Ev<il>", "https://x.com/<script>", Status.FOUND, 0.9, "tekst"),
               Result("Down", "https://d.com/a", Status.ERROR, reason="timeout")]
    html = render_html("a<b", {"a<b": results}, {"a<b": {"checked": 2, "error": 1, "unsupported": 0}},
                       [{"engine": "google", "query": '"a<b"', "url": "https://g/?q=x"}])
    assert "<script>" not in html and "&lt;script&gt;" in html
    assert "Nie udało się sprawdzić: 1" in html and "Wyszukiwarki" in html


def test_manual_check_list_for_blocked_sites():
    results = [Result("Allegro", "https://allegro.pl/uzytkownik/a", Status.ERROR, reason="dostęp zabroniony (403)"),
               Result("Ig", "https://ig.com/a", Status.ERROR, reason="wymaga logowania (przekierowanie na logowanie)"),
               Result("Slow", "https://s.com/a", Status.ERROR, reason="timeout")]
    html = render_html("a", {"a": results}, {"a": {"checked": 3, "error": 3, "unsupported": 0}}, [])
    assert "Sprawdź ręcznie: 2" in html and "https://allegro.pl/uzytkownik/a" in html
    assert "Nie udało się sprawdzić: 1" in html                             # timeout osobno
    extra = [Result("Gutefrage", "https://gutefrage.net/nutzer/a", Status.ERROR, reason="zablokowane wg kontroli bazy")]
    html = render_html("a", {"a": results}, {"a": {"checked": 3, "error": 3, "unsupported": 0}}, [],
                       manual_extra=extra)
    assert "Sprawdź ręcznie: 3" in html and "gutefrage.net/nutzer/a" in html


def test_csv_export(tmp_path):
    p = tmp_path / "w.csv"
    write_csv(p, {"alice": [Result("Gh", "https://gh.com/alice", Status.FOUND, 0.97, "ok", 200)]})
    rows = list(csv.reader(open(p, encoding="utf-8-sig"), delimiter=";"))
    assert rows[0][:3] == ["nazwa", "serwis", "status"] and rows[1][:4] == ["alice", "Gh", "FOUND", "0.97"]


def test_full_cli_run_with_fake_network(tmp_path, monkeypatch, capsys):
    db = tmp_path / "sites.json"
    save_db([Site("Gh", "https://gh.com/{username}", e_strings=["avatar"], tags=["social"]),
             Site("Fo", "https://fo.com/{username}", e_strings=["avatar"], tags=["forum"])], db)

    class FakeFetcher:
        def __init__(self, *a, **k): pass
        async def __aenter__(self): return self
        async def __aexit__(self, *e): pass
        async def fetch(self, method, url, headers=None, body=None):
            if "web.archive.org" in url:
                return Response(200, '[["timestamp","original","statuscode"],["20200101000000","fo.com/alice","200"]]',
                                final_url=url)
            return Response(200, "avatar" if ("gh.com" in url and url.endswith("/alice")) else "nic", final_url=url)

    monkeypatch.setattr(cli, "Fetcher", FakeFetcher)
    monkeypatch.setattr(cli, "WAYBACK_TAGS", {"forum"})
    out_dir = tmp_path / "wyniki"
    assert cli.main(["alice", "--db", str(db), "--wayback", "--results-dir", str(out_dir),
                     "--report", "r.html", "--csv", "r.csv"]) == 0
    (scan_dir,) = [d for d in out_dir.iterdir() if d.is_dir()]
    report = scan_dir / "r.html"
    out = capsys.readouterr().out
    assert "[+]" in out and "gh.com/alice" in out
    assert "[A] https://fo.com/alice" in out
    html = report.read_text(encoding="utf-8")
    assert "Archiwum" in html and "2020-01-01" in html
