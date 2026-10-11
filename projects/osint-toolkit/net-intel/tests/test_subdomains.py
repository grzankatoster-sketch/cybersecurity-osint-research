import json
import socket
import threading

import pytest

from conftest import FakeFetch, Response, fixture_text, ok, subdomain_fetch
from net_intel.cli import main
from net_intel.http import FetchError
from net_intel.subdomains import (
    clean_name, enumerate_subdomains, parse_certspotter_page, parse_crtsh, parse_hackertarget,
    resolve_entries, source_certspotter, system_resolve,
)

D = "example.org"
ALL_FAILED_MSG = "nie udało się sprawdzić (wszystkie źródła zawiodły)"


# --- czyszczenie nazw --------------------------------------------------------------------------

@pytest.mark.parametrize("raw,expected", [
    ("WWW.Example.org", "www.example.org"),
    ("*.example.org", "example.org"),
    ("*.stage.example.org.", "stage.example.org"),
    ("example.org", "example.org"),
    ("_dmarc.example.org", "_dmarc.example.org"),
    ("notexample.org", None),
    ("example.org.attacker.com", None),
    ("user@example.org", None),
    ("a.*.example.org", None),
    ("bad name.example.org", None),
    ("-x.example.org", None),
    ("", None),
])
def test_clean_name(raw, expected):
    assert clean_name(raw, D) == expected


# --- parsery źródeł ----------------------------------------------------------------------------

def test_hackertarget_ok():
    r = parse_hackertarget(fixture_text("hackertarget_ok.txt"), D)
    assert r.ok and r.names == {"example.org", "www.example.org", "mail.example.org", "ipv6.example.org", "cdn.example.org"}
    assert r.ips["mail.example.org"] == {"192.0.2.25"}
    assert r.status_text == "OK(5)"


@pytest.mark.parametrize("fixture,fragment", [
    ("hackertarget_limit.txt", "limit API"),
    ("hackertarget_error.txt", "komunikat zamiast wyników"),
])
def test_hackertarget_limit_and_error_are_source_errors(fixture, fragment):
    r = parse_hackertarget(fixture_text(fixture), D)
    assert not r.ok and fragment in r.error and r.names == set()
    assert r.status_text.startswith("ERROR(")


def test_hackertarget_no_records_is_genuine_empty():
    r = parse_hackertarget(fixture_text("hackertarget_empty.txt"), D)
    assert r.ok and r.names == set() and r.status_text == "OK(0)"


def test_hackertarget_empty_body_is_error():
    assert not parse_hackertarget("", D).ok
    assert not parse_hackertarget("\n  \n", D).ok


def test_hackertarget_limit_text_with_valid_lines_still_counts_lines():
    r = parse_hackertarget("www.example.org,192.0.2.1\nAPI count exceeded", D)
    assert r.ok and r.names == {"www.example.org"}


def test_certspotter_page_parsing():
    names, last, err = parse_certspotter_page(fixture_text("certspotter_page1.json"), D)
    assert err == "" and last == "1003"
    assert names == {"example.org", "www.example.org", "api.example.org", "stage.example.org", "mail.example.org"}


def test_certspotter_error_and_garbage():
    assert "rate limit" in parse_certspotter_page(fixture_text("certspotter_error.json"), D)[2]
    assert parse_certspotter_page("<html>", D)[2]
    assert parse_certspotter_page("[]", D) == (set(), None, "")


def test_certspotter_pagination_merges_pages():
    f = FakeFetch().on("certspotter.com", [ok("certspotter_page1.json"), ok("certspotter_page2.json"), ok("certspotter_empty.json")])
    r = source_certspotter(D, f, 5, max_pages=3)
    assert r.ok and not r.note and "old.example.org" in r.names and len(r.names) == 6
    assert "after=1003" in f.urls()[1] and "after=1004" in f.urls()[2]


def test_certspotter_later_page_failure_is_partial_not_error():
    f = FakeFetch().on("certspotter.com", [ok("certspotter_page1.json"), Response(429, "")])
    r = source_certspotter(D, f, 5)
    assert r.ok and "niepełne" in r.note and "429" in r.note and "api.example.org" in r.names


def test_certspotter_first_page_failure_is_error():
    r = source_certspotter(D, FakeFetch().on("certspotter.com", Response(429, "")), 5)
    assert not r.ok and "429" in r.error


def test_rate_limit_error_includes_retry_after():
    r = source_certspotter(D, FakeFetch().on("certspotter.com", Response(429, "{}", {"retry-after": "67"})), 5)
    assert not r.ok and "429" in r.error and "67 s" in r.error


def test_certspotter_page_limit_noted():
    f = FakeFetch().on("certspotter.com", ok("certspotter_page1.json"))
    r = source_certspotter(D, f, 5, max_pages=2)
    assert r.ok and "niepełne" in r.note and len(f.calls) == 2


def test_crtsh_ok_dedupes_wildcards_and_drops_emails():
    r = parse_crtsh(fixture_text("crtsh_ok.json"), D)
    assert r.ok and r.names == {"example.org", "www.example.org", "vpn.example.org", "dev.example.org"}


def test_crtsh_html_error_page_is_error():
    r = parse_crtsh(fixture_text("crtsh_503.html"), D)
    assert not r.ok and "JSON" in r.error


def test_crtsh_empty_array_is_genuine_empty_but_empty_body_is_error():
    assert parse_crtsh("[]", D).ok
    assert not parse_crtsh("", D).ok
    assert not parse_crtsh('{"a": 1}', D).ok


# --- scalanie i reguła "porażka != brak wyników" ------------------------------------------------

def test_merge_sorted_deduped_with_sources():
    res = enumerate_subdomains(D, subdomain_fetch(), 5)
    names = [e.name for e in res.entries]
    assert names == sorted(set(names))
    by = {e.name: e for e in res.entries}
    assert by["www.example.org"].sources == ["hackertarget", "certspotter", "crt.sh"]
    assert by["mail.example.org"].sources == ["hackertarget", "certspotter"]
    assert by["vpn.example.org"].sources == ["crt.sh"]
    assert by["old.example.org"].sources == ["certspotter"]
    assert by["mail.example.org"].passive_ips == ["192.0.2.25"]
    assert "other.invalid-example.net" not in by and "notexample.org" not in by
    assert res.status == "ok" and not res.all_failed


def test_one_source_failing_is_partial():
    res = enumerate_subdomains(D, subdomain_fetch(crt=Response(503, "")), 5)
    assert res.status == "partial" and not res.all_failed
    assert [s.status_text for s in res.sources if not s.ok] == ["ERROR(HTTP 503)"]
    assert "vpn.example.org" not in [e.name for e in res.entries]


def failing_fetch():
    return subdomain_fetch(ht=ok("hackertarget_limit.txt"), cs=Response(429, ""), crt=ok("crtsh_503.html", 503))


def test_all_sources_failed_is_not_zero_results():
    res = enumerate_subdomains(D, failing_fetch(), 5)
    assert res.all_failed and res.status == "failed"
    d = res.to_dict()
    assert d["count"] is None and d["checked"] is False
    assert all(s["status"] == "ERROR" for s in d["sources"])


def test_genuine_empty_is_zero_results():
    f = subdomain_fetch(ht=ok("hackertarget_empty.txt"), cs=ok("certspotter_empty.json"), crt=Response(200, "[]"))
    res = enumerate_subdomains(D, f, 5)
    assert not res.all_failed and res.status == "ok" and res.entries == []
    assert res.to_dict()["count"] == 0 and res.to_dict()["checked"] is True


def test_network_exceptions_become_source_errors():
    f = subdomain_fetch(ht=FetchError("przekroczono limit czasu"), cs=FetchError("błąd sieci: x"), crt=FetchError("błąd sieci: y"))
    res = enumerate_subdomains(D, f, 5)
    assert res.all_failed and "limit czasu" in res.sources[0].error


def test_unexpected_exception_in_source_is_error_not_crash():
    def boom(domain, fetch, timeout):
        raise KeyError("x")
    res = enumerate_subdomains(D, FakeFetch(), 5, sources={"bad": boom})
    assert res.all_failed and "KeyError" in res.sources[0].error


# --- CLI: kody wyjścia i komunikaty ----------------------------------------------------------

def test_cli_all_failed_differs_from_genuine_zero(capsys):
    code_failed = main(["subdomains", D], fetch=failing_fetch())
    out_failed = capsys.readouterr().out
    empty = subdomain_fetch(ht=ok("hackertarget_empty.txt"), cs=ok("certspotter_empty.json"), crt=Response(200, "[]"))
    code_zero = main(["subdomains", D], fetch=empty)
    out_zero = capsys.readouterr().out
    assert code_failed == 1 and code_zero == 0
    assert ALL_FAILED_MSG in out_failed and ALL_FAILED_MSG not in out_zero
    assert "ERROR(" in out_failed and "OK(0)" in out_zero
    assert "0 nazw" in out_zero and "0 nazw" not in out_failed


def test_cli_all_failed_json(capsys):
    code = main(["subdomains", D, "--json"], fetch=failing_fetch())
    out = json.loads(capsys.readouterr().out)
    assert code == 1 and out["status"] == "failed" and out["result"]["count"] is None
    assert ALL_FAILED_MSG in out["headline"]


def test_cli_ok_json_and_per_source_counts(capsys):
    code = main(["subdomains", D, "--json"], fetch=subdomain_fetch())
    out = json.loads(capsys.readouterr().out)
    assert code == 0 and out["status"] == "ok"
    counts = {s["source"]: s["count"] for s in out["result"]["sources"]}
    assert counts == {"hackertarget": 5, "certspotter": 6, "crt.sh": 4}
    assert out["result"]["count"] == len(out["result"]["subdomains"]) == 10


def test_cli_partial_mentions_incomplete(capsys):
    code = main(["subdomains", D], fetch=subdomain_fetch(crt=Response(503, "")))
    text = capsys.readouterr().out
    assert code == 0 and "niepełny" in text and "crt.sh" in text and "ERROR(HTTP 503)" in text


def test_cli_html_report_escaped_and_atomic(tmp_path, capsys):
    path = tmp_path / "r.html"
    assert main(["subdomains", D, "--html", str(path)], fetch=subdomain_fetch()) == 0
    html = path.read_text(encoding="utf-8")
    assert "<!doctype html>" in html and "prefers-color-scheme:dark" in html and "www.example.org" in html
    assert not [p for p in tmp_path.iterdir() if p.name.endswith(".tmp")]
    assert "Zapisano raport HTML" in capsys.readouterr().out


def test_cli_html_failure_to_write_exit_1(tmp_path, capsys):
    bad = tmp_path / "brak_katalogu" / "r.html"
    code = main(["subdomains", D, "--html", str(bad)], fetch=subdomain_fetch())
    cap = capsys.readouterr()
    assert code == 1 and "Błąd zapisu raportu HTML" in cap.err and "www.example.org" in cap.out


def test_cli_html_all_failed_banner(tmp_path):
    path = tmp_path / "r.html"
    main(["subdomains", D, "--html", str(path)], fetch=failing_fetch())
    assert ALL_FAILED_MSG in path.read_text(encoding="utf-8")


def test_cli_usage_errors():
    for argv in (["subdomains"], [], ["bogus", D], ["subdomains", D, "--timeout", "0"],
                 ["subdomains", D, "--timeout", "nan"], ["subdomains", D, "--concurrency", "0"]):
        with pytest.raises(SystemExit) as ei:
            main(argv, fetch=FakeFetch())
        assert ei.value.code == 2
    assert main(["subdomains", "nie domena"], fetch=FakeFetch()) == 2


def test_cli_no_network_for_invalid_input():
    f = FakeFetch()
    assert main(["subdomains", "bad_domain"], fetch=f) == 2
    assert f.calls == []


def test_default_transport_sends_user_agent(monkeypatch):
    import net_intel.http as h
    seen = {}

    class FakeResp:
        status = 200
        headers = {}

        def read(self, n):
            return b"{}"

        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

    class FakeOpener:
        def open(self, req, timeout):
            seen["ua"] = req.get_header("User-agent")
            seen["timeout"] = timeout
            return FakeResp()

    monkeypatch.setattr(h, "_OPENER", FakeOpener())
    assert h.urllib_fetch("https://example.test/", timeout=3).status == 200
    assert seen["ua"].startswith("net-intel/") and seen["timeout"] == 3


# --- --resolve -------------------------------------------------------------------------------

def test_resolve_entries_with_concurrency_cap():
    res = enumerate_subdomains(D, subdomain_fetch(), 5)
    state = {"active": 0, "peak": 0}
    lock = threading.Lock()

    def slow(name):
        with lock:
            state["active"] += 1
            state["peak"] = max(state["peak"], state["active"])
        threading.Event().wait(0.02)
        with lock:
            state["active"] -= 1
        if name.startswith("vpn"):
            raise socket.gaierror(-3, "temp")
        return [] if name.startswith("old") else ["192.0.2.1"]

    skipped = resolve_entries(res, slow, workers=3, deadline=10)
    by = {e.name: e for e in res.entries}
    assert skipped == 0 and state["peak"] <= 3
    assert by["www.example.org"].resolved == ["192.0.2.1"]
    assert by["old.example.org"].resolved == []
    assert by["vpn.example.org"].resolved is None and "gaierror" in by["vpn.example.org"].resolve_error


def test_resolve_limit_marks_skipped():
    res = enumerate_subdomains(D, subdomain_fetch(), 5)
    skipped = resolve_entries(res, lambda n: ["192.0.2.1"], workers=2, deadline=10, limit=2)
    assert skipped == len(res.entries) - 2
    assert all("pominięto" in e.resolve_error for e in res.entries[2:])


def test_system_resolve_not_found_vs_error(monkeypatch):
    def nx(*a, **k):
        raise socket.gaierror(socket.EAI_NONAME, "not found")

    def tmp(*a, **k):
        raise socket.gaierror(-3, "temporary failure")
    monkeypatch.setattr(socket, "getaddrinfo", nx)
    assert system_resolve("x.example.org") == []
    monkeypatch.setattr(socket, "getaddrinfo", tmp)
    with pytest.raises(socket.gaierror):
        system_resolve("x.example.org")


def test_cli_resolve_flag_uses_injected_resolver(capsys):
    code = main(["subdomains", D, "--resolve", "--json", "--concurrency", "2"], fetch=subdomain_fetch(),
                resolve=lambda n: ["192.0.2.9"])
    out = json.loads(capsys.readouterr().out)
    assert code == 0
    assert all(e["resolved"] == ["192.0.2.9"] for e in out["result"]["subdomains"])


def test_cli_resolve_skipped_when_all_failed():
    def never(n):
        raise AssertionError("nie powinno rozwiązywać")
    assert main(["subdomains", D, "--resolve"], fetch=failing_fetch(), resolve=never) == 1
