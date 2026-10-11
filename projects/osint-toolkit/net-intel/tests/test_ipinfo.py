import json
import socket

import pytest

from conftest import FakeFetch, FetchError, Response, fixture_text, ok
from net_intel.cli import main
from net_intel.ipinfo import (
    Rdns, fetch_ipinfo, local_scope, parse_ip, parse_ipinfo, reverse_lookup, split_org,
)


def test_split_org():
    assert split_org("AS15169 Google LLC") == ("AS15169", "Google LLC")
    assert split_org("Some Hosting") == (None, "Some Hosting")
    assert split_org(None) == (None, None)
    assert split_org("AS64500") == (None, "AS64500")


def test_parse_ipinfo_fixture():
    info = parse_ipinfo(json.loads(fixture_text("ipinfo_google.json")), "8.8.8.8")
    assert (info.asn, info.org_name) == ("AS15169", "Google LLC")
    assert info.hostname == "dns.google" and info.country == "US" and info.anycast is True
    assert info.timezone == "America/Los_Angeles" and info.bogon is False
    assert "loc" not in info.to_dict() and "postal" not in info.to_dict()


def test_parse_ipinfo_bogon():
    info = parse_ipinfo(json.loads(fixture_text("ipinfo_bogon.json")), "100.64.0.1")
    assert info.bogon is True and info.asn is None


@pytest.mark.parametrize("raw", ["10.1.2.3", "192.168.0.1", "127.0.0.1", "169.254.1.1", "0.0.0.0", "::1",
                                 "fe80::1", "fc00::1", "224.0.0.1", "192.0.2.1", "100.64.0.1", "240.0.0.1"])
def test_local_scope_non_public(raw):
    note = local_scope(parse_ip(raw))
    assert note and "prywatny/zarezerwowany" in note


@pytest.mark.parametrize("raw", ["8.8.8.8", "1.1.1.1", "2001:4860:4860::8888"])
def test_local_scope_public(raw):
    assert local_scope(parse_ip(raw)) is None


@pytest.mark.parametrize("raw", ["", "300.1.1.1", "abc", "1.2.3", "8.8.8.8/32"])
def test_parse_ip_rejects(raw):
    with pytest.raises(ValueError):
        parse_ip(raw)


def test_parse_ip_brackets():
    assert str(parse_ip("[2001:db8::1]")) == "2001:db8::1"


def test_fetch_ipinfo_ok_without_token_sends_no_auth():
    f = FakeFetch().on("ipinfo.io/8.8.8.8/json", ok("ipinfo_google.json"))
    info, err = fetch_ipinfo("8.8.8.8", f, 5, token=None)
    assert err == "" and info.asn == "AS15169"
    assert "Authorization" not in f.calls[0][1]
    assert f.urls() == ["https://ipinfo.io/8.8.8.8/json"]


@pytest.mark.parametrize("resp,fragment", [
    (Response(429, "rate"), "429"),
    (Response(403, "{}"), "token"),
    (Response(500, ""), "HTTP 500"),
    (Response(200, "<html>"), "JSON"),
    (Response(200, "[1]"), "format"),
    (Response(200, '{"error": {"title": "x", "message": "Wrong ip"}}'), "Wrong ip"),
    (FetchError("przekroczono limit czasu"), "limit czasu"),
])
def test_fetch_ipinfo_errors(resp, fragment):
    info, err = fetch_ipinfo("8.8.8.8", FakeFetch().on("ipinfo.io", resp), 5)
    assert info is None and fragment in err


def test_reverse_lookup_variants():
    assert reverse_lookup("8.8.8.8", 2, lambda ip: ("dns.google.", [], [ip])) == Rdns("ok", ["dns.google"])

    def no_ptr(ip):
        raise socket.herror(1, "Unknown host")
    assert reverse_lookup("192.0.2.1", 2, no_ptr).status == "none"
    assert reverse_lookup("192.0.2.1", 2, lambda ip: (ip, [], [ip])).status == "none"

    def boom(ip):
        raise socket.gaierror(-3, "Temporary failure")
    r = reverse_lookup("192.0.2.1", 2, boom)
    assert r.status == "error" and "Temporary failure" in r.error


def test_reverse_lookup_timeout():
    import threading
    gate = threading.Event()
    r = reverse_lookup("8.8.8.8", 0.05, lambda ip: gate.wait(5) or ("x", [], []))
    gate.set()
    assert r.status == "error" and "limit czasu" in r.error


# --- CLI -----------------------------------------------------------------------------------

def test_cli_private_ip_makes_no_network_call(capsys):
    f = FakeFetch()  # brak tras: jakiekolwiek zapytanie rzuci AssertionError

    def no_dns(ip, timeout):
        raise AssertionError("odwrotny DNS dla adresu prywatnego")

    assert main(["ip", "192.168.1.10", "--json"], fetch=f, reverse=no_dns) == 0
    out = json.loads(capsys.readouterr().out)
    assert f.calls == []
    assert out["result"]["scope"] == "local" and "prywatny/zarezerwowany" in out["result"]["local_reason"]
    assert out["status"] == "ok"


def test_cli_ip_public_ok(capsys):
    f = FakeFetch().on("ipinfo.io", ok("ipinfo_google.json"))
    code = main(["ip", "8.8.8.8", "--json"], fetch=f, reverse=lambda ip, t: Rdns("ok", ["dns.google"]))
    out = json.loads(capsys.readouterr().out)
    assert code == 0 and out["status"] == "ok"
    assert out["result"]["ipinfo"]["asn"] == "AS15169" and out["result"]["ipinfo"]["org"] == "Google LLC"
    assert out["result"]["reverse_dns"]["names"] == ["dns.google"]


def test_cli_ip_text_output(capsys):
    f = FakeFetch().on("ipinfo.io", ok("ipinfo_google.json"))
    main(["ip", "8.8.8.8"], fetch=f, reverse=lambda ip, t: Rdns("none"))
    text = capsys.readouterr().out
    assert "AS15169 Google LLC" in text and "brak rekordu PTR" in text


def test_cli_ip_partial_when_ipinfo_fails(capsys):
    f = FakeFetch().on("ipinfo.io", Response(429, ""))
    code = main(["ip", "8.8.8.8", "--json"], fetch=f, reverse=lambda ip, t: Rdns("ok", ["dns.google"]))
    out = json.loads(capsys.readouterr().out)
    assert out["status"] == "partial" and code == 0
    assert out["result"]["ipinfo"] is None and "429" in out["result"]["ipinfo_error"]


def test_cli_ip_all_sources_failed_is_not_empty_result(capsys):
    f = FakeFetch().on("ipinfo.io", FetchError("błąd sieci: x"))
    code = main(["ip", "8.8.8.8"], fetch=f, reverse=lambda ip, t: Rdns("error", error="przekroczono limit czasu"))
    text = capsys.readouterr().out
    assert code == 1 and "nie udało się sprawdzić (wszystkie źródła zawiodły)" in text


def test_cli_ip_invalid(capsys):
    assert main(["ip", "999.1.1.1"], fetch=FakeFetch()) == 2
    assert "nieprawidłowy adres IP" in capsys.readouterr().err


def test_token_sent_only_in_header_and_never_printed(capsys, monkeypatch, tmp_path):
    secret = "tok_SEKRET_123456"
    monkeypatch.setenv("IPINFO_TOKEN", secret)
    f = FakeFetch().on("ipinfo.io", Response(403, "{}"))
    html = tmp_path / "r.html"
    code = main(["ip", "8.8.8.8", "--html", str(html)], fetch=f, reverse=lambda ip, t: Rdns("none"))
    cap = capsys.readouterr()
    assert f.calls[0][1]["Authorization"] == f"Bearer {secret}"
    assert secret not in f.calls[0][0]
    assert secret not in cap.out and secret not in cap.err and secret not in html.read_text(encoding="utf-8")
    assert code == 0  # PTR odpowiedzial (brak rekordu), ipinfo odrzucone: wynik niepelny
