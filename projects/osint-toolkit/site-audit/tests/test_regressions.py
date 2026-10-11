"""Regresje z przegladu bezpieczenstwa (Codex, 2026-10-03): kazdy test odpowiada jednemu ustaleniu."""

import time

from site_audit.analyze import analyze
from site_audit.collector import collect
from site_audit.fetch import Fetcher, Hop, Response
from site_audit.models import Severity
from site_audit.parsers import csp_issues, frame_ancestors_open, parse_csp, parse_hsts, parse_page, parse_sitemap
from site_audit.report import printable
from site_audit.target import is_public, parse_target
from conftest import fake_resolver
from test_analyze import GOOD_HEADERS, NOW, fetched, resp, site, titles

RES = fake_resolver({"site.test": "127.0.0.1", "other.test": "127.0.0.1"})


# ---- budzet: naglowki i DNS (HIGH / MED)
def test_slow_headers_bounded_by_budget(server):
    server.add("/", delay_headers=(60, 0.1))
    start = time.monotonic()
    r = Fetcher(allow_private=True, resolver=RES, timeout=5, budget=0.6).get(server.url("/"))
    assert time.monotonic() - start < 2
    assert r.error_kind == "budget"


def test_slow_dns_bounded_by_budget():
    def slow(host, port):
        time.sleep(5)
        return ["93.184.216.34"]
    start = time.monotonic()
    r = Fetcher(resolver=slow, timeout=5, budget=0.5).get("https://slow.test/")
    assert time.monotonic() - start < 1.5
    assert r.error_kind in ("budget", "timeout") and r.response is None


def test_dns_timeout_shorter_than_budget():
    def slow(host, port):
        time.sleep(3)
        return ["93.184.216.34"]
    r = Fetcher(resolver=slow, timeout=0.3, budget=30).get("https://slow.test/")
    assert r.error_kind == "timeout"


# ---- NAT64 / 6to4 (HIGH)
def test_nat64_embedding_private_ipv4_is_blocked():
    assert not is_public("64:ff9b::a00:1")          # 10.0.0.1
    assert not is_public("64:ff9b::a9fe:a9fe")      # 169.254.169.254 (metadane chmury)
    assert not is_public("64:ff9b:1::7f00:1")       # 127.0.0.1, prefiks lokalny RFC 8215
    assert is_public("64:ff9b::5db8:d822")          # 93.184.216.34
    assert is_public("::ffff:93.184.216.34")


# ---- zakres plikow pomocniczych przed zadaniem (MED)
def test_helper_redirect_offhost_makes_no_request(server):
    server.add("/", 200, [("Content-Type", "text/html")])
    server.add("/robots.txt", 302, [("Location", server.url("/r.txt", "other.test"))])
    server.add("/r.txt", 200)
    data = collect(parse_target(server.url("/")), Fetcher(allow_private=True, resolver=RES, timeout=3))
    assert data.robots.error_kind == "offhost" and "/r.txt" not in server.hits


def test_sitemap_on_other_port_not_fetched(server):
    server.add("/", 200, [("Content-Type", "text/html")])
    server.add("/robots.txt", 200, [("Content-Type", "text/plain")], "Sitemap: http://site.test:1/s.xml\n")
    data = collect(parse_target(server.url("/")), Fetcher(allow_private=True, resolver=RES, timeout=3))
    assert data.sitemap_url == server.url("/sitemap.xml")
    assert any("poza audytowanym hostem" in n for n in data.notes)


# ---- XML (MED)
def test_sitemap_utf16_doctype_refused():
    bomb = ('<?xml version="1.0" encoding="UTF-16"?><!DOCTYPE l [<!ENTITY a "aaaa">]>'
            "<urlset><url>&a;</url></urlset>").encode("utf-16")
    assert "DOCTYPE" in parse_sitemap(bomb).error


def test_sitemap_utf16_without_dtd_still_parsed():
    ok = '<?xml version="1.0" encoding="UTF-16"?><urlset><url/><url/></urlset>'.encode("utf-16")
    assert parse_sitemap(ok).count == 2


# ---- wejscie od serwera wywracajace audyt (MED)
def test_hsts_unicode_digits_do_not_crash():
    h = parse_hsts("max-age=²")
    assert h.max_age is None and h.errors
    assert parse_hsts("max-age=" + "9" * 40).max_age is None


def test_hostile_charset_falls_back():
    r = Response("u", 200, "OK", [("Content-Type", "text/html; charset=idna")], "zażółć".encode())
    assert r.text() == "zażółć"


def test_malformed_location_is_invalid_not_crash(server):
    server.add("/", 302, [("Location", "http://[::1/x")])
    r = Fetcher(allow_private=True, resolver=RES, timeout=3).get(server.url("/"))
    assert r.error_kind == "invalid"


def test_non_ascii_path_is_percent_encoded(server):
    server.add("/%C5%BCaba", 200)
    t = parse_target(server.url("/żaba"))
    assert t.path == "/%C5%BCaba"
    assert Fetcher(allow_private=True, resolver=RES, timeout=3).get(t).response.status == 200


def test_bad_href_does_not_hide_later_insecure_form():
    p = parse_page('<a href="http://[::1">x</a><form action="http://a.example/l"></form>', "a.example")
    assert p.insecure_forms == ["http://a.example/l"] and p.incomplete is None


# ---- raport (LOW)
def test_bidi_controls_made_visible():
    assert printable("abc‮dcb") == "abc\\u202edcb"


# ---- TLS na skoku przekierowania (MED)
def test_tls_error_on_redirect_hop_reported():
    chain = [Hop("https://old.example/", 301, "https://shop.example/", "self-signed certificate"),
             Hop("https://shop.example/", 200)]
    f = analyze(site(fetched(resp(), chain=chain)), NOW)
    assert any("skoku przekierowania" in t for t in titles(f, Severity.FAIL))


# ---- oceny (MED)
def test_frame_ancestors_wildcard_not_ok():
    assert frame_ancestors_open(parse_csp("frame-ancestors *")) is True
    assert frame_ancestors_open(parse_csp("frame-ancestors 'self'")) is False
    h = [x for x in GOOD_HEADERS if x[0] != "Content-Security-Policy"] + [
        ("Content-Security-Policy", "default-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors *"),
        ("X-Frame-Options", "DENY")]
    f = analyze(site(fetched(resp(headers=h))), NOW)
    assert any("dowolne strony" in t for t in titles(f, Severity.WARN))


def test_script_src_elem_does_not_hide_eval_or_attr():
    issues = " | ".join(csp_issues(parse_csp(
        "script-src-elem 'self'; script-src 'self' 'unsafe-eval' 'unsafe-inline'; object-src 'none'; base-uri 'self'")))
    assert "'unsafe-eval'" in issues and "atrybutach zdarzeń" in issues


def test_http_probe_timeout_is_inconclusive():
    f = analyze(site(http_probe=fetched(None, "przekroczony czas", "timeout")), NOW)
    assert any("Nie rozstrzygnięto" in t for t in titles(f, Severity.INFO))
