"""Klient HTTP na prawdziwym lokalnym serwerze: przekierowania, petle, limity, budzet, straznik SSRF."""

import ipaddress
import socket
import time

import pytest

import site_audit.target as target_mod
from site_audit.fetch import Fetcher
from conftest import fake_resolver

LOCAL = {"site.test": "127.0.0.1", "www.site.test": "127.0.0.1"}


def fetcher(**kw):
    kw.setdefault("allow_private", True)
    kw.setdefault("resolver", fake_resolver(LOCAL))
    kw.setdefault("timeout", 3)
    return Fetcher(**kw)


def test_follows_redirect_chain(server):
    server.add("/", 301, [("Location", "/a")]).add("/a", 302, [("Location", server.url("/b", "www.site.test"))])
    server.add("/b", 200, [("Content-Type", "text/html")], "<title>ok</title>")
    r = fetcher().get(server.url("/"))
    assert r.ok and r.response.status == 200 and r.response.body == b"<title>ok</title>"
    assert [h.status for h in r.chain] == [301, 302, 200]
    assert r.response.url == server.url("/b", "www.site.test")


def test_no_follow_returns_redirect(server):
    server.add("/", 301, [("Location", "https://site.test/")])
    r = fetcher().get(server.url("/"), follow=False)
    assert r.response.status == 301 and r.response.header("location") == "https://site.test/"


def test_redirect_loop_detected(server):
    server.add("/a", 302, [("Location", "/b")]).add("/b", 302, [("Location", "/a")])
    r = fetcher().get(server.url("/a"))
    assert r.error_kind == "redirects" and "pętla" in r.error


def test_too_many_redirects(server):
    for i in range(5):
        server.add(f"/{i}", 302, [("Location", f"/{i + 1}")])
    r = fetcher().get(server.url("/0"), max_redirects=3)
    assert r.error_kind == "redirects"


def test_redirect_to_disallowed_scheme(server):
    server.add("/", 302, [("Location", "file:///etc/passwd")])
    r = fetcher().get(server.url("/"))
    assert r.error_kind == "invalid" and r.response is None


def test_max_bytes_truncates(server):
    server.add("/", 200, [("Content-Type", "text/plain")], b"a" * 5000)
    r = fetcher(max_bytes=1000).get(server.url("/"))
    assert r.response.truncated and len(r.response.body) == 1000


def test_repeated_headers_kept(server):
    server.add("/", 200, [("Set-Cookie", "a=1"), ("Set-Cookie", "b=2")])
    assert fetcher().get(server.url("/")).response.header_all("set-cookie") == ["a=1", "b=2"]


def test_private_target_blocked_by_default(server):
    server.add("/", 200)
    r = Fetcher(resolver=fake_resolver(LOCAL), timeout=3).get(server.url("/"))
    assert r.error_kind == "blocked" and server.hits == []


def test_redirect_to_private_address_blocked_before_connect(server, monkeypatch):
    """Pierwszy host 'publiczny' (127.0.0.1 udaje publiczny), przekierowanie na intranet -> blokada."""
    real = target_mod.is_public
    monkeypatch.setattr(target_mod, "is_public", lambda ip: ip == "127.0.0.1" or real(ip))
    server.add("/", 302, [("Location", "http://intranet.test/admin")])
    connects = []
    orig = socket.create_connection
    monkeypatch.setattr(socket, "create_connection", lambda addr, *a, **k: connects.append(addr) or orig(addr, *a, **k))
    r = Fetcher(resolver=fake_resolver({**LOCAL, "intranet.test": "10.0.0.7"}), timeout=3).get(server.url("/"))
    assert r.error_kind == "blocked" and "10.0.0.7" in r.error
    assert all(a[0] != "10.0.0.7" for a in connects)


def test_connects_to_checked_ip_not_second_resolution(server, monkeypatch):
    """Polaczenie idzie na adres sprawdzony przez straznika (ochrona przed DNS rebinding)."""
    server.add("/", 200)
    calls = []

    def rebinding(host, port):
        calls.append(host)
        return ["127.0.0.1"] if len(calls) == 1 else ["10.9.9.9"]
    real_gai = socket.getaddrinfo

    def only_literals(host, *a, **k):
        try:
            ipaddress.ip_address(host)
        except ValueError:
            pytest.fail(f"druga rezolucja nazwy {host}")
        return real_gai(host, *a, **k)
    monkeypatch.setattr(socket, "getaddrinfo", only_literals)
    r = Fetcher(resolver=rebinding, allow_private=True, timeout=3).get(server.url("/"))
    assert r.ok and calls == ["site.test"]


def test_budget_exhausted_stops_requests(server):
    server.add("/", 200)
    t = [0.0]
    f = fetcher(budget=10, clock=lambda: t[0])
    assert f.get(server.url("/")).ok
    t[0] = 11
    r = f.get(server.url("/"))
    assert r.error_kind == "budget" and f.requests == 1


def test_slow_body_bounded_by_budget(server):
    server.add("/slow", 200, delay_chunks=(50, 0.1))
    f = fetcher(budget=0.6, timeout=5)
    start = time.monotonic()
    r = f.get(server.url("/slow"))
    elapsed = time.monotonic() - start
    # budzet konczy sie w trakcie czytania: blad budzetu, nie zawieszenie na 5 s
    assert elapsed < 2, elapsed
    assert r.error_kind == "budget"


def test_connection_refused_is_network_error():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    r = fetcher().get(f"http://site.test:{port}/")
    assert r.error_kind == "network" and r.response is None
