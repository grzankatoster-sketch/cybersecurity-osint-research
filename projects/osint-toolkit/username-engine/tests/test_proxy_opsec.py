"""OPSEC: proxy SOCKS5 (Tor), zero lokalnego DNS, fail-closed, ponawianie na nowych obwodach, kanały w raporcie.
Wszystko na 127.0.0.1: atrapa SOCKS5 zapisuje, o co prosi klient, a prawdziwe żądania idą do lokalnego serwera
aiohttp (nazwy z żądań są mapowane na jego port). Zero ruchu do internetu."""
import asyncio
import contextlib
import json
import socket
import ssl
import threading
import time

import aiohttp
import pytest
from aiohttp import web

from username_engine import cli
from username_engine.engine import check_site, rescan_errors, scan
from username_engine.http import (DNS_ERROR, DNS_TEMP, PROXY_DOWN, PROXY_UNREACHABLE, TLS_NO_RETRY, Fetcher,
                                  PreflightResult, mask_ip, preflight, proxy_label)
from username_engine.models import Response, Site, Status
from username_engine.report import render_html
from username_engine.sources import save_db

LOCAL = (None, "127.0.0.1", "localhost", "::1")


# ---------------------------------------------------------------- atrapy

class SocksStub:
    """Serwer SOCKS5 (RFC 1928/1929) na 127.0.0.1. `hosts`: nazwa żądana przez klienta -> port lokalnego serwera
    (połączenie naprawdę powstaje); nieznana nazwa albo `reply` = odpowiedź błędem (4 = host unreachable)."""

    def __init__(self, hosts=None, auth="none", reply=None, fail_first=0):
        self.hosts = hosts or {}
        self.auth = auth                # none | userpass
        self.reply = reply
        self.fail_first = fail_first    # tyle pierwszych żądań kończy się „host unreachable”
        self.requests: list[dict] = []
        self.port = 0
        self._server = None

    @property
    def url(self) -> str:
        return f"socks5h://127.0.0.1:{self.port}"

    @property
    def users(self) -> list:
        return [r["user"] for r in self.requests]

    async def __aenter__(self):
        self._server = await asyncio.start_server(self._handle, "127.0.0.1", 0)
        self.port = self._server.sockets[0].getsockname()[1]
        return self

    async def __aexit__(self, *exc):
        self._server.close()
        with contextlib.suppress(Exception):
            await asyncio.wait_for(self._server.wait_closed(), 1)

    async def _handle(self, reader, writer):
        remote = None
        try:
            _, n = await reader.readexactly(2)
            methods = await reader.readexactly(n)
            user = None
            if self.auth == "userpass" and 2 in methods:
                writer.write(b"\x05\x02")
                await reader.readexactly(1)
                user = (await reader.readexactly((await reader.readexactly(1))[0])).decode()
                await reader.readexactly((await reader.readexactly(1))[0])
                writer.write(b"\x01\x00")
            elif 0 in methods:
                writer.write(b"\x05\x00")
            else:
                writer.write(b"\x05\xff")
                await writer.drain()
                return
            _, _, _, atyp = await reader.readexactly(4)
            if atyp == 1:
                host = socket.inet_ntoa(await reader.readexactly(4))
            elif atyp == 3:
                host = (await reader.readexactly((await reader.readexactly(1))[0])).decode()
            else:
                host = socket.inet_ntop(socket.AF_INET6, await reader.readexactly(16))
            port = int.from_bytes(await reader.readexactly(2), "big")
            self.requests.append({"atyp": atyp, "host": host, "port": port, "user": user})
            code = 0
            if self.reply is not None:
                code = self.reply
            elif len(self.requests) <= self.fail_first or atyp != 3 or host not in self.hosts:
                code = 4
            else:
                try:
                    remote = await asyncio.open_connection("127.0.0.1", self.hosts[host])
                except OSError:
                    code = 5
            if code:
                writer.write(bytes([5, code, 0, 1]) + b"\0" * 6)
                await writer.drain()
                return
            writer.write(b"\x05\x00\x00\x01" + b"\0" * 6)
            await writer.drain()
            await asyncio.gather(self._pipe(reader, remote[1]), self._pipe(remote[0], writer))
        except (asyncio.IncompleteReadError, ConnectionError, OSError):
            pass
        finally:
            for w in (writer, remote[1] if remote else None):
                if w is not None:
                    with contextlib.suppress(Exception):
                        w.close()

    @staticmethod
    async def _pipe(src, dst):
        try:
            while data := await src.read(65536):
                dst.write(data)
                await dst.drain()
        except (ConnectionError, OSError):
            pass
        finally:
            with contextlib.suppress(Exception):
                dst.close()


@contextlib.asynccontextmanager
async def target_server(handler=None):
    """Lokalny „serwis”: zlicza trafienia; domyślnie konta alice i a istnieją (tekst obecności), inne nie."""
    hits: list[str] = []

    async def default(request):
        hits.append(request.path)
        if request.path.rsplit("/", 1)[-1] in ("alice", "a"):
            return web.Response(text="avatar profile")
        return web.Response(status=404, text="nic")        # losowa nazwa kontrolna: brak konta

    async def counting(request):
        hits.append(request.path)
        return await handler(request)

    app = web.Application()
    app.router.add_route("*", "/{tail:.*}", counting if handler else default)
    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(runner, "127.0.0.1", 0)
    await site.start()
    try:
        yield site._server.sockets[0].getsockname()[1], hits
    finally:
        await runner.cleanup()


class BgLoop:
    """Pętla zdarzeń w wątku: atrapy działają dla synchronicznego cli.main (który sam woła asyncio.run)."""

    def __enter__(self):
        self.loop = asyncio.new_event_loop()
        self.thread = threading.Thread(target=self.loop.run_forever, daemon=True)
        self.thread.start()
        return self

    def call(self, coro):
        return asyncio.run_coroutine_threadsafe(coro, self.loop).result(10)

    def __exit__(self, *exc):
        self.loop.call_soon_threadsafe(self.loop.stop)
        self.thread.join(5)
        self.loop.close()


def free_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


@pytest.fixture
def dns_spy(monkeypatch):
    """Zapisuje każde lokalne zapytanie DNS; wszystko poza pętlą zwrotną kończy się gaierror."""
    seen: list = []
    real = socket.getaddrinfo

    def spy(host, *a, **k):
        seen.append(host)
        if host in LOCAL:
            return real(host, *a, **k)
        raise socket.gaierror(socket.EAI_NONAME, "test: lokalny DNS zabroniony")

    monkeypatch.setattr(socket, "getaddrinfo", spy)
    return seen


def foreign(seen) -> list:
    return [h for h in seen if h not in LOCAL]


SITE = Site("Gh", "http://gh.test/{username}", e_strings=["avatar"])


# ---------------------------------------------------------------- (a) zdalny DNS

def test_proxy_sends_domain_atyp_and_zero_local_dns(dns_spy):
    async def go():
        async with target_server() as (tport, hits):
            async with SocksStub({"gh.test": tport}) as socks:
                async with Fetcher(proxy=socks.url, retries=0) as f:
                    r = await f.fetch("GET", "http://gh.test/u/alice")
                return r, socks.requests, hits

    r, reqs, hits = asyncio.run(go())
    assert r.status == 200 and "avatar" in r.text and hits == ["/u/alice"]
    assert [(q["atyp"], q["host"]) for q in reqs] == [(3, "gh.test")]      # ATYP 3 = nazwa domeny, nie adres IP
    assert foreign(dns_spy) == []                                         # żadnego lokalnego DNS dla celu


def test_proxy_blocks_local_names_without_any_lookup(dns_spy):
    async def go():
        async with SocksStub() as socks:
            async with Fetcher(proxy=socks.url, retries=0) as f:
                out = [await f.fetch("GET", u) for u in (
                    "http://localhost/", "http://x.localhost/", "http://drukarka.local/", "http://a.internal/",
                    "http://abcdefgh.onion/", "http://127.0.0.1/", "http://10.0.0.1/", "http://[::1]/")]
                allowed = await f.fetch("GET", "http://gh.test/u/alice")
            return out, allowed, socks.requests

    out, allowed, reqs = asyncio.run(go())
    assert all(r.status is None and r.error.startswith("zablokowany cel") for r in out), [r.error for r in out]
    assert [q["host"] for q in reqs] == ["gh.test"]        # do proxy trafiła tylko nazwa publiczna (ERROR: nieosiągalna)
    assert allowed.error == PROXY_UNREACHABLE and foreign(dns_spy) == []


def test_proxy_allow_hosts_still_works_for_tests(dns_spy):
    async def go():
        async with target_server() as (tport, hits):
            async with SocksStub({"app.local": tport}) as socks:
                async with Fetcher(proxy=socks.url, retries=0, allow_hosts=("app.local",)) as f:
                    return await f.fetch("GET", "http://app.local/u/a")

    assert asyncio.run(go()).status == 200


# ---------------------------------------------------------------- (b) martwe proxy: fail-closed

def test_dead_proxy_is_error_not_exception_and_no_direct_connection(dns_spy, monkeypatch):
    sleeps = []
    real = asyncio.sleep

    async def fake(d):
        if d:
            sleeps.append(d)
        await real(0)

    monkeypatch.setattr("username_engine.http.asyncio.sleep", fake)
    calls = {"n": 0}
    orig = Fetcher._once

    async def counting(self, *a, **k):
        calls["n"] += 1
        return await orig(self, *a, **k)

    monkeypatch.setattr(Fetcher, "_once", counting)

    async def go():
        async with target_server() as (tport, hits):
            # cel dostępny bezpośrednio pod 127.0.0.1:<port>, ale przez martwe proxy nie wolno go dotknąć
            async with Fetcher(proxy=f"socks5h://127.0.0.1:{free_port()}", retries=3, jitter=False,
                               allow_hosts=("127.0.0.1",)) as f:
                r = await f.fetch("GET", f"http://127.0.0.1:{tport}/u/alice")
            return r, hits

    t0 = time.monotonic()
    r, hits = asyncio.run(go())
    assert r.status is None and r.error == PROXY_DOWN
    assert hits == [] and foreign(dns_spy) == []           # zero ruchu bezpośredniego
    assert calls["n"] == 1 and sleeps == [] and time.monotonic() - t0 < 3   # martwe proxy: bez ponowień


def test_proxy_timeout_and_protocol_errors_are_responses():
    async def silent(reader, writer):          # proxy, które przyjmuje połączenie i milczy
        await asyncio.sleep(3)
        writer.close()

    async def go():
        server = await asyncio.start_server(silent, "127.0.0.1", 0)
        port = server.sockets[0].getsockname()[1]
        try:
            async with Fetcher(proxy=f"socks5h://127.0.0.1:{port}", retries=0, timeout=0.5) as f:
                return await f.fetch("GET", "http://gh.test/u/a")
        finally:
            server.close()

    r = asyncio.run(go())
    assert r.status is None and r.error and "zablokowany" not in r.error      # timeout, ale bez wyjątku


# ---------------------------------------------------------------- (c) host unreachable -> ERROR

def test_host_unreachable_is_proxy_error_and_engine_error():
    async def go():
        async with SocksStub(reply=4) as socks:
            async with Fetcher(proxy=socks.url, retries=2, jitter=False) as f:
                r = await f.fetch("GET", "http://gh.test/u/alice")
                res = await check_site(SITE, "alice", f, control="none")
            return r, res, len(socks.requests)

    r, res, n = asyncio.run(go())
    assert r.status is None and r.error == "proxy: host nieosiągalny"
    assert res.status is Status.ERROR and res.reason.startswith("proxy:")      # nigdy NOT_FOUND
    assert n == 2                                                              # po jednym żądaniu, bez ponowień


@pytest.mark.parametrize("code,text", [(1, "host nieosiągalny"), (3, "host nieosiągalny"), (5, "odrzucone"),
                                       (2, "niedozwolone")])
def test_other_socks_reply_codes_are_distinguished(code, text):
    async def go():
        async with SocksStub(reply=code) as socks:
            async with Fetcher(proxy=socks.url, retries=0) as f:
                return await f.fetch("GET", "http://gh.test/")

    r = asyncio.run(go())
    assert r.status is None and r.error.startswith("proxy: ") and text in r.error


# ---------------------------------------------------------------- (d) walidacja adresu proxy

@pytest.mark.parametrize("bad", ["http://127.0.0.1:8080", "https://p:1", "socks4://127.0.0.1:9050",
                                 "127.0.0.1:9050", "socks5h://127.0.0.1", "socks5://:9050", "ftp://x:1"])
def test_non_socks5_proxy_rejected_with_polish_message(bad):
    with pytest.raises(ValueError) as e:
        Fetcher(proxy=bad)
    assert str(e.value).startswith("proxy:")


@pytest.mark.parametrize("good", ["socks5://127.0.0.1:9050", "socks5h://127.0.0.1:9050", "SOCKS5H://u:p@[::1]:1080"])
def test_socks5_proxies_accepted(good):
    assert Fetcher(proxy=good).proxy


def test_no_http_proxy_path_left_in_source():
    import pathlib
    src = pathlib.Path(cli.__file__).parent
    for f in src.glob("*.py"):
        text = f.read_text(encoding="utf-8")
        assert "proxy=self.proxy" not in text, f.name          # aiohttp HTTP proxy (wyciek DNS) nie wraca


# ---------------------------------------------------------------- (e) izolacja obwodów

def test_each_fetcher_gets_own_socks_login_and_explicit_creds_are_kept():
    async def go():
        async with target_server() as (tport, hits):
            async with SocksStub({"gh.test": tport}, auth="userpass") as socks:
                for kw in ({}, {}, {"isolation": "obwod-7"}):
                    async with Fetcher(proxy=socks.url, retries=0, **kw) as f:
                        assert (await f.fetch("GET", "http://gh.test/u/a")).status == 200
                url = f"socks5h://moj:sekret@127.0.0.1:{socks.port}"
                async with Fetcher(proxy=url, retries=0, isolation="ignorowany") as f:
                    assert (await f.fetch("GET", "http://gh.test/u/a")).status == 200
                    assert not f.isolated
                return socks.users

    u1, u2, u3, u4 = asyncio.run(go())
    assert u1 and u2 and u1 != u2                  # losowe loginy = osobne obwody Tora (IsolateSOCKSAuth)
    assert u3 == "obwod-7" and u4 == "moj"          # jawna izolacja / własne dane logowania zostają


def test_proxy_credentials_never_in_label_repr_or_errors():
    f = Fetcher(proxy="socks5h://uzytkownik:tajne@127.0.0.1:9050")
    assert proxy_label("socks5h://uzytkownik:tajne@127.0.0.1:9050") == "socks5h://127.0.0.1:9050"
    assert "tajne" not in repr(f) and "uzytkownik" not in repr(f) and f.proxy == "socks5h://127.0.0.1:9050"
    assert proxy_label("socks5://[::1]:1080") == "socks5://[::1]:1080"
    assert proxy_label(None) == "" and proxy_label("śmieci") == "proxy"
    with pytest.raises(ValueError) as e:
        Fetcher(proxy="http://uzytkownik:tajne@127.0.0.1:9050")
    assert "tajne" not in str(e.value) and "uzytkownik" not in str(e.value)


# ---------------------------------------------------------------- (f) ponowienie bez weryfikacji TLS

def _cert_error():
    from aiohttp.client_reqrep import ConnectionKey
    return aiohttp.ClientConnectorCertificateError(ConnectionKey("x.test", 443, True, True, None, None, None),
                                                   Exception("bad cert"))


def _tls_fetcher(error, **kw):
    calls = []

    async def fake_request(method, url, headers, body, ssl):
        calls.append(ssl)
        if ssl:
            raise error
        return Response(status=200, text="avatar", final_url=url)

    f = Fetcher(retries=0, **kw)
    f._session = object()
    f._request = fake_request
    return f, calls


@pytest.mark.parametrize("error", [_cert_error(), ssl.SSLCertVerificationError(1, "bad cert")])
def test_no_insecure_retry_through_proxy_but_still_without(error):
    f, calls = _tls_fetcher(error, proxy="socks5h://127.0.0.1:9050")
    r = asyncio.run(f.fetch("GET", "https://x.test/a"))
    assert r.status is None and r.error == TLS_NO_RETRY and not r.insecure and calls == [True]
    f, calls = _tls_fetcher(error)                                                     # bez proxy: jak dotąd
    r = asyncio.run(f.fetch("GET", "https://x.test/a"))
    assert r.status == 200 and r.insecure and calls == [True, False]
    f, calls = _tls_fetcher(error, proxy="socks5h://127.0.0.1:9050", allow_insecure_retry=True)   # jawnie (fallback)
    r = asyncio.run(f.fetch("GET", "https://x.test/a"))
    assert r.status == 200 and r.insecure and calls == [True, False]
    f, calls = _tls_fetcher(error, allow_insecure_retry=False)
    assert asyncio.run(f.fetch("GET", "https://x.test/a")).error == TLS_NO_RETRY
    f, calls = _tls_fetcher(error, proxy="socks5h://127.0.0.1:9050", allow_insecure_retry=True, strict_tls=True)
    assert "--strict-tls" in asyncio.run(f.fetch("GET", "https://x.test/a")).error and calls == [True]


def test_real_bad_certificate_over_socks_is_not_retried_unless_allowed(tmp_path):
    """Przez SOCKS aiohttp opakowuje błąd certyfikatu w ClientOSError: musi być rozpoznany (samopodpisany cert)."""
    import shutil
    import subprocess
    if not shutil.which("openssl"):
        pytest.skip("brak openssl do wygenerowania certyfikatu testowego")
    key, crt = tmp_path / "k.pem", tmp_path / "c.pem"
    subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", str(key), "-out", str(crt),
                    "-days", "1", "-subj", "/CN=gh.test"], check=True, capture_output=True)

    async def go():
        async def page(request):
            return web.Response(text="avatar")

        app = web.Application()
        app.router.add_get("/{t:.*}", page)
        runner = web.AppRunner(app)
        await runner.setup()
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(crt, key)
        site = web.TCPSite(runner, "127.0.0.1", 0, ssl_context=ctx)
        await site.start()
        try:
            async with SocksStub({"gh.test": site._server.sockets[0].getsockname()[1]}) as socks:
                out = []
                for kw in ({}, {"allow_insecure_retry": True}):
                    async with Fetcher(proxy=socks.url, retries=0, **kw) as f:
                        out.append(await f.fetch("GET", "https://gh.test/x"))
                return out
        finally:
            await runner.cleanup()

    strict, relaxed = asyncio.run(go())
    assert strict.status is None and strict.error == TLS_NO_RETRY and not strict.insecure
    assert relaxed.status == 200 and relaxed.insecure                    # proxy zapasowe: jak dotąd, z oznaczeniem


# ---------------------------------------------------------------- (g) rundy ponowień na nowych obwodach

def test_error_recovered_on_new_circuit_gets_proxy_retry_channel():
    async def go():
        async with target_server() as (tport, hits):
            async with SocksStub({"gh.test": tport}, auth="userpass", fail_first=2) as socks:
                def fresh():
                    return Fetcher(proxy=socks.url, retries=0, timeout=5)

                async with Fetcher(proxy=socks.url, retries=0) as f:
                    first = await scan("alice", [SITE], f, control="none", channel="proxy")
                seen = []
                out = await rescan_errors("alice", [SITE], first, fresh, retries=2, control="none",
                                          on_round=lambda k, n: seen.append((k, n)))
                return first, out, seen, socks.users

    first, out, seen, users = asyncio.run(go())
    assert first[0].status is Status.ERROR and first[0].channel == "proxy"
    assert out[0].status is Status.FOUND and out[0].channel == "proxy-retry"
    assert seen == [("proxy-retry", 1), ("proxy-retry", 1)]         # pierwsza runda nie pomogła, druga tak
    assert len(set(users)) == 3                                      # każda próba na innym obwodzie


def test_retry_rounds_stop_early_skip_unsupported_and_respect_limit():
    unsupported = Site("Reg", "http://reg.test/{username}", regex="^[0-9]+$", e_strings=["avatar"])
    made = []

    async def go(fail_first, retries):
        async with target_server() as (tport, hits):
            async with SocksStub({"gh.test": tport}, fail_first=fail_first) as socks:
                def fresh():
                    made.append(1)
                    return Fetcher(proxy=socks.url, retries=0, timeout=5)

                async with Fetcher(proxy=socks.url, retries=0) as f:
                    first = await scan("alice", [SITE, unsupported], f, control="none", channel="proxy")
                return await rescan_errors("alice", [SITE, unsupported], first, fresh, retries=retries, control="none")

    out = asyncio.run(go(1, 2))
    assert made == [1]                                                  # naprawione w 1. rundzie: bez 2.
    assert out[0].channel == "proxy-retry" and out[1].status is Status.UNSUPPORTED and out[1].channel == "proxy"
    made.clear()
    out = asyncio.run(go(99, 2))
    assert made == [1, 1] and out[0].status is Status.ERROR and out[0].channel == "proxy"      # limit rund
    made.clear()
    asyncio.run(go(99, 0))
    assert made == []                                                   # retries=0: bez dodatkowych rund


def test_dead_proxy_errors_are_not_hammered_by_retry_rounds():
    made = []
    res = [__import__("username_engine.models", fromlist=["Result"]).Result("Gh", "u", Status.ERROR, reason=PROXY_DOWN)]

    async def go():
        return await rescan_errors("alice", [SITE], res, lambda: made.append(1), retries=2, control="none")

    assert asyncio.run(go())[0].status is Status.ERROR and made == []


# ---------------------------------------------------------------- (h) proxy zapasowe

def test_fallback_only_for_remaining_errors_and_never_direct(dns_spy):
    bad = Site("Bad", "http://bad.test/{username}", e_strings=["avatar"])

    async def go():
        async with target_server() as (tport, hits):
            async with SocksStub({"gh.test": tport}) as primary, \
                    SocksStub({"gh.test": tport, "bad.test": tport}) as backup:
                async with Fetcher(proxy=primary.url, retries=0) as f:
                    first = await scan("alice", [SITE, bad], f, control="none", channel="proxy")
                out = await rescan_errors(
                    "alice", [SITE, bad], first, lambda: Fetcher(proxy=primary.url, retries=0), lambda: Fetcher(
                        proxy=backup.url, retries=0, allow_insecure_retry=True), retries=1, control="none")
                return out, primary, backup, hits

    out, primary, backup, hits = asyncio.run(go())
    assert (out[0].status, out[0].channel) == (Status.FOUND, "proxy")
    assert (out[1].status, out[1].channel) == (Status.FOUND, "fallback")
    assert {q["host"] for q in backup.requests} == {"bad.test"}        # zapasowe tylko dla pozostałych błędów
    assert foreign(dns_spy) == []


def test_all_channels_failing_leaves_error_and_zero_direct_hits(dns_spy):
    async def go():
        async with target_server() as (tport, hits):
            async with SocksStub(reply=4) as a, SocksStub(reply=4) as b:
                async with Fetcher(proxy=a.url, retries=0) as f:
                    first = await scan("alice", [SITE], f, control="none", channel="proxy")
                out = await rescan_errors("alice", [SITE], first, lambda: Fetcher(proxy=a.url, retries=0),
                                          lambda: Fetcher(proxy=b.url, retries=0), retries=2, control="none")
                return out, hits

    out, hits = asyncio.run(go())
    assert out[0].status is Status.ERROR and hits == []


# ---------------------------------------------------------------- (j) bez proxy: gaierror to Response

def test_gaierror_without_proxy_is_response_not_exception(dns_spy):
    async def go():
        async with Fetcher(retries=0) as f:
            return await f.fetch("GET", "http://nie-istnieje.test/")

    r = asyncio.run(go())
    assert r.status is None and r.error == DNS_ERROR
    assert "nie-istnieje.test" in dns_spy                              # bez proxy lokalny DNS działa jak dotąd


@pytest.mark.parametrize("exc,expect", [(socket.gaierror(socket.EAI_NONAME, "x"), DNS_ERROR),
                                        (socket.gaierror(socket.EAI_AGAIN, "x"), DNS_TEMP),
                                        (OSError(5, "x"), "połączenie: OSError")])
def test_raw_resolver_errors_become_responses(exc, expect):
    f = Fetcher(retries=0)
    f._session = object()

    async def raiser(*a, **k):
        raise exc

    f._request = raiser
    r = asyncio.run(f._once("GET", "http://x.test/", {}, None))
    assert r.status is None and r.error.startswith(expect)


# ---------------------------------------------------------------- (k) preflight, maskowanie

def test_mask_ip():
    assert mask_ip("185.220.101.7") == "185.220.x.x"
    assert mask_ip("2a0b:f4c2:2::1") == "2a0b:f4c2:..."
    assert mask_ip("nie-ip") is None and mask_ip(None) is None


def _json_handler(payload, status=200, raw=None):
    async def handler(request):
        return web.Response(status=status, text=raw if raw is not None else json.dumps(payload),
                            content_type="application/json")
    return handler


@pytest.mark.parametrize("payload,raw,status,ok,is_tor,err", [
    ({"IsTor": True, "IP": "185.220.101.7"}, None, 200, True, True, None),
    ({"IsTor": False, "IP": "203.0.113.9"}, None, 200, True, False, None),
    ({"IP": "203.0.113.9"}, None, 200, False, None, "IsTor"),
    (None, "to nie json", 200, False, None, "JSON"),
    ({"IsTor": True, "IP": "185.220.101.7"}, None, 503, False, None, "503")])
def test_preflight_results(dns_spy, payload, raw, status, ok, is_tor, err):
    async def go():
        async with target_server(_json_handler(payload, status, raw)) as (tport, hits):
            async with SocksStub({"check.test": tport}) as socks:
                return await preflight(socks.url, timeout=5, url="http://check.test/api/ip")

    r = asyncio.run(go())
    assert r.ok is ok and r.is_tor is is_tor
    assert (r.exit_ip_masked is not None) is ok and (err is None or err in r.error)
    if ok:
        assert r.exit_ip_masked.endswith(".x.x") and r.exit_ip_masked.count(".") == 3
    assert foreign(dns_spy) == []


def test_preflight_fails_closed_for_unreachable_check_and_bad_url():
    async def go():
        async with SocksStub(reply=4) as socks:
            return await preflight(socks.url, timeout=3, url="http://check.test/api/ip")

    r = asyncio.run(go())
    assert r.ok is False and r.error == PROXY_UNREACHABLE and r.is_tor is None and r.exit_ip_masked is None
    r = asyncio.run(preflight("http://127.0.0.1:8080"))
    assert r.ok is False and r.error.startswith("proxy:")


# ---------------------------------------------------------------- (i) CLI

def _db(tmp_path, url="http://gh.test/{username}"):
    db = tmp_path / "sites.json"
    save_db([Site("Gh", url, e_strings=["avatar"], tags=["social"])], db)
    return db


def _cli(tmp_path, *extra, db=None):
    return cli.main(["alice", "--db", str(db or _db(tmp_path)), "--no-variants", "--include-broken",
                     "--results-dir", str(tmp_path / "wyniki"), *extra])


def test_cli_dead_proxy_exits_3_before_any_target_request(tmp_path, capsys, dns_spy, monkeypatch):
    monkeypatch.delenv("OSINT_PROXY", raising=False)
    with BgLoop() as bg:
        async def start():
            cm = target_server()
            tport, hits = await cm.__aenter__()
            return cm, tport, hits

        cm, tport, hits = bg.call(start())
        try:
            db = _db(tmp_path, f"http://127.0.0.1:{tport}/{{username}}")
            code = _cli(tmp_path, "--proxy", f"socks5h://127.0.0.1:{free_port()}", db=db)
        finally:
            bg.call(cm.__aexit__(None, None, None))
    out = capsys.readouterr()
    assert code == 3 and hits == [] and foreign(dns_spy) == []
    assert "Proxy niedostępne" in out.err and "zero ruchu bezpośredniego" in out.err


def test_cli_proxy_from_env_and_fallback_preflight_fail_closed(tmp_path, capsys, monkeypatch):
    asked = []

    async def fake_preflight(url, *a, **k):
        asked.append(url)
        return PreflightResult(True, True, "185.220.x.x") if url.endswith(":1") else PreflightResult(False, error="x")

    class NoFetcher:
        def __init__(self, *a, **k): raise AssertionError("żądania do celów mimo nieudanej kontroli kanału")

    monkeypatch.setattr(cli, "preflight", fake_preflight)
    monkeypatch.setattr(cli, "Fetcher", NoFetcher)
    monkeypatch.setenv("OSINT_PROXY", "socks5h://127.0.0.1:2")
    assert _cli(tmp_path) == 3 and asked == ["socks5h://127.0.0.1:2"]
    assert "Proxy niedostępne (x)" in capsys.readouterr().err
    monkeypatch.setenv("OSINT_PROXY", "socks5h://127.0.0.1:1")
    monkeypatch.setenv("OSINT_PROXY_FALLBACK", "socks5h://127.0.0.1:2")           # główne ok, zapasowe martwe
    assert _cli(tmp_path) == 3
    assert "Proxy zapasowe niedostępne" in capsys.readouterr().err


@pytest.mark.parametrize("extra", [("--proxy", "http://x:1"), ("--proxy", "socks4://x:1"),
                                   ("--direct", "--proxy", "socks5h://127.0.0.1:9050"),
                                   ("--proxy-fallback", "socks5h://127.0.0.1:9050"),
                                   ("--proxy", "socks5h://127.0.0.1:9050", "--proxy-fallback", "http://x:1")])
def test_cli_bad_network_options_exit_2(tmp_path, capsys, monkeypatch, extra):
    monkeypatch.delenv("OSINT_PROXY", raising=False)
    monkeypatch.delenv("OSINT_PROXY_FALLBACK", raising=False)
    assert _cli(tmp_path, *extra) == 2
    assert "Błąd opcji" in capsys.readouterr().err


def test_cli_bad_env_proxy_exit_2(tmp_path, capsys, monkeypatch):
    monkeypatch.setenv("OSINT_PROXY", "http://127.0.0.1:8080")
    assert _cli(tmp_path) == 2
    assert "OSINT_PROXY" in capsys.readouterr().err


def test_cli_direct_ignores_env_proxy(tmp_path, capsys, monkeypatch):
    monkeypatch.setenv("OSINT_PROXY", "socks5h://127.0.0.1:9")
    monkeypatch.setenv("OSINT_PROXY_FALLBACK", "socks5h://127.0.0.1:9")
    seen = []

    class F:
        def __init__(self, *a, **k): seen.append(k)
        async def __aenter__(self): return self
        async def __aexit__(self, *e): pass
        async def fetch(self, method, url, headers=None, body=None):
            return Response(200, "avatar", final_url=url)

    async def boom(*a, **k):
        raise AssertionError("preflight w trybie --direct")

    monkeypatch.setattr(cli, "Fetcher", F)
    monkeypatch.setattr(cli, "preflight", boom)
    assert _cli(tmp_path, "--direct", "--json", "w.json") == 0
    assert seen and all("proxy" not in k for k in seen)
    out = capsys.readouterr().out
    assert "Kanał: bezpośrednio (twoje IP widoczne dla serwisów)" in out
    (scan_dir,) = [d for d in (tmp_path / "wyniki").iterdir() if d.is_dir()]
    data = json.loads((scan_dir / "w.json").read_text(encoding="utf-8"))
    assert data["channel"]["mode"] == "direct" and data["results"]["alice"][0]["channel"] == "direct"


def test_cli_full_run_through_proxy_retry_channels_and_no_credentials(tmp_path, capsys, monkeypatch):
    monkeypatch.delenv("OSINT_PROXY", raising=False)
    monkeypatch.delenv("OSINT_PROXY_FALLBACK", raising=False)

    async def fake_preflight(url, *a, **k):
        return PreflightResult(True, True, "185.220.x.x")

    monkeypatch.setattr(cli, "preflight", fake_preflight)
    with BgLoop() as bg:
        async def start():
            cm = target_server()
            tport, hits = await cm.__aenter__()
            socks = await SocksStub({"gh.test": tport}, auth="userpass", fail_first=1).__aenter__()
            return cm, socks, hits

        cm, socks, hits = bg.call(start())
        try:
            url = f"socks5h://operator:tajnehaslo@127.0.0.1:{socks.port}"
            code = _cli(tmp_path, "--proxy", url, "--report", "r.html", "--json", "w.json", "--csv", "w.csv", "--all")
        finally:
            bg.call(socks.__aexit__())
            bg.call(cm.__aexit__(None, None, None))
    cap = capsys.readouterr()
    assert code == 0 and hits[0] == "/alice"          # dalej tylko kontrola z losową nazwą
    assert "Kanał: Tor (wyjście 185.220.x.x)" in cap.out and "ponawiam 1 błędów na nowym obwodzie" in cap.out
    (scan_dir,) = [d for d in (tmp_path / "wyniki").iterdir() if d.is_dir()]
    data = json.loads((scan_dir / "w.json").read_text(encoding="utf-8"))
    assert data["channel"] == {"mode": "tor", "proxy_label": f"socks5h://127.0.0.1:{socks.port}", "is_tor": True,
                               "exit_ip_masked": "185.220.x.x", "counts": {"proxy-retry": 1}}
    assert data["results"]["alice"][0]["channel"] == "proxy-retry" and data["results"]["alice"][0]["status"] == "FOUND"
    html = (scan_dir / "r.html").read_text(encoding="utf-8")
    assert "Kanał: Tor (wyjście 185.220.x.x)" in html and "proxy-retry" in html
    assert "proxy-retry" in (scan_dir / "w.csv").read_text(encoding="utf-8-sig")
    everything = cap.out + cap.err + html + json.dumps(data) + (scan_dir / "w.csv").read_text(encoding="utf-8-sig")
    assert "tajnehaslo" not in everything and "operator" not in everything


def test_report_channel_line_is_escaped_and_optional():
    html = render_html("a", {"a": []}, {"a": {"checked": 0, "error": 0, "unsupported": 0}}, [],
                       channel_info={"mode": "proxy", "proxy_label": "socks5h://<x>:1", "counts": {"proxy": 2}})
    assert "socks5h://&lt;x&gt;:1" in html and "proxy: 2" in html and "<x>" not in html
    assert "Kanał:" not in render_html("a", {"a": []}, {"a": {"checked": 0, "error": 0, "unsupported": 0}}, [])
