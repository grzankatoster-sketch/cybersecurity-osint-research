"""Tryb OPSEC: DohResolver (DoH przez SOCKS5). Wszystko lokalnie: stub SOCKS5 + stub DoH po TLS na 127.0.0.1.

Certyfikat samopodpisany tworzy `openssl` (jesli go brak, testy TLS sa pomijane)."""

from __future__ import annotations

import functools
import json
import shutil
import socket
import socketserver
import ssl
import struct
import subprocess
import threading
import time

import dns.flags
import dns.message
import dns.rcode
import dns.rrset
import pytest

from conftest import good_domain
from dns_audit import cli
from dns_audit.collector import collect
from dns_audit.report import build_report, render_html, render_json, render_text
from dns_audit.resolver import DnsAnswer, DohResolver, Status, preflight

DOH_HOST = "doh.test"  # nazwa nigdzie nie istnieje: gdyby ktos ja rozwiazywal lokalnie, test sie wywroci
DOH_URL = f"https://{DOH_HOST}/dns-query"


# --- stuby ------------------------------------------------------------------------------------------------------

def _recv_exact(sock, n):
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("eof")
        buf += chunk
    return buf


class _Server(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


class _SocksHandler(socketserver.BaseRequestHandler):
    def handle(self):
        s = self.request
        env = self.server.env
        try:
            ver, n = _recv_exact(s, 2)
            methods = _recv_exact(s, n)
            method = 2 if 2 in methods else 0
            s.sendall(bytes([5, method]))
            user = pw = None
            if method == 2:
                _recv_exact(s, 1)
                user = _recv_exact(s, _recv_exact(s, 1)[0]).decode()
                pw = _recv_exact(s, _recv_exact(s, 1)[0]).decode()
                s.sendall(b"\x01\x01" if env.reject_auth else b"\x01\x00")
                if env.reject_auth:
                    return
            _ver, cmd, _rsv, atyp = _recv_exact(s, 4)
            if atyp == 3:
                host = _recv_exact(s, _recv_exact(s, 1)[0]).decode()
            elif atyp == 1:
                host = socket.inet_ntoa(_recv_exact(s, 4))
            else:
                host = _recv_exact(s, 16).hex()
            port = struct.unpack(">H", _recv_exact(s, 2))[0]
            env.socks_log.append({"atyp": atyp, "host": host, "port": port, "user": user, "pw": pw, "cmd": cmd})
            up = socket.create_connection(("127.0.0.1", env.doh_port))  # niezaleznie od zadanego hosta
            s.sendall(b"\x05\x00\x00\x01\x00\x00\x00\x00\x00\x00")
            t = threading.Thread(target=self._pipe, args=(up, s), daemon=True)
            t.start()
            self._pipe(s, up)
            t.join(2)
        except (ConnectionError, OSError):
            pass

    @staticmethod
    def _pipe(src, dst):
        try:
            while data := src.recv(65536):
                dst.sendall(data)
        except OSError:
            pass
        try:
            dst.shutdown(socket.SHUT_WR)
        except OSError:
            pass


class _DohHandler(socketserver.BaseRequestHandler):
    def handle(self):
        env = self.server.env
        try:
            conn = env.server_ctx.wrap_socket(self.request, server_side=True)
        except (ssl.SSLError, OSError):
            return
        f = conn.makefile("rb")
        try:
            while True:
                line = f.readline()
                if not line:
                    return
                headers = {}
                while (h := f.readline()) not in (b"\r\n", b""):
                    k, _, v = h.decode().partition(":")
                    headers[k.strip().lower()] = v.strip()
                body = f.read(int(headers.get("content-length", "0")))
                env.doh_requests.append({"ct": headers.get("content-type"), "accept": headers.get("accept"), "len": len(body)})
                q = dns.message.from_wire(body)
                out = env.handler(q)
                if isinstance(out, int):
                    conn.sendall(f"HTTP/1.1 {out} X\r\nContent-Length: 0\r\n\r\n".encode())
                    continue
                wire = out.to_wire()
                conn.sendall(
                    b"HTTP/1.1 200 OK\r\nContent-Type: application/dns-message\r\nContent-Length: "
                    + str(len(wire)).encode() + b"\r\n\r\n" + wire
                )
        except (ConnectionError, OSError, ssl.SSLError):
            pass
        finally:
            try:
                conn.close()
            except OSError:
                pass


def _answer(q, rtype=None, text=None, ad=False, rcode=dns.rcode.NOERROR, owner=None):
    r = dns.message.make_response(q)
    r.set_rcode(rcode)
    if ad:
        r.flags |= dns.flags.AD
    if text is not None:
        r.answer.append(dns.rrset.from_text(owner or q.question[0].name, 300, "IN", rtype, *text))
    return r


class Env:
    def __init__(self):
        self.socks_log: list[dict] = []
        self.doh_requests: list[dict] = []
        self.reject_auth = False
        self.handler = lambda q: _answer(q, rcode=dns.rcode.NXDOMAIN)

    def proxy(self, creds=""):
        return f"socks5h://{creds}127.0.0.1:{self.socks_port}"

    def resolver(self, proxy=None, **kw):
        return DohResolver(DOH_URL, proxy or self.proxy(), ssl_context=self.client_ctx, **kw)


@pytest.fixture(scope="session")
def certs(tmp_path_factory):
    exe = shutil.which("openssl")
    if not exe:
        pytest.skip("brak openssl: testy TLS pominiete")
    d = tmp_path_factory.mktemp("cert")
    crt, key = d / "c.pem", d / "k.pem"
    proc = subprocess.run(
        [exe, "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", str(key), "-out", str(crt),
         "-days", "2", "-subj", f"/CN={DOH_HOST}", "-addext", f"subjectAltName=DNS:{DOH_HOST}"],
        capture_output=True, text=True,
    )
    if proc.returncode != 0:
        pytest.skip("openssl nie wygenerowal certyfikatu: " + proc.stderr[:200])
    return crt, key


@pytest.fixture
def env(certs, monkeypatch):
    crt, key = certs
    e = Env()
    e.server_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    e.server_ctx.load_cert_chain(str(crt), str(key))
    e.client_ctx = ssl.create_default_context(cafile=str(crt))
    doh = _Server(("127.0.0.1", 0), _DohHandler)
    socks = _Server(("127.0.0.1", 0), _SocksHandler)
    doh.env = socks.env = e
    e.doh_port, e.socks_port = doh.server_address[1], socks.server_address[1]
    for srv in (doh, socks):
        threading.Thread(target=functools.partial(srv.serve_forever, 0.02), daemon=True).start()

    # Zadne lokalne rozwiazywanie nazw poza 127.0.0.1 (adres proxy): inaczej wyciek DNS
    resolved: list[str] = []
    real = socket.getaddrinfo

    def guarded(host, *a, **k):
        resolved.append(str(host))
        if str(host) != "127.0.0.1":
            raise AssertionError(f"lokalne rozwiazywanie nazwy: {host!r}")
        return real(host, *a, **k)

    monkeypatch.setattr(socket, "getaddrinfo", guarded)
    e.resolved = resolved
    yield e
    for srv in (doh, socks):
        srv.shutdown()
        srv.server_close()


def _closed_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


# --- DohResolver: walidacja argumentow (bez sieci) ---------------------------------------------------------------

@pytest.mark.parametrize("proxy", ["http://127.0.0.1:9150", "https://127.0.0.1:1", "127.0.0.1:9150",
                                   "socks4://127.0.0.1:9150", "socks5h://", "socks5h://127.0.0.1:99999",
                                   "socks5h://127.0.0.1:9150/x"])
def test_zly_proxy_value_error(proxy):
    with pytest.raises(ValueError):
        DohResolver(DOH_URL, proxy)


@pytest.mark.parametrize("url", ["http://dns.quad9.net/dns-query", "dns.quad9.net", "https://", "https://u:p@dns.quad9.net/x"])
def test_zly_doh_value_error(url):
    with pytest.raises(ValueError):
        DohResolver(url, "socks5h://127.0.0.1:9150")


def test_opis_bez_danych_logowania():
    r = DohResolver("https://dns.quad9.net/dns-query", "socks5h://alice:s3cret@127.0.0.1:9150")
    assert r.description == "DoH https://dns.quad9.net/dns-query przez socks5h://127.0.0.1:9150"
    assert "alice" not in r.description and "s3cret" not in r.description


def test_izolacja_login_losowy_na_instancje_a_jawny_zachowany():
    a = DohResolver(DOH_URL, "socks5h://127.0.0.1:9150")
    b = DohResolver(DOH_URL, "socks5h://127.0.0.1:9150")
    assert a._proxy[2] != b._proxy[2] and len(a._proxy[2]) == 16 and a._proxy[3] == "x"
    c = DohResolver(DOH_URL, "socks5h://al%40ice:p%3Aw@127.0.0.1:9150")
    assert c._proxy[2:] == ("al@ice", "p:w")


# --- DohResolver: przez stuby ------------------------------------------------------------------------------------

def test_socks_atyp3_domena_i_zero_lokalnego_rozwiazywania(env):
    env.handler = lambda q: _answer(q, "A", ["192.0.2.1"])
    r = env.resolver()
    assert r.query("example.org", "A") == DnsAnswer(Status.OK, ("192.0.2.1",), False)
    assert len(env.socks_log) == 1
    e = env.socks_log[0]
    assert (e["atyp"], e["host"], e["port"], e["cmd"]) == (3, DOH_HOST, 443, 1)
    assert DOH_HOST not in env.resolved and set(env.resolved) <= {"127.0.0.1"}
    req = env.doh_requests[0]
    assert req["ct"] == "application/dns-message" and req["accept"] == "application/dns-message"


def test_zapytanie_rfc8484_id0_rd_ad_do(env):
    seen = []

    def h(q):
        seen.append(q)
        return _answer(q, "A", ["192.0.2.1"])

    env.handler = h
    env.resolver().query("example.org", "A")
    q = seen[0]
    assert q.id == 0 and q.flags & dns.flags.RD and q.flags & dns.flags.AD
    assert q.edns == 0 and q.ednsflags & dns.flags.DO and q.payload == 1232


def test_mapowanie_nxdomain_nodata_servfail_ok_ad(env):
    def h(q):
        n = str(q.question[0].name)
        if n.startswith("nx."):
            return _answer(q, rcode=dns.rcode.NXDOMAIN)
        if n.startswith("nodata."):
            return _answer(q)
        if n.startswith("sf."):
            return _answer(q, rcode=dns.rcode.SERVFAIL)
        if n.startswith("ref."):
            return _answer(q, rcode=dns.rcode.REFUSED)
        if n.startswith("cname."):  # lancuch CNAME: A pod inna nazwa wlasciciela
            r = _answer(q, "CNAME", ["real.example.org."])
            r.answer.append(dns.rrset.from_text("real.example.org.", 300, "IN", "A", "192.0.2.7"))
            return r
        return _answer(q, "A", ["192.0.2.1", "192.0.2.2"], ad=True)

    env.handler = h
    r = env.resolver()
    assert r.query("nx.example.org", "A").status is Status.NXDOMAIN
    assert r.query("nodata.example.org", "A").status is Status.NODATA
    sf = r.query("sf.example.org", "A")
    assert sf.status is Status.SERVFAIL and sf.failed
    assert r.query("ref.example.org", "A").status is Status.ERROR
    ok = r.query("ok.example.org", "A")
    assert ok.status is Status.OK and ok.ad and sorted(ok.records) == ["192.0.2.1", "192.0.2.2"]
    assert r.query("cname.example.org", "A").records == ("192.0.2.7",)
    # sam CNAME bez rekordu zadanego typu = NODATA
    env.handler = lambda q: _answer(q, "CNAME", ["real.example.org."])
    assert r.query("c.example.org", "A").status is Status.NODATA


def test_txt_segmenty_sklejone_i_rekordy_mx(env):
    env.handler = lambda q: (
        _answer(q, "TXT", ['"v=spf1 " "include:_spf.x.example -all"', '"inny"']) if q.question[0].rdtype == 16
        else _answer(q, "MX", ["10 mx1.example.org."])
    )
    r = env.resolver()
    assert sorted(r.query("example.org", "TXT").records) == ["inny", "v=spf1 include:_spf.x.example -all"]
    assert r.query("example.org", "MX").records == ("10 mx1.example.org.",)


def test_keepalive_jedno_polaczenie_socks_dla_wielu_zapytan(env):
    env.handler = lambda q: _answer(q, "A", ["192.0.2.1"])
    r = env.resolver()
    for i in range(6):
        assert r.query(f"h{i}.example.org", "A").ok
    assert len(env.socks_log) == 1 and len(env.doh_requests) == 6


def test_watki_wspoldzielony_login_i_poprawne_odpowiedzi(env):
    env.handler = lambda q: _answer(q, "A", ["192.0.2.1"])
    r = env.resolver()
    out = []
    ts = [threading.Thread(target=lambda i=i: out.append(r.query(f"h{i}.example.org", "A"))) for i in range(8)]
    [t.start() for t in ts]
    [t.join() for t in ts]
    assert len(out) == 8 and all(a.ok for a in out)
    assert 1 <= len(env.socks_log) <= 8
    assert len({e["user"] for e in env.socks_log}) == 1  # jedna tozsamosc (izolacja) na instancje


def test_login_losowy_na_instancje_widziany_przez_proxy(env):
    env.handler = lambda q: _answer(q, "A", ["192.0.2.1"])
    a, b = env.resolver(), env.resolver()
    a.query("x.example.org", "A")
    b.query("x.example.org", "A")
    ua, ub = (e["user"] for e in env.socks_log)
    assert ua != ub and len(ua) == len(ub) == 16 and all(e["pw"] == "x" for e in env.socks_log)


def test_jawne_dane_logowania_zachowane(env):
    env.handler = lambda q: _answer(q, "A", ["192.0.2.1"])
    r = env.resolver(env.proxy("alice:s3cret@"))
    assert r.query("x.example.org", "A").ok
    assert (env.socks_log[0]["user"], env.socks_log[0]["pw"]) == ("alice", "s3cret")
    assert "alice" not in r.description and "s3cret" not in r.description


def test_odrzucone_uwierzytelnienie_to_error_bez_hasla(env):
    env.reject_auth = True
    r = env.resolver(env.proxy("alice:s3cret@"))
    a = r.query("x.example.org", "A")
    assert a.status is Status.ERROR and "s3cret" not in a.error and "alice" not in a.error


def test_http_nie_200_to_error(env):
    env.handler = lambda q: 503
    a = env.resolver().query("x.example.org", "A")
    assert a.status is Status.ERROR and "503" in a.error


def test_timeout_to_timeout(env):
    def slow(q):
        time.sleep(1.5)
        return _answer(q, "A", ["192.0.2.1"])

    env.handler = slow
    assert env.resolver(timeout=0.3).query("x.example.org", "A").status is Status.TIMEOUT


def test_zly_certyfikat_to_error(env):
    r = DohResolver(DOH_URL, env.proxy(), timeout=3)  # domyslny kontekst: certyfikat stubu nie jest zaufany
    a = r.query("x.example.org", "A")
    assert a.status is Status.ERROR and a.failed


def test_martwy_proxy_to_error_i_preflight(env):
    r = DohResolver(DOH_URL, f"socks5h://127.0.0.1:{_closed_port()}", ssl_context=env.client_ctx)
    a = r.query("x.example.org", "A")
    assert a.status is Status.ERROR
    assert preflight(r)


def test_nieprawidlowy_typ_rekordu_nie_rzuca(env):
    assert env.resolver().query("x.example.org", "NIEMA").status is Status.ERROR


def test_preflight_ok(env):
    env.handler = lambda q: _answer(q, "A", ["93.184.216.34"])
    assert preflight(env.resolver()) is None


def test_poswiadczenia_nieobecne_w_raporcie(env):
    env.handler = lambda q: _answer(q, rcode=dns.rcode.NXDOMAIN)
    r = env.resolver(env.proxy("alice:s3cret@"))
    report = build_report(collect("example.org", r, ["a"]), [])
    for text in (render_text(report), render_html(report), render_json(report)):
        assert "DoH https://doh.test/dns-query przez socks5h://127.0.0.1:" in text
        assert "alice" not in text and "s3cret" not in text
    assert json.loads(render_json(report))  # poprawny JSON


# --- CLI ---------------------------------------------------------------------------------------------------------

@pytest.fixture(autouse=True)
def _bez_proxy_w_srodowisku(monkeypatch):
    monkeypatch.delenv("OSINT_PROXY", raising=False)


def _zakaz_collect(monkeypatch):
    calls = []

    def boom(*a, **k):
        calls.append(a)
        raise AssertionError("collect nie powinien byc wywolany")

    monkeypatch.setattr(cli, "collect", boom)
    return calls


def test_cli_martwy_proxy_exit3_zero_zapytan(monkeypatch, capsys):
    calls = _zakaz_collect(monkeypatch)
    # zwykly resolver tez nie moze zostac uzyty
    monkeypatch.setattr(cli, "DnsPythonResolver", lambda *a, **k: pytest.fail("zapytanie bezposrednie"))
    rc = cli.main(["example.org", "--proxy", f"socks5h://alice:s3cret@127.0.0.1:{_closed_port()}"])
    err = capsys.readouterr().err
    assert rc == 3 and not calls
    assert "Proxy/DoH niedostępne" in err and "zero zapytań bezpośrednich" in err
    assert "s3cret" not in err and "alice" not in err


def test_cli_proxy_z_env(monkeypatch, capsys):
    monkeypatch.setenv("OSINT_PROXY", f"socks5h://127.0.0.1:{_closed_port()}")
    _zakaz_collect(monkeypatch)
    assert cli.main(["example.org"]) == 3
    assert "Kanał: DoH przez proxy DoH https://cloudflare-dns.com/dns-query przez socks5h://127.0.0.1:" in capsys.readouterr().err


def test_cli_resolver_z_proxy_exit2(monkeypatch):
    calls = _zakaz_collect(monkeypatch)
    assert cli.main(["example.org", "--proxy", "socks5h://127.0.0.1:9150", "--resolver", "1.1.1.1"]) == 2
    monkeypatch.setenv("OSINT_PROXY", "socks5h://127.0.0.1:9150")
    assert cli.main(["example.org", "--resolver", "1.1.1.1"]) == 2
    assert not calls


@pytest.mark.parametrize("args", [["--proxy", "http://127.0.0.1:9150"], ["--proxy", "127.0.0.1:9150"],
                                  ["--proxy", "socks5h://127.0.0.1:9150", "--doh", "http://dns.quad9.net/dns-query"]])
def test_cli_zly_proxy_lub_doh_exit2(monkeypatch, args):
    calls = _zakaz_collect(monkeypatch)
    assert cli.main(["example.org", *args]) == 2
    assert not calls


def test_cli_zly_proxy_z_env_exit2(monkeypatch):
    monkeypatch.setenv("OSINT_PROXY", "http://127.0.0.1:9150")
    _zakaz_collect(monkeypatch)
    assert cli.main(["example.org"]) == 2


def test_cli_proxy_i_direct_wykluczaja_sie():
    with pytest.raises(SystemExit) as e:
        cli.main(["example.org", "--proxy", "socks5h://127.0.0.1:9150", "--direct"])
    assert e.value.code == 2


def test_cli_direct_ignoruje_env_i_bez_env_jest_bezposrednio(monkeypatch, capsys):
    made = []

    def fake(nameserver=None, **k):
        made.append(nameserver)
        return good_domain()

    monkeypatch.setattr(cli, "DnsPythonResolver", fake)
    monkeypatch.setattr(cli, "DohResolver", lambda *a, **k: pytest.fail("DoH mimo --direct"))
    monkeypatch.setenv("OSINT_PROXY", "socks5h://127.0.0.1:9150")
    assert cli.main(["example.org", "--direct", "--resolver", "1.1.1.1"]) == 0
    assert "Kanał: bezpośrednio (resolver widzi audytowaną domenę)" in capsys.readouterr().err
    monkeypatch.delenv("OSINT_PROXY")
    assert cli.main(["example.org"]) == 0
    assert "Kanał: bezpośrednio" in capsys.readouterr().err
    assert made == ["1.1.1.1", None]


def test_cli_wstrzykniety_resolver_bez_zmian(monkeypatch, capsys):
    monkeypatch.setenv("OSINT_PROXY", "http://zly")
    assert cli.main(["example.org"], resolver=good_domain()) == 0
    assert "Kanał" not in capsys.readouterr().err


def test_cli_pelny_audyt_przez_stuby(env, monkeypatch, capsys):
    env.handler = lambda q: (
        _answer(q, "A", ["93.184.216.34"]) if str(q.question[0].name) == "example.com." and q.question[0].rdtype == 1
        else _answer(q, rcode=dns.rcode.NXDOMAIN)
    )
    monkeypatch.setattr(cli, "DohResolver", functools.partial(DohResolver, ssl_context=env.client_ctx))
    rc = cli.main(["example.org", "--proxy", env.proxy("alice:s3cret@"), "--doh", DOH_URL, "--json"])
    cap = capsys.readouterr()
    assert rc == 0
    assert "Kanał: DoH przez proxy DoH https://doh.test/dns-query przez socks5h://127.0.0.1:" in cap.err
    assert "alice" not in cap.err + cap.out and "s3cret" not in cap.err + cap.out
    assert json.loads(cap.out)
    assert env.socks_log and all(e["atyp"] == 3 and e["host"] == DOH_HOST for e in env.socks_log)
    assert len(env.doh_requests) > 20 and DOH_HOST not in env.resolved
