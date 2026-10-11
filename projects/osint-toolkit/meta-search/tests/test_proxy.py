"""META_PROXY: proxy HTTP(S) ze stałym IP, fail-closed (bez fallbacku na połączenie bezpośrednie). Bez internetu."""
import socket
import threading

import pytest

from meta_search import graph
from meta_search.config import Config, load_config
from meta_search.contract import St
from meta_search.threads import ThreadsClient

TOKEN = "EAAtesttokentesttokentesttoken"


def _no_direct(url, timeout):
    raise AssertionError("połączenie bezpośrednie mimo ustawionego META_PROXY")


def test_config_accepts_http_proxy_and_hides_credentials(tmp_path):
    cfg = load_config({"META_SEARCH_ENV_FILE": str(tmp_path / "brak.env"),
                       "META_PROXY": "http://user:tajne@10.0.0.5:3128"})
    assert cfg.proxy == "http://user:tajne@10.0.0.5:3128" and not cfg.proxy_blocked
    shown = cfg.describe()["proxy"]
    assert shown == "http://10.0.0.5:3128" and "tajne" not in shown and "user" not in shown


def test_config_reads_proxy_from_file(tmp_path):
    f = tmp_path / "meta.env"
    f.write_text("META_PROXY=http://127.0.0.1:8080\n", encoding="utf-8")
    assert load_config({"META_SEARCH_ENV_FILE": str(f)}).proxy == "http://127.0.0.1:8080"


@pytest.mark.parametrize("value", ["socks5h://127.0.0.1:9150", "127.0.0.1:8080", "http://host", "http://h:99999",
                                   "http://a b:1"])
def test_bad_proxy_blocks_all_traffic(tmp_path, monkeypatch, value):
    monkeypatch.setattr(graph, "urllib_transport", _no_direct)
    cfg = load_config({"META_SEARCH_ENV_FILE": str(tmp_path / "brak.env"), "META_PROXY": value,
                       "THREADS_ACCESS_TOKEN": TOKEN})
    assert cfg.proxy_blocked and cfg.proxy is None
    assert any("META_PROXY" in p for p in cfg.problems)
    res = ThreadsClient(cfg, sleep=lambda s: None).profile("meta")
    assert res.status == St.SOURCE_ERROR and "META_PROXY" in res.message


def test_dead_proxy_fails_closed(monkeypatch):
    monkeypatch.setattr(graph, "urllib_transport", _no_direct)
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()                                  # zamknięty port: proxy martwe
    cfg = Config(threads_token=TOKEN, proxy=f"http://127.0.0.1:{port}")
    res = ThreadsClient(cfg, sleep=lambda s: None, timeout=3).profile("meta")
    assert res.status == St.SOURCE_ERROR and "bez połączenia bezpośredniego" in res.message
    assert TOKEN not in res.message


def test_required_proxy_without_proxy_blocks_configured_api(tmp_path):
    cfg = load_config({"META_SEARCH_ENV_FILE": str(tmp_path / "brak.env"),
                       "META_REQUIRE_PROXY": "1", "THREADS_ACCESS_TOKEN": TOKEN})
    assert cfg.require_proxy and cfg.proxy_blocked and cfg.proxy is None
    assert "META_PROXY" in " ".join(cfg.problems)


def test_request_goes_through_proxy_as_connect_tunnel(monkeypatch):
    """Proxy dostaje CONNECT z nazwą hosta API (DNS rozwiązuje proxy); token nie trafia do linii CONNECT."""
    monkeypatch.setattr(graph, "urllib_transport", _no_direct)
    srv = socket.socket()
    srv.bind(("127.0.0.1", 0))
    srv.listen(2)
    seen = []

    def serve():
        for _ in range(2):                     # zapytanie + jedno ponowienie
            try:
                conn, _ = srv.accept()
            except OSError:
                return
            with conn:
                seen.append(conn.recv(4096).decode("latin-1").split("\r\n", 1)[0])
                conn.sendall(b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n")
    t = threading.Thread(target=serve, daemon=True)
    t.start()
    cfg = Config(threads_token=TOKEN, proxy=f"http://127.0.0.1:{srv.getsockname()[1]}")
    res = ThreadsClient(cfg, sleep=lambda s: None, timeout=3).profile("meta")
    srv.close()
    t.join(2)
    assert seen and seen[0].startswith("CONNECT graph.threads.net:443 ")
    assert all(TOKEN not in line for line in seen)
    assert res.status == St.SOURCE_ERROR


def test_without_proxy_uses_default_transport(monkeypatch):
    calls = []
    monkeypatch.setattr(graph, "urllib_transport", lambda url, timeout: calls.append(url) or (500, {}, b"", None))
    ThreadsClient(Config(threads_token=TOKEN), sleep=lambda s: None, retries=0).profile("meta")
    assert calls


# --- R1-D: jawne META_PROXY wygrywa z NO_PROXY, wyjątkami systemowymi i *_PROXY środowiska ---

API = "https://graph.threads.net/v1.0/me"


class _Resp:
    status = code = 200
    msg = "OK"
    headers = {}

    def read(self, n=-1):
        return b"{}"

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False

    def info(self):
        return {}

    def geturl(self):
        return API


@pytest.mark.parametrize("env", [
    {"NO_PROXY": "graph.threads.net"},
    {"no_proxy": "graph.threads.net"},
    {"NO_PROXY": "*", "no_proxy": "*"},
    {"no_proxy": ".threads.net,localhost"},
    {"HTTPS_PROXY": "http://10.9.9.9:1", "https_proxy": "http://10.9.9.9:1", "NO_PROXY": "*"},
])
def test_explicit_proxy_ignores_bypass_rules(monkeypatch, env):
    import os
    import urllib.request
    seen = []

    def capture(self, req):
        seen.append({"host": req.host, "tunnel": getattr(req, "_tunnel_host", None),
                     "auth": req.get_header("Proxy-authorization")})
        return _Resp()
    for key in ("NO_PROXY", "no_proxy", "HTTPS_PROXY", "https_proxy"):
        monkeypatch.delenv(key, raising=False)
    for key, val in env.items():
        monkeypatch.setenv(key, val)
    monkeypatch.setattr(urllib.request, "proxy_bypass", lambda host: True)   # wyjątek systemowy (rejestr) dla każdego hosta
    monkeypatch.setattr(urllib.request.HTTPSHandler, "https_open", capture)
    before = dict(os.environ)
    status, _, body, err = graph.proxy_transport("http://us%40r:p%3Ass@127.0.0.1:9999")(API, 1)
    assert (status, err) == (200, None) and dict(os.environ) == before
    assert seen == [{"host": "127.0.0.1:9999", "tunnel": "graph.threads.net",
                     "auth": "Basic " + __import__("base64").b64encode(b"us@r:p:ss").decode()}]


def test_dead_proxy_with_wildcard_no_proxy_never_connects_directly(monkeypatch):
    attempts = []

    def fake_connect(address, *a, **k):
        attempts.append(address)
        raise ConnectionRefusedError("atrapa: proxy nie odpowiada")
    monkeypatch.setenv("NO_PROXY", "*")
    monkeypatch.setenv("no_proxy", "*")
    monkeypatch.setattr(socket, "create_connection", fake_connect)
    monkeypatch.setattr(graph, "urllib_transport", _no_direct)
    cfg = Config(threads_token=TOKEN, proxy="http://127.0.0.1:9")
    res = ThreadsClient(cfg, sleep=lambda s: None, timeout=1).profile("meta")
    assert res.status == St.SOURCE_ERROR and "bez połączenia bezpośredniego" in res.message
    assert attempts and all(a == ("127.0.0.1", 9) for a in attempts)   # zapytanie i ponowienie: tylko do proxy


def test_plain_http_is_refused_without_any_connection(monkeypatch):
    monkeypatch.setattr(socket, "create_connection", lambda *a, **k: pytest.fail("połączenie dla http://"))
    status, _, _, err = graph.proxy_transport("http://127.0.0.1:9")("http://graph.threads.net/x", 1)
    assert status is None and "bez połączenia bezpośredniego" in err


# --- audyt OPSEC 04.10.2026: raport bez zasobów zdalnych, adres zdjęcia Threads tylko https ---

def test_report_has_csp_and_no_referrer_without_remote_resources():
    from meta_search.report import render_html
    from meta_search.threads import ThreadsClient as TC
    fake = lambda url, timeout: (200, {}, b'{"username":"meta","name":"Meta","follower_count":5,'
                                         b'"profile_picture_url":"https://cdn.example/p.jpg"}', None)
    html = render_html(TC(Config(threads_token=TOKEN), transport=fake).profile("meta"))
    assert "default-src 'none'" in html and 'name="referrer" content="no-referrer"' in html
    assert "<img" not in html and "<script" not in html and "<link" not in html


@pytest.mark.parametrize("pic", ["javascript:alert(1)", "http://cdn.example/p.jpg", "data:image/png;base64,AA"])
def test_threads_profile_picture_must_be_https(pic):
    import json as _json
    body = _json.dumps({"username": "meta", "profile_picture_url": pic}).encode()
    res = ThreadsClient(Config(threads_token=TOKEN), transport=lambda u, t: (200, {}, body, None)).profile("meta")
    assert res.status == St.FOUND and res.items[0]["profile_picture_url"] == ""
