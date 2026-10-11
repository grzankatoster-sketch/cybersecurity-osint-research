"""Klient HTTP wobec lokalnego serwera 127.0.0.1 (bez internetu)."""
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest

from entity_graph.http import HttpClient, HttpResponse, classify_http
from entity_graph.model import Status

HITS: dict[str, int] = {}


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def do_GET(self):
        HITS[self.path] = HITS.get(self.path, 0) + 1
        if self.path == "/ok":
            body = "witaj ąę".encode("utf-8")
            self.send_response(200)
        elif self.path == "/missing":
            body = b"nie ma"
            self.send_response(404)
        elif self.path == "/limit":
            body = b"zwolnij"
            self.send_response(429)
            self.send_header("Retry-After", "0")
        elif self.path == "/limit-once":
            if HITS[self.path] == 1:
                body = b"x"
                self.send_response(429)
                self.send_header("Retry-After", "0")
            else:
                body = b"juz dobrze"
                self.send_response(200)
        elif self.path == "/ftp-redirect":
            body = b""
            self.send_response(302)
            self.send_header("Location", "ftp://example.com/x")
        elif self.path == "/redir":
            body = b""
            self.send_response(302)
            self.send_header("Location", "/ok")
        elif self.path == "/big":
            body = b"a" * 5000
            self.send_response(200)
        else:
            body = b"?"
            self.send_response(500)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


@pytest.fixture(scope="module")
def server():
    srv = HTTPServer(("127.0.0.1", 0), Handler)
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    yield f"http://127.0.0.1:{srv.server_port}"
    srv.shutdown()


def client(**kw):
    return HttpClient(timeout=3, min_interval=0, sleep=lambda s: None, **kw)


def test_ok_and_utf8(server):
    r = client().get(server + "/ok")
    assert r.status == 200 and r.text == "witaj ąę" and r.error is None


def test_404_is_status_not_error(server):
    r = client().get(server + "/missing")
    assert r.status == 404 and r.text == "nie ma"


def test_429_retries_once_then_reports_status(server):
    HITS.clear()
    r = client(retries=1).get(server + "/limit")
    assert r.status == 429 and HITS["/limit"] == 2
    HITS.clear()
    assert client(retries=1).get(server + "/limit-once").status == 200


def test_redirect_followed_but_non_http_scheme_blocked(server):
    assert client().get(server + "/redir").text.startswith("witaj")
    r = client().get(server + "/ftp-redirect")
    assert r.status == 302 or r.error   # nie podążamy za ftp://, nic nie wychodzi poza http(s)
    assert not (r.status == 200)


def test_body_limit(server):
    r = client(max_bytes=1000).get(server + "/big")
    assert r.error and "limit" in r.error and r.text == ""


def test_connection_refused_is_error_not_status():
    r = client().get("http://127.0.0.1:9/x")
    assert r.status is None and r.error


def test_rejects_non_http_scheme():
    for url in ("file:///etc/passwd", "ftp://example.com/x", "gopher://x/"):
        r = client().get(url)
        assert r.status is None and "schemat" in r.error


def test_throttle_waits_per_host():
    sleeps = []
    t = [0.0]
    c = HttpClient(timeout=1, min_interval=2.0, sleep=sleeps.append, clock=lambda: t[0])
    c._once = lambda url, headers: HttpResponse(200, "x")
    c.get("http://a.example/1")
    c.get("http://a.example/2")
    c.get("http://b.example/1")
    assert sleeps == [2.0]   # druga prośba do a.example czeka; b.example nie


def test_user_agent_is_honest(server):
    assert "entity-graph" in HttpClient().user_agent


def test_has_no_proxy_options():
    import inspect

    assert "proxy" not in " ".join(inspect.signature(HttpClient.__init__).parameters)


@pytest.mark.parametrize("resp,expected", [
    (HttpResponse(200, "x"), None),
    (HttpResponse(404), Status.NOT_FOUND),
    (HttpResponse(429), Status.ERROR),
    (HttpResponse(403), Status.ERROR),
    (HttpResponse(401), Status.ERROR),
    (HttpResponse(503), Status.ERROR),
    (HttpResponse(None, error="timeout"), Status.ERROR),
    (HttpResponse(302), Status.UNKNOWN),
])
def test_classify_http(resp, expected):
    assert classify_http(resp)[0] is expected


def test_classify_404_when_not_authoritative_is_error():
    assert classify_http(HttpResponse(404), not_found_ok=False)[0] is Status.ERROR
