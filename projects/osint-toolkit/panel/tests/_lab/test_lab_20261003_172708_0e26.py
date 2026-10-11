import re
import sys
import threading
import urllib.error
import urllib.request
from http.server import ThreadingHTTPServer
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))
import app  # noqa: E402


@pytest.fixture
def server():
    srv = ThreadingHTTPServer(("127.0.0.1", 0), app.Handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    yield f"http://127.0.0.1:{srv.server_address[1]}"
    srv.shutdown()


def _open(url, method="GET", headers=None, data=None):
    """Zwraca (status, naglowki, tresc) takze dla odpowiedzi bledow."""
    req = urllib.request.Request(url, method=method, headers=headers or {}, data=data)
    try:
        with urllib.request.urlopen(req) as r:
            return r.status, r.headers, r.read()
    except urllib.error.HTTPError as e:
        return e.code, e.headers, e.read()


def _directives(csp):
    out = {}
    for part in (csp or "").split(";"):
        bits = part.strip().split()
        if bits:
            out[bits[0]] = bits[1:]
    return out


def _assert_strict(headers):
    assert headers.get("X-Content-Type-Options") == "nosniff"
    d = _directives(headers.get("Content-Security-Policy"))
    assert d.get("default-src") == ["'none'"], headers.get("Content-Security-Policy")
    assert d.get("frame-ancestors") == ["'none'"]
    assert d.get("base-uri") == ["'none'"]
    assert d.get("form-action") == ["'none'"]


def test_index_csp_with_per_request_nonce(server):
    status, h, body = _open(server + "/")
    assert status == 200
    html = body.decode("utf-8")
    csp = h.get("Content-Security-Policy")
    assert csp, "strona glowna bez CSP"
    d = _directives(csp)
    assert d["default-src"] == ["'none'"]
    assert d["frame-ancestors"] == ["'none'"]
    assert d["base-uri"] == ["'none'"] and d["form-action"] == ["'none'"]
    assert d["connect-src"] == ["'self'"] and d["frame-src"] == ["'self'"]
    assert d["style-src"] == ["'unsafe-inline'"]
    assert len(d["script-src"]) == 1 and "'unsafe-inline'" not in d["script-src"]
    m = re.fullmatch(r"'nonce-([A-Za-z0-9_-]{16,})'", d["script-src"][0])
    assert m, d["script-src"]
    nonce = m.group(1)
    assert f'<script nonce="{nonce}">' in html
    assert "__NONCE__" not in html and app.TOKEN in html
    assert h.get("X-Content-Type-Options") == "nosniff"


def test_index_nonce_differs_between_requests(server):
    def nonce():
        _, h, _ = _open(server + "/")
        return re.search(r"'nonce-([^']+)'", h.get("Content-Security-Policy") or "").group(1)
    assert nonce() != nonce()


def test_404_and_bad_host_have_strict_csp(server):
    status, h, _ = _open(server + "/nie-ma")
    assert status == 404
    _assert_strict(h)
    status, h, _ = _open(server + "/", headers={"Host": "evil.example"})
    assert status == 403
    _assert_strict(h)


def test_api_json_responses_have_strict_csp(server):
    status, h, _ = _open(server + "/api/phone", method="POST", data=b"{}",
                         headers={"Content-Type": "application/json", "X-Panel-Token": "zly"})
    assert status == 403
    _assert_strict(h)
    status, h, _ = _open(server + "/api/nieznana", method="POST", data=b"{}",
                         headers={"Content-Type": "application/json", "X-Panel-Token": app.TOKEN})
    assert status == 400
    _assert_strict(h)


@pytest.mark.parametrize("method", ["PUT", "DELETE"])
def test_stdlib_send_error_gets_security_headers(server, method):
    status, h, body = _open(server + "/", method=method, data=b"" if method == "PUT" else None)
    assert status == 501
    _assert_strict(h)
    assert h.get("Cache-Control") == "no-store"
    assert h.get("Content-Type", "").startswith("text/plain")
    assert b"<html" not in body.lower() and b"<!doctype" not in body.lower()


def test_report_iframe_not_blocked_by_frame_ancestors(server, tmp_path, monkeypatch):
    monkeypatch.setattr(app, "OUT", tmp_path)
    (tmp_path / "dns_x_20260101-000000.html").write_text("<html>ok</html>", encoding="utf-8")
    status, h, body = _open(server + "/wyniki/dns_x_20260101-000000.html")
    assert status == 200 and b"ok" in body
    assert "frame-ancestors 'none'" not in (h.get("Content-Security-Policy") or "")
