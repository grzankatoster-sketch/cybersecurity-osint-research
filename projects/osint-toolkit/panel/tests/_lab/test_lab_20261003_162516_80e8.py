import sys
import threading
import urllib.request
from http.server import ThreadingHTTPServer
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))
import app  # noqa: E402


@pytest.fixture
def server(tmp_path, monkeypatch):
    monkeypatch.setattr(app, "OUT", tmp_path)
    srv = ThreadingHTTPServer(("127.0.0.1", 0), app.Handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    yield f"http://127.0.0.1:{srv.server_address[1]}", tmp_path
    srv.shutdown()


def _get(url):
    with urllib.request.urlopen(url) as r:
        return r.status, r.headers, r.read()


def _tokens(csp):
    return csp.lower().replace(";", " ").split()


def test_report_served_with_csp_sandbox(server):
    base, out = server
    (out / "dns_example.com_20260101-000000.html").write_text("<html><script>1</script></html>", encoding="utf-8")
    status, headers, body = _get(base + "/wyniki/dns_example.com_20260101-000000.html")
    assert status == 200 and b"<script>1</script>" in body
    csp = headers.get("Content-Security-Policy")
    assert csp, "raport bez naglowka CSP"
    assert "sandbox" in _tokens(csp)


def test_report_sandbox_has_no_same_origin_but_keeps_scripts_and_popups(server):
    base, out = server
    (out / "mapa_20260101-000000.html").write_text("<html>mapa</html>", encoding="utf-8")
    _, headers, _ = _get(base + "/wyniki/mapa_20260101-000000.html")
    toks = _tokens(headers.get("Content-Security-Policy") or "")
    assert "sandbox" in toks
    assert "allow-same-origin" not in toks
    for flag in ("allow-scripts", "allow-popups", "allow-popups-to-escape-sandbox"):
        assert flag in toks, flag


def test_every_report_kind_gets_sandbox(server):
    base, out = server
    names = ["un_mozilla_20260101-000000.html", "maigret_jan.k_20260101-000000.html"]
    for n in names:
        (out / n).write_text("<html></html>", encoding="utf-8")
    for n in names:
        _, headers, _ = _get(base + "/wyniki/" + n)
        assert "sandbox" in _tokens(headers.get("Content-Security-Policy") or ""), n


def test_index_page_not_sandboxed_and_still_has_token(server):
    base, _ = server
    status, headers, body = _get(base + "/")
    assert status == 200 and app.TOKEN in body.decode("utf-8")
    assert "sandbox" not in _tokens(headers.get("Content-Security-Policy") or "")
    assert headers.get("X-Content-Type-Options") == "nosniff"
