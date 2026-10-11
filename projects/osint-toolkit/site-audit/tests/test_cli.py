"""Calosc: CLI -> collector -> analiza -> raport, na lokalnym serwerze HTTP i HTTPS."""

import json
import shutil
import ssl
import subprocess
import threading

import pytest

from site_audit.cli import main
from site_audit.collector import collect
from site_audit.fetch import Fetcher
from site_audit.target import parse_target
from conftest import fake_resolver

RES = fake_resolver({"site.test": "127.0.0.1", "other.test": "127.0.0.1", "localhost": "127.0.0.1"})


def run(capsys, *argv):
    code = main(["--allow-private", "--timeout", "3", *argv], resolver=RES)
    out = capsys.readouterr()
    return code, out.out, out.err


def test_collect_uses_final_host_and_robots_sitemap(server):
    server.add("/", 200, [("Content-Type", "text/html")], "<title>t</title>")
    server.add("/robots.txt", 200, [("Content-Type", "text/plain")],
               f"User-agent: *\nSitemap: {server.url('/mapa.xml')}\nSitemap: http://other.test/x.xml\n")
    server.add("/mapa.xml", 200, [("Content-Type", "application/xml")], "<urlset><url><loc>a</loc></url></urlset>")
    data = collect(parse_target(server.url("/")), Fetcher(allow_private=True, resolver=RES, timeout=3))
    assert data.sitemap_url == server.url("/mapa.xml") and data.sitemap.response.status == 200
    assert "/.well-known/security.txt" in server.hits and "/security.txt" in server.hits
    assert data.http_probe is None  # niestandardowy port: bez sondy http://
    assert "/x.xml" not in server.hits


def test_offhost_redirect_of_helper_file_is_not_trusted(server):
    server.add("/", 200, [("Content-Type", "text/html")])
    server.add("/robots.txt", 302, [("Location", server.url("/r.txt", "other.test"))])
    server.add("/r.txt", 200, [("Content-Type", "text/plain")], "User-agent: *\n")
    data = collect(parse_target(server.url("/")), Fetcher(allow_private=True, resolver=RES, timeout=3))
    assert data.robots.response is None and data.robots.error_kind == "offhost"


def test_cli_json_and_exit_codes(server, capsys):
    server.add("/", 200, [("Content-Type", "text/html")], "<title>t</title>")
    code, out, _ = run(capsys, server.url("/"), "--json")
    d = json.loads(out)
    assert code == 0 and d["summary"]["status"] == 200
    assert any(f["title"] == "Strona końcowa działa bez HTTPS" for f in d["findings"])
    code, _, err = run(capsys, "ftp://x")
    assert code == 2 and "http i https" in err


def test_cli_unreachable_returns_3(capsys):
    code, out, _ = run(capsys, "http://site.test:1/", "--no-extra")
    assert code == 3 and "Nie udało się sprawdzić" in out


def test_cli_blocks_private_without_flag(server, capsys):
    server.add("/", 200)
    code = main([server.url("/"), "--json"], resolver=RES)
    out = capsys.readouterr().out
    assert code == 3 and "Cel zablokowany" in out and server.hits == []


def test_html_report_escapes_untrusted_values(server, capsys, tmp_path):
    evil = '<script>alert(1)</script>'
    server.add("/", 200, [("Content-Type", "text/html"), ("Server", f"x/1.0 {evil}"), ("Set-Cookie", f"{evil}=1")])
    out_file = tmp_path / "r.html"
    code, _, _ = run(capsys, server.url("/"), "--html", str(out_file), "--no-extra")
    page = out_file.read_text(encoding="utf-8")
    assert code == 0 and evil not in page and "&lt;script&gt;" in page
    assert "default-src 'none'" in page


def test_text_output_neutralises_control_chars(server, capsys):
    server.add("/", 200, [("Content-Type", "text/html"), ("X-Powered-By", "PHP/8.1 \x1b[2J")])
    code, out, _ = run(capsys, server.url("/"), "--no-extra")
    assert "\x1b" not in out and "\\x1b" in out


# ---------------------------------------------------------------- TLS lokalnie

@pytest.fixture
def tls_server(tmp_path):
    if shutil.which("openssl") is None:
        pytest.skip("brak openssl do wygenerowania certyfikatu testowego")
    key, cert = tmp_path / "k.pem", tmp_path / "c.pem"
    subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", str(key), "-out", str(cert),
                    "-days", "2", "-subj", "/CN=localhost"], check=True, capture_output=True)
    from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

    class H(BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def do_GET(self):
            body = b"<title>tls</title>"
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.send_header("Strict-Transport-Security", "max-age=31536000")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    httpd = ThreadingHTTPServer(("127.0.0.1", 0), H)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(cert, key)
    httpd.socket = ctx.wrap_socket(httpd.socket, server_side=True)
    threading.Thread(target=httpd.serve_forever, kwargs={"poll_interval": 0.05}, daemon=True).start()
    yield httpd.server_address[1]
    httpd.shutdown()
    httpd.server_close()


def test_self_signed_certificate_reported_but_headers_still_read(tls_server, capsys):
    code, out, _ = run(capsys, f"https://localhost:{tls_server}/", "--json", "--no-extra")
    d = json.loads(out)
    tls = d["summary"]["tls"]
    assert code == 0 and tls["verify_error"] and tls["cert"] is None and tls["version"]
    assert any(f["severity"] == "FAIL" and "weryfikacji" in f["title"] for f in d["findings"])
    assert any(f["severity"] == "OK" and f["title"].startswith("HSTS") for f in d["findings"])
