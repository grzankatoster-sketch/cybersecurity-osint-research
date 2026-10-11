"""Lokalny serwer HTTP (127.0.0.1) i falszywy resolver: testy bez internetu."""

from __future__ import annotations

import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest


class Route:
    def __init__(self, status=200, headers=None, body=b"", delay_chunks=None, delay_headers=None):
        self.status = status
        self.headers = headers or []
        self.body = body if isinstance(body, bytes) else body.encode("utf-8")
        self.delay_chunks = delay_chunks  # (liczba, sekundy): wolne wysylanie tresci
        self.delay_headers = delay_headers  # (liczba, sekundy): wolne wysylanie naglowkow


class LocalServer:
    def __init__(self):
        self.routes: dict[str, Route] = {}
        self.hits: list[str] = []
        server = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def do_GET(self):
                server.hits.append(self.path)
                r = server.routes.get(self.path) or Route(404, [("Content-Type", "text/plain")], b"nie ma")
                if r.delay_headers:
                    import time
                    n, sec = r.delay_headers
                    try:
                        self.wfile.write(b"HTTP/1.1 200 OK\r\n")
                        for i in range(n):
                            self.wfile.write(f"X-Pad-{i}: a\r\n".encode())
                            self.wfile.flush()
                            time.sleep(sec)
                    except OSError:
                        pass
                    return
                self.send_response(r.status)
                for k, v in r.headers:
                    self.send_header(k, v)
                if r.delay_chunks:
                    self.end_headers()
                    import time
                    n, sec = r.delay_chunks
                    for _ in range(n):
                        self.wfile.write(b"x" * 10)
                        self.wfile.flush()
                        time.sleep(sec)
                    return
                self.send_header("Content-Length", str(len(r.body)))
                self.end_headers()
                self.wfile.write(r.body)

        self.httpd = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.httpd.daemon_threads = True
        self.port = self.httpd.server_address[1]
        self.thread = threading.Thread(target=self.httpd.serve_forever, kwargs={"poll_interval": 0.05}, daemon=True)
        self.thread.start()

    def add(self, path, *a, **k):
        self.routes[path] = Route(*a, **k)
        return self

    def url(self, path="/", host="site.test"):
        return f"http://{host}:{self.port}{path}"

    def close(self):
        self.httpd.shutdown()
        self.httpd.server_close()


@pytest.fixture
def server():
    s = LocalServer()
    yield s
    s.close()


def fake_resolver(mapping: dict[str, str]):
    def resolve(host, port):
        if host not in mapping:
            raise OSError(f"nieznany host {host}")
        return [mapping[host]]
    return resolve
