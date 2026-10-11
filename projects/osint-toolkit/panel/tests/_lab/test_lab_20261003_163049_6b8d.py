import json
import socket
import sys
import threading
from http.server import ThreadingHTTPServer
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))
import app  # noqa: E402


@pytest.fixture
def server():
    srv = ThreadingHTTPServer(("127.0.0.1", 0), app.Handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    yield srv.server_address[1]
    srv.shutdown()
    srv.server_close()


def test_negative_content_length_does_not_bypass_size_limit(server, monkeypatch):
    calls = []

    def fake_run_tool(action, params):
        calls.append((action, params))
        return {"code": 0, "stdout": "", "stderr": "", "seconds": 0, "report": None}

    monkeypatch.setattr(app, "run_tool", fake_run_tool)

    big = "a" * 25_000
    body = json.dumps({"number": "+48221234567", "pad": big}).encode()
    assert len(body) > 20_000
    head = (
        "POST /api/phone HTTP/1.1\r\n"
        f"Host: 127.0.0.1:{server}\r\n"
        "Content-Type: application/json\r\n"
        f"X-Panel-Token: {app.TOKEN}\r\n"
        "Content-Length: -1\r\n"
        "Connection: close\r\n\r\n"
    ).encode()

    with socket.create_connection(("127.0.0.1", server), timeout=5) as s:
        s.sendall(head + body)
        s.shutdown(socket.SHUT_WR)
        resp = b""
        while True:
            chunk = s.recv(65536)
            if not chunk:
                break
            resp += chunk

    status = int(resp.split(b" ", 2)[1])
    # zapytanie z nieprawidlowym (ujemnym) Content-Length i cialem ponad limit musi byc odrzucone
    assert status == 400, resp[:300]
    # i nadmiarowe dane nie moga dotrzec do uruchamiania narzedzi
    assert not any(p.get("pad") == big for _, p in calls)
