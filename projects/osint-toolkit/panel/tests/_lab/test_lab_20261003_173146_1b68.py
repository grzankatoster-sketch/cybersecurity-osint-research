import json
import sys
import threading
import urllib.error
import urllib.request
from http.server import ThreadingHTTPServer
from pathlib import Path
from types import SimpleNamespace

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
import app  # noqa: E402

PHONE = {"number": "603123456"}


def _free(sem):
    """Liczba wolnych slotow semafora (bez trwalej zmiany jego stanu)."""
    n = 0
    while sem.acquire(blocking=False):
        n += 1
    for _ in range(n):
        sem.release()
    return n


def _ok(*a, **k):
    return SimpleNamespace(returncode=0, stdout="ok", stderr="")


def _never(*a, **k):
    raise AssertionError("podproces nie powinien zostac uruchomiony")


@pytest.fixture
def slots(monkeypatch, tmp_path):
    monkeypatch.setattr(app, "OUT", tmp_path)
    sem = threading.BoundedSemaphore(2)
    monkeypatch.setattr(app, "_PROC_SLOTS", sem)
    return sem


@pytest.fixture
def exhausted(slots):
    assert slots.acquire(blocking=False) and slots.acquire(blocking=False)
    yield slots
    slots.release()
    slots.release()


def test_default_limit_is_four():
    assert app.MAX_PROCS == 4
    assert _free(app._PROC_SLOTS) == 4
    assert issubclass(app.Overloaded, Exception)


def test_concurrent_runs_over_limit_refused_and_slots_return(slots, monkeypatch):
    entered = threading.Semaphore(0)
    gate = threading.Event()

    def slow(*a, **k):
        entered.release()
        assert gate.wait(10)
        return _ok()

    monkeypatch.setattr(app.subprocess, "run", slow)
    results = []
    ths = [threading.Thread(target=lambda: results.append(app.run_tool("phone", PHONE))) for _ in range(2)]
    for t in ths:
        t.start()
    try:
        assert entered.acquire(timeout=5) and entered.acquire(timeout=5)
        with pytest.raises(app.Overloaded) as e:
            app.run_tool("phone", PHONE)
        assert "rownoczesnych" in str(e.value)
    finally:
        gate.set()
        for t in ths:
            t.join(5)
    assert [r["code"] for r in results] == [0, 0]
    assert _free(slots) == 2
    assert app.run_tool("phone", PHONE)["code"] == 0
    assert _free(slots) == 2


def test_validation_has_priority_over_limit(exhausted, monkeypatch):
    monkeypatch.setattr(app.subprocess, "run", _never)
    with pytest.raises(ValueError):
        app.run_tool("phone", {"number": "-x"})
    with pytest.raises(ValueError):
        app.run_tool("nieznana", {})
    with pytest.raises(app.Overloaded):
        app.run_tool("phone", PHONE)


@pytest.mark.parametrize("exc", [OSError("brak pliku"), app.subprocess.TimeoutExpired("x", 1)])
def test_slot_released_after_tool_error(slots, monkeypatch, exc):
    def boom(*a, **k):
        raise exc
    monkeypatch.setattr(app.subprocess, "run", boom)
    r = app.run_tool("phone", PHONE)
    assert r["code"] == -1
    assert _free(slots) == 2


def test_slot_released_after_unexpected_exception(slots, monkeypatch):
    def boom(*a, **k):
        raise RuntimeError("nieoczekiwany")
    monkeypatch.setattr(app.subprocess, "run", boom)
    with pytest.raises(RuntimeError):
        app.run_tool("phone", PHONE)
    assert _free(slots) == 2


def test_limit_does_not_leak_long_lock(exhausted, monkeypatch):
    monkeypatch.setattr(app.subprocess, "run", _never)
    with pytest.raises(app.Overloaded):
        app.run_tool("username", {"username": "mozilla"})
    assert not app._LONG_LOCK.locked()


def test_busy_long_scan_does_not_leak_slot(slots, monkeypatch):
    monkeypatch.setattr(app.subprocess, "run", _never)
    assert app._LONG_LOCK.acquire(blocking=False)
    try:
        with pytest.raises(app.Busy):
            app.run_tool("username", {"username": "mozilla"})
    finally:
        app._LONG_LOCK.release()
    assert _free(slots) == 2


def test_password_check_respects_limit(exhausted, monkeypatch):
    monkeypatch.setattr(app.subprocess, "run", _never)
    with pytest.raises(ValueError):
        app.check_password_proc("")
    with pytest.raises(app.Overloaded):
        app.check_password_proc("tajne123")


def test_password_check_releases_slot(slots, monkeypatch):
    monkeypatch.setattr(app.subprocess, "run",
                        lambda *a, **k: SimpleNamespace(returncode=0, stdout='{"count": 0}', stderr=""))
    r = app.check_password_proc("tajne123")
    assert r["code"] == 0 and r["pwned"] is False
    assert _free(slots) == 2


@pytest.fixture
def server():
    srv = ThreadingHTTPServer(("127.0.0.1", 0), app.Handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    yield f"http://127.0.0.1:{srv.server_address[1]}"
    srv.shutdown()


def _post(url, body):
    req = urllib.request.Request(url, data=json.dumps(body).encode(), method="POST",
                                 headers={"Content-Type": "application/json", "X-Panel-Token": app.TOKEN})
    try:
        with urllib.request.urlopen(req) as r:
            return r.status, r.headers, json.loads(r.read())
    except urllib.error.HTTPError as e:
        return e.code, e.headers, json.loads(e.read())


def test_http_429_when_limit_reached(server, exhausted, monkeypatch):
    monkeypatch.setattr(app.subprocess, "run", _never)
    for action, body in (("phone", PHONE), ("hibp_password", {"password": "tajne123"}),
                         ("username", {"username": "mozilla"})):
        status, headers, r = _post(server + "/api/" + action, body)
        assert status == 429, (action, r)
        assert r["busy"] is True and r["overloaded"] is True
        assert "rownoczesnych" in r["error"]
        assert headers.get("Retry-After") == "5"
    status, _, r = _post(server + "/api/phone", {"number": "-x"})
    assert status == 400


def test_http_ok_again_after_slots_free(server, slots, monkeypatch):
    monkeypatch.setattr(app.subprocess, "run", _ok)
    status, headers, r = _post(server + "/api/phone", PHONE)
    assert status == 200 and r["code"] == 0 and "overloaded" not in r
    assert headers.get("Retry-After") is None
    assert _free(slots) == 2
