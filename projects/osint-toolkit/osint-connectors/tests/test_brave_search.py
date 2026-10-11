"""Test kontraktowy konektora Brave Search API: atrapa HTTP, dane syntetyczne, zero ruchu sieciowego."""
import asyncio
import json
from urllib.parse import parse_qs, urlsplit

import pytest

import osint_connectors.connectors.brave_search as brave  # noqa: F401  (rejestruje konektor)
import osint_connectors.connectors.gravatar_public  # noqa: F401
import osint_connectors.connectors.manual  # noqa: F401
import osint_connectors.connectors.passive_local  # noqa: F401
from osint_connectors import (Context, InputKind, Status, Subject, UrllibClient, registry, run, subject_ref)
from osint_connectors.errors import ConnectorTimeout

KEY = "SYNTH-KEY-0123456789abcdef"
PAYLOAD = {
    "type": "search",
    "query": {"original": "x", "more_results_available": True},
    "web": {"results": [
        {"title": "Jan <strong>Testowy</strong> | Facebook", "url": "https://www.facebook.com/jan.testowy.1",
         "description": "Jan Testowy jest na Facebooku. &amp; więcej\x07"},
        {"title": "bez url"},
        "śmieć",
        {"title": "x" * 500, "url": "https://www.instagram.com/jtestowy/", "description": "y" * 900},
    ]},
}


class Resp:
    def __init__(self, status_code, payload=None, raw=None):
        self.status_code = status_code
        self._payload, self._raw = payload, raw

    def json(self):
        if self._raw is not None:
            return json.loads(self._raw)
        return self._payload

    @property
    def text(self):
        return self._raw or json.dumps(self._payload)


class FakeHttp:
    def __init__(self, response=None, exc=None):
        self.response, self.exc, self.calls = response, exc, []

    async def get(self, url, *, headers=None, timeout=None):
        self.calls.append((url, dict(headers or {}), timeout))
        if self.exc is not None:
            raise self.exc
        return self.response


def _check(http, name="Jan Testowy", key=KEY, query=None, count=20):
    query = query or brave.build_queries(name)[0]
    ctx = Context(salt="sol", http=http, timeout=1.0, extra={"query": query, "api_key": key, "count": count})
    return asyncio.run(run([registry.get("brave_search")], Subject(InputKind.PERSON_NAME, name), ctx))[0]


# --- typ wejścia i zgodność istniejących konektorów ----------------------------------------------------------

def test_person_name_input_kind_is_separate_and_existing_connectors_unchanged():
    assert InputKind.PERSON_NAME.value == "person_name"
    assert [c.name for c in registry.for_input(InputKind.PERSON_NAME)] == ["brave_search"]
    assert "brave_search" not in [c.name for c in registry.for_input(InputKind.EMAIL)]
    assert "brave_search" not in [c.name for c in registry.for_input(InputKind.USERNAME)]
    assert {c.name for c in registry.for_input(InputKind.EMAIL)} >= {"gravatar_public", "manual_confirm"}
    ref = subject_ref(Subject(InputKind.PERSON_NAME, "Jan Testowy"), "sol")
    assert ref != subject_ref(Subject(InputKind.USERNAME, "Jan Testowy"), "sol") and len(ref) == 64


# --- plan zapytań: dane, nie operatory ----------------------------------------------------------------------

def test_build_queries_deterministic_order_and_variants():
    plan = brave.build_queries("Łukasz Żółć", "Kraków Firma")
    assert [q.text for q in plan] == [
        '"Łukasz Żółć" site:facebook.com', '"Łukasz Żółć" site:instagram.com', '"Łukasz Żółć" site:threads.com',
        '"Łukasz Żółć" kraków firma site:facebook.com', '"Łukasz Żółć" kraków firma site:instagram.com',
        '"Łukasz Żółć" kraków firma site:threads.com',
        '"Lukasz Zolc" site:facebook.com', '"Lukasz Zolc" site:instagram.com', '"Lukasz Zolc" site:threads.com']
    assert plan[0].variant == brave.VARIANT_BASE and plan[-1].variant == brave.VARIANT_ASCII
    assert [q.text for q in brave.build_queries("Jan Testowy")] == [
        '"Jan Testowy" site:facebook.com', '"Jan Testowy" site:instagram.com', '"Jan Testowy" site:threads.com']
    assert brave.build_queries("Jan Testowy") == brave.build_queries("  Jan   Testowy ")


@pytest.mark.parametrize("bad", [
    'Jan" OR site:evil.example "x', "Jan site:evil.example", "Jan -Testowy", "Jan +Testowy", "Jan",
    "Jan\nTestowy", "Jan\x00Testowy", "J" * 101, "a b c d e f g", "Jan (Testowy)", "Jan *", "", None, 5,
])
def test_name_injection_and_shape_rejected(bad):
    with pytest.raises(ValueError):
        brave.build_queries(bad)


@pytest.mark.parametrize("bad", ["site:evil.example", '"x"', "-wyklucz", "+wymus", "a b c d e f", "x\ty\x01"])
def test_context_injection_rejected(bad):
    with pytest.raises(ValueError):
        brave.build_queries("Jan Testowy", bad)


def test_context_logical_operators_neutralised_by_lowercase():
    q = brave.build_queries("Anna Nowak-Kowalska", "Gdańsk OR NOT")[3]
    assert q.text == '"Anna Nowak-Kowalska" gdańsk or not site:facebook.com'


# --- odpowiedzi i statusy ------------------------------------------------------------------------------------

def test_found_parses_minimal_records_and_sends_key_only_in_header():
    http = FakeHttp(Resp(200, PAYLOAD))
    f = _check(http, count=7)
    assert f.status is Status.FOUND and f.confidence == 0.0
    res = f.extra["results"]
    assert [r["url"] for r in res] == ["https://www.facebook.com/jan.testowy.1", "https://www.instagram.com/jtestowy/"]
    assert res[0]["title"] == "Jan Testowy | Facebook" and res[0]["snippet"] == "Jan Testowy jest na Facebooku. & więcej"
    assert len(res[1]["title"]) <= brave.MAX_TITLE and len(res[1]["snippet"]) <= brave.MAX_SNIPPET
    assert f.extra["more_results_available"] is True
    url, headers, _ = http.calls[0]
    parts = urlsplit(url)
    assert f"{parts.scheme}://{parts.netloc}{parts.path}" == brave.ENDPOINT
    qs = parse_qs(parts.query)
    assert qs == {"q": ['"Jan Testowy" site:facebook.com'], "count": ["7"]}     # bez offset: bez stronicowania
    assert headers["X-Subscription-Token"] == KEY and KEY not in url
    dumped = json.dumps(f.to_dict(), ensure_ascii=False)
    assert KEY not in dumped and "Jan Testowy\"" not in dumped and f.subject_ref


def test_empty_result_is_not_found_for_this_query_only():
    f = _check(FakeHttp(Resp(200, {"type": "search", "query": {"original": "x"}})))
    assert f.status is Status.NOT_FOUND and "nie oznacza braku kont" in f.evidence
    f = _check(FakeHttp(Resp(200, {"type": "search", "web": {"results": []}})))
    assert f.status is Status.NOT_FOUND


@pytest.mark.parametrize("resp,exc,kind", [
    (Resp(401), None, "auth_required"),
    (Resp(403), None, "auth_required"),
    (Resp(429), None, "rate_limited"),
    (Resp(422), None, "request_rejected"),
    (Resp(503), None, "transport"),
    (Resp(302), None, "schema_changed"),
    (Resp(200, raw="{nie json"), None, "parse"),
    (Resp(200, {"cos": "innego"}), None, "schema_changed"),
    (Resp(200, {"type": "search", "web": {"results": "x"}}), None, "schema_changed"),
    (None, ConnectorTimeout("t"), "timeout"),
    (None, OSError("sieć z adresem https://api.search.brave.com/?q=Jan"), "transport"),
])
def test_error_reasons_are_distinct(resp, exc, kind):
    f = _check(FakeHttp(resp, exc))
    assert f.status in (Status.ERROR, Status.UNKNOWN) and f.error_kind == kind
    assert "Jan" not in (f.evidence or "")


def test_missing_key_sends_nothing():
    http = FakeHttp(Resp(200, PAYLOAD))
    f = _check(http, key="")
    assert f.status is Status.UNKNOWN and f.error_kind == "not_configured" and http.calls == []


def test_query_from_other_person_or_bad_count_rejected_without_request():
    http = FakeHttp(Resp(200, PAYLOAD))
    other = brave.build_queries("Anna Inna")[0]
    assert _check(http, query=other).error_kind == "request_rejected"
    assert _check(http, count=21).error_kind == "request_rejected"
    assert http.calls == []
    ascii_q = brave.build_queries("Łukasz Żółć")[3]
    assert _check(FakeHttp(Resp(200, PAYLOAD)), name="Łukasz Żółć", query=ascii_q).status is Status.FOUND


# --- klient stdlib: proxy fail-closed ------------------------------------------------------------------------

@pytest.mark.parametrize("proxy", ["socks5h://127.0.0.1:9150", "https://127.0.0.1:8443", "http://host",
                                   "ftp://h:21", "http://h:99999",
                                   "http://h:8080/sciezka"])
def test_urllib_client_rejects_bad_proxy(proxy):
    with pytest.raises(ValueError):
        UrllibClient(proxy=proxy)


def test_urllib_client_dead_proxy_never_goes_direct():
    client = UrllibClient(proxy="http://127.0.0.1:9")    # port discard: brak proxy
    with pytest.raises(Exception) as info:
        asyncio.run(client.get("https://api.search.brave.com/res/v1/web/search?q=x", headers={"X-Subscription-Token": KEY},
                               timeout=2))
    assert "bez połączenia bezpośredniego" in str(info.value) and KEY not in str(info.value)
    with pytest.raises(Exception):
        asyncio.run(client.get("http://example.invalid/", timeout=2))   # HTTP przez proxy: zablokowane


# --- R5A: walidacja otoczki odpowiedzi (błąd struktury nigdy nie jest "brakiem wyników") ---------------------------

@pytest.mark.parametrize("payload", [
    {"type": "error", "error": {"code": "SYNTHETIC_ERROR"}},                     # dokument błędu
    {"type": "ErrorResponse", "error": {"status": 422, "code": "SYNTHETIC"}},
    {"error": {"code": "SYNTHETIC"}, "query": {"original": "x"}},                 # błąd mimo sekcji query
    {"type": "news", "web": {"results": []}},                                     # nieznany typ
    {"type": 7, "web": {"results": []}},
    {"type": "search"},                                                           # ani query, ani web
    {"type": "search", "query": "x"},                                             # złe typy pól
    {"type": "search", "query": {"original": "x"}, "web": []},
    {"type": "search", "web": {"type": "search"}},                                # web bez results
    {"type": "search", "web": {"results": None}},
    {"type": "search", "web": {"results": [{"title": "bez url"}, "śmieć", {"url": 5}, {"url": "  "}]}},
    [], "tekst", None,
])
def test_invalid_envelope_is_schema_error_not_empty(payload):
    with pytest.raises(brave.SchemaChanged):
        brave.parse_response(payload)
    f = _check(FakeHttp(Resp(200, payload)))
    assert f.status is Status.ERROR and f.error_kind == "schema_changed"


@pytest.mark.parametrize("payload", [
    {"type": "search", "query": {"original": "x", "more_results_available": False}},     # bez sekcji web
    {"type": "search", "query": {"original": "x"}, "web": {"type": "search", "results": []}},
    {"query": {"original": "x"}, "web": {"results": []}},                                # type nieobecny
])
def test_valid_zero_results_stays_not_found(payload):
    assert brave.parse_response(payload).results == []
    assert _check(FakeHttp(Resp(200, payload))).status is Status.NOT_FOUND


def test_mixed_records_keep_valid_and_count_broken():
    """Zachowanie jawne: poprawne rekordy przechodzą, uszkodzone są liczone; pola opisowe złego typu = pusty tekst."""
    payload = {"type": "search", "query": {"original": "x"}, "web": {"results": [
        {"url": "https://www.facebook.com/jan.testowy.1", "title": ["nie", "tekst"], "description": 5},
        {"title": "bez url"}, "śmieć", {"url": "https://x.example/\x07"}]}}
    parsed = brave.parse_response(payload)
    assert [r["url"] for r in parsed.results] == ["https://www.facebook.com/jan.testowy.1"]
    assert parsed.results[0]["title"] == "" and parsed.results[0]["snippet"] == "" and parsed.skipped == 3
    f = _check(FakeHttp(Resp(200, payload)))
    assert f.status is Status.FOUND and f.extra["skipped_records"] == 3 and "uszkodzone rekordy: 3" in f.evidence
    assert brave.parse_results(PAYLOAD)[0] and brave.parse_response(PAYLOAD).skipped == 2


# --- R5A: rzeczywisty termin transportu (zegar rzeczywisty, lokalny serwer, zero ruchu na zewnątrz) -------------

import socket  # noqa: E402
import threading  # noqa: E402
import time  # noqa: E402

from osint_connectors.http import ABORT_GRACE  # noqa: E402

MARGIN = 1.5            # zapas na powolny Windows / obciążoną maszynę; wciąż dużo mniej niż blokada serwera
BLOCK = 8.0             # tyle serwer trzymałby połączenie bez przerwania


class LocalServer:
    """Kontrolowany serwer na 127.0.0.1: tryby 'ok', 'drip' (nagłówki, potem bajt co 50 ms), 'silent' (nic)."""

    def __init__(self, *modes):
        self.modes, self.requests, self.closed_early = list(modes), [], threading.Event()
        self.sock = socket.socket()
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen(8)
        self.port = self.sock.getsockname()[1]
        threading.Thread(target=self._loop, daemon=True).start()

    def _loop(self):
        while True:
            try:
                conn, _ = self.sock.accept()
            except OSError:
                return
            threading.Thread(target=self._serve, args=(conn,), daemon=True).start()

    def _serve(self, conn):
        with conn:
            head = conn.recv(65536).decode("latin-1")
            self.requests.append(head.split("\r\n", 1)[0])
            mode = self.modes[min(len(self.requests), len(self.modes)) - 1]
            if mode == "ok":
                body = json.dumps({"type": "search", "query": {"original": "x"}, "web": {"results": [
                    {"url": "https://www.facebook.com/jan.testowy.7", "title": "Jan Testowy", "description": "x"}]}})
                conn.sendall(b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: "
                             + str(len(body)).encode() + b"\r\n\r\n" + body.encode())
                return
            if mode == "drip":
                conn.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 100000\r\n\r\n")
            conn.settimeout(0.05)
            end = time.monotonic() + BLOCK
            while time.monotonic() < end:
                try:
                    if mode == "drip":
                        conn.sendall(b" ")
                    if conn.recv(1) == b"":         # klient zamknął połączenie: przerwanie dotarło do gniazda
                        self.closed_early.set()
                        return
                except socket.timeout:
                    continue
                except OSError:
                    self.closed_early.set()
                    return

    def close(self):
        self.sock.close()


def _http_threads():
    return [t for t in threading.enumerate() if t.name == "osint-connectors-http" and t.is_alive()]


@pytest.mark.parametrize("mode", ["silent", "drip"])
def test_urllib_client_total_deadline_aborts_blocking_and_slow_reads(mode):
    srv = LocalServer(mode)
    try:
        started = time.monotonic()
        with pytest.raises(ConnectorTimeout):
            asyncio.run(UrllibClient().get(f"http://127.0.0.1:{srv.port}/x", timeout=0.6))
        elapsed = time.monotonic() - started
        assert 0.55 <= elapsed < 0.6 + ABORT_GRACE + MARGIN
        assert srv.closed_early.wait(MARGIN), "serwer nie zobaczył zamknięcia: transport nadal czytał"
        assert not _http_threads()                  # brak pracy w tle po zakończeniu
    finally:
        srv.close()


def test_runner_cancellation_also_aborts_transport():
    """Runner (wait_for z ctx.timeout) anuluje coroutine: transport też musi się przerwać, nie tylko coroutine."""
    srv = LocalServer("silent")

    class Local:     # ten sam transport stdlib, adres podmieniony na lokalny serwer (bez ruchu na zewnątrz)
        def __init__(self):
            self.client = UrllibClient()

        async def get(self, url, *, headers=None, timeout=None):
            return await self.client.get(f"http://127.0.0.1:{srv.port}/?{urlsplit(url).query}", headers=headers,
                                         timeout=timeout + 5)    # transport dłużej niż runner: decyduje anulowanie
    try:
        started = time.monotonic()
        f = _check(Local())
        assert f.error_kind == "timeout" and time.monotonic() - started < 1.0 + ABORT_GRACE + MARGIN
        assert srv.closed_early.wait(MARGIN) and not _http_threads()
    finally:
        srv.close()


def test_urllib_client_normal_response_and_size_limit_still_work():
    srv = LocalServer("ok")
    try:
        resp = asyncio.run(UrllibClient().get(f"http://127.0.0.1:{srv.port}/", headers={"X-Subscription-Token": KEY},
                                              timeout=5))
        assert resp.status_code == 200 and resp.json()["web"]["results"][0]["url"].endswith("jan.testowy.7")
        with pytest.raises(Exception) as info:
            asyncio.run(UrllibClient(max_bytes=10).get(f"http://127.0.0.1:{srv.port}/", timeout=5))
        assert "limit rozmiaru" in str(info.value)
    finally:
        srv.close()
