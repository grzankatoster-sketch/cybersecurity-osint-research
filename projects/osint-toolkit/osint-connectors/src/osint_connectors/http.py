"""Minimalna abstrakcja klienta HTTP dla konektorów.

Konektory nie tworzą własnego klienta — dostają go przez ``Context.http``. Dzięki
temu testy wstrzykują atrapę i nie wykonują żadnego ruchu sieciowego, a rdzeń
pozostaje niezależny od konkretnej biblioteki. Domyślny adapter na ``httpx`` jest
ładowany leniwie (import dopiero przy użyciu), więc sam rdzeń nie wymaga httpx.
"""
from __future__ import annotations

import asyncio as _asyncio
import base64 as _b64
import http.client as _http
import json as _json
import socket as _socket
import threading as _threading
import time as _time
import urllib.error as _error
import urllib.parse as _urlparse
import urllib.request as _request
from typing import Any, Mapping, Optional, Protocol, runtime_checkable

# Po upływie terminu wątek transportu dostaje sygnał przerwania (shutdown gniazda); tyle czekamy na jego koniec.
ABORT_GRACE = 0.1


@runtime_checkable
class HttpResponse(Protocol):
    status_code: int

    def json(self) -> Any:
        ...

    @property
    def text(self) -> str:
        ...


@runtime_checkable
class HttpClient(Protocol):
    async def get(
        self,
        url: str,
        *,
        headers: Optional[Mapping[str, str]] = None,
        timeout: Optional[float] = None,
    ) -> HttpResponse:
        ...


class HttpxClient:
    """Adapter na ``httpx.AsyncClient``. Import httpx dopiero przy tworzeniu.

    Używany wyłącznie w produkcji; w testach wstrzykuje się atrapę. Ten pakiet
    nie uruchamia go samoczynnie.
    """

    def __init__(self, **kwargs: Any) -> None:
        import httpx  # leniwie — rdzeń nie zależy od httpx

        self._client = httpx.AsyncClient(**kwargs)

    async def get(self, url, *, headers=None, timeout=None):
        return await self._client.get(url, headers=dict(headers or {}), timeout=timeout)

    async def aclose(self) -> None:
        await self._client.aclose()


class UrllibResponse:
    """Odpowiedź :class:`UrllibClient` zgodna z protokołem :class:`HttpResponse` (plus nagłówki)."""

    def __init__(self, status_code: int, body: bytes, headers: Mapping[str, str]) -> None:
        self.status_code = status_code
        self._body = body
        self.headers = {k.lower(): v for k, v in headers.items()}

    @property
    def text(self) -> str:
        return self._body.decode("utf-8", errors="replace")

    def json(self) -> Any:
        return _json.loads(self._body.decode("utf-8"))   # ValueError przy złym JSON / kodowaniu


class _NoRedirect(_request.HTTPRedirectHandler):
    """Bez przekierowań: nagłówki z kluczem API nie mogą trafić pod inny adres. 3xx zostaje odpowiedzią."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: D102
        return None


class _PinnedProxy(_request.BaseHandler):
    """Trasa przypięta do jednego proxy HTTP (tunel CONNECT do celu HTTPS). W przeciwieństwie do ProxyHandler nie obowiązują
    NO_PROXY ani wyjątki systemowe; żądanie bez tunelu przez to proxy jest blokowane (fail-closed)."""

    handler_order = 100

    def __init__(self, proxy: str) -> None:
        parts = _urlparse.urlsplit(proxy)
        try:
            port = parts.port
        except ValueError:
            port = None
        if parts.scheme != "http" or not parts.hostname or port is None or parts.path not in ("", "/"):
            raise ValueError("proxy: oczekiwane http://host:port")
        self.scheme = parts.scheme
        self.hostport = parts.netloc.rpartition("@")[2]
        self.auth = None
        if parts.username is not None:
            creds = f"{_urlparse.unquote(parts.username)}:{_urlparse.unquote(parts.password or '')}"
            self.auth = "Basic " + _b64.b64encode(creds.encode("utf-8")).decode("ascii")

    def https_open(self, req):
        if req.has_proxy() or getattr(req, "_tunnel_host", None):
            raise _error.URLError("żądanie ma już inną trasę proxy - zablokowane")
        if self.auth:
            req.add_header("Proxy-authorization", self.auth)
        req.set_proxy(self.hostport, self.scheme)
        if req.host != self.hostport or not getattr(req, "_tunnel_host", None):
            raise _error.URLError("trasa z pominięciem proxy zablokowana")
        return None

    def http_open(self, req):
        raise _error.URLError("przez proxy wysyłane są tylko zapytania HTTPS")


class Deadline:
    """Całkowity termin jednego żądania i sygnał przerwania dla wątku transportu.

    Timeout gniazda dotyczy pojedynczej operacji, więc sam nie ogranicza powolnej odpowiedzi. Tu: każde łączenie
    dostaje najwyżej pozostały czas, a ``abort()`` (po terminie albo przy anulowaniu) robi ``shutdown`` wszystkich
    gniazd żądania, co natychmiast przerywa zablokowany odczyt w drugim wątku. Po ``abort()`` żaden kolejny krok
    (połączenie, wysłanie) się nie zaczyna. Jedyny krok bez możliwości przerwania to systemowe rozwiązywanie nazwy
    (getaddrinfo); po nim wątek sprawdza sygnał i kończy bez ruchu sieciowego.
    """

    def __init__(self, seconds: float) -> None:
        self.at = _time.monotonic() + seconds
        self._lock = _threading.Lock()
        self._socks: list = []
        self.aborted = False
        self.finished = False

    def remaining(self) -> float:
        return self.at - _time.monotonic()

    def check(self) -> None:
        from .errors import ConnectorTimeout
        if self.aborted or self.remaining() <= 0:
            raise ConnectorTimeout("przekroczono limit czasu")

    def register(self, sock) -> None:
        with self._lock:
            if self.aborted:
                _shutdown(sock)
            else:
                self._socks.append(sock)
        self.check()

    def abort(self) -> None:
        with self._lock:
            self.aborted = True
            socks = [] if self.finished else list(self._socks)
        for sock in socks:
            _shutdown(sock)

    def finish(self) -> None:
        with self._lock:
            self.finished = True
            self._socks.clear()


def _shutdown(sock) -> None:
    # Zamknięty albo odłączony obiekt gniazda ma fileno -1: OSError, nigdy cudzy deskryptor.
    try:
        _socket.socket.shutdown(sock, _socket.SHUT_RDWR)
    except OSError:
        pass


def _connect(address, deadline: Deadline, source_address=None):
    """socket.create_connection z terminem: każda próba (adres IPv4/IPv6) najwyżej pozostały czas."""
    host, port = address
    err = None
    for family, kind, proto, _, addr in _socket.getaddrinfo(host, port, 0, _socket.SOCK_STREAM):
        deadline.check()
        sock = _socket.socket(family, kind, proto)
        try:
            deadline.register(sock)
            sock.settimeout(max(0.001, deadline.remaining()))
            if source_address:
                sock.bind(source_address)
            sock.connect(addr)
            return sock
        except OSError as exc:
            err = exc
            sock.close()
        except BaseException:
            sock.close()
            raise
    if err is not None:
        raise err
    raise OSError("getaddrinfo: brak adresów")


def _connection_class(base, deadline: Deadline):
    """Klasa połączenia http.client z gniazdami rejestrowanymi w terminie (TLS: rejestracja PRZED uzgadnianiem)."""

    class _Conn(base):
        def __init__(self, *args, **kwargs):
            super().__init__(*args, **kwargs)
            self._create_connection = lambda addr, timeout=None, source=None: _connect(addr, deadline, source)

        def connect(self):
            if not isinstance(self, _http.HTTPSConnection):
                return super().connect()
            _http.HTTPConnection.connect(self)          # gniazdo (+ tunel CONNECT przez proxy)
            server_hostname = self._tunnel_host or self.host
            self.sock = self._context.wrap_socket(self.sock, server_hostname=server_hostname,
                                                  do_handshake_on_connect=False)
            deadline.register(self.sock)
            self.sock.settimeout(max(0.001, deadline.remaining()))
            self.sock.do_handshake()

    return _Conn


class _DeadlineHTTPS(_request.HTTPSHandler):
    def https_open(self, req):
        deadline = getattr(req, "osint_deadline", None)
        base = _http.HTTPSConnection if deadline is None else _connection_class(_http.HTTPSConnection, deadline)
        return self.do_open(base, req, context=self._context)


class _DeadlineHTTP(_request.HTTPHandler):
    def http_open(self, req):
        deadline = getattr(req, "osint_deadline", None)
        base = _http.HTTPConnection if deadline is None else _connection_class(_http.HTTPConnection, deadline)
        return self.do_open(base, req)


class UrllibClient:
    """Produkcyjny klient na samej bibliotece standardowej (własny wątek na żądanie, twardy termin).

    * ``timeout`` to CAŁKOWITY termin żądania (łączenie, TLS, nagłówki i treść), nie timeout pojedynczej operacji
      gniazda: po terminie gniazda są zamykane (shutdown), wątek kończy się, a wołający dostaje ConnectorTimeout
      najpóźniej po ``timeout + ABORT_GRACE``. Anulowanie coroutine też przerywa transport;
    * bez przekierowań (klucz w nagłówku nie wychodzi poza wskazany host), limit rozmiaru odpowiedzi;
    * ``proxy=None``: połączenie bezpośrednie albo proxy systemowe (jak reszta narzędzi stdlib);
    * ``proxy="http://host:port"``: WYŁĄCZNIE przez to proxy (CONNECT), tylko HTTPS; niedostępne proxy = błąd,
      nigdy połączenie bezpośrednie. Błędny adres proxy -> ValueError już przy tworzeniu (zero ruchu).

    Błędy transportu są typowane (:class:`ConnectorTimeout`, :class:`TransportError`) i nie zawierają adresu
    żądania ani nagłówków (adres może zawierać zapytanie, nagłówki: klucz).
    """

    def __init__(self, *, proxy: Optional[str] = None, max_bytes: int = 2_000_000,
                 user_agent: str = "osint-connectors/0.1 (autoryzowany OSINT)") -> None:
        self.proxy = proxy
        self.max_bytes = max_bytes
        self.user_agent = user_agent
        route = _PinnedProxy(proxy) if proxy else _request.ProxyHandler()
        opener = _request.OpenerDirector()
        handlers = [route, _DeadlineHTTPS(), _request.HTTPDefaultErrorHandler(), _NoRedirect(),
                    _request.HTTPErrorProcessor(), _request.UnknownHandler()]
        if not proxy:
            handlers.append(_DeadlineHTTP())
        for handler in handlers:
            opener.add_handler(handler)
        self._opener = opener

    def _read(self, fp) -> bytes:
        data = fp.read(self.max_bytes + 1) if fp is not None else b""
        if len(data) > self.max_bytes:
            from .errors import ParseError
            raise ParseError("odpowiedź przekracza limit rozmiaru")
        return data

    def _get_sync(self, url: str, headers: Mapping[str, str], timeout: float,
                  deadline: Optional[Deadline] = None) -> UrllibResponse:
        from .errors import TransportError

        if _urlparse.urlsplit(url).scheme not in ("http", "https"):
            raise TransportError("niedozwolony schemat adresu (tylko http/https)")
        timer = None
        if deadline is None:               # wywołanie bez get(): termin pilnuje własny zegar przerwania
            deadline = Deadline(timeout)
            timer = _threading.Timer(max(0.0, timeout), deadline.abort)
            timer.daemon = True
            timer.start()
        try:
            return self._fetch(url, headers, deadline)
        finally:
            if timer is not None:
                timer.cancel()
                deadline.finish()

    def _fetch(self, url: str, headers: Mapping[str, str], deadline: Deadline) -> UrllibResponse:
        from .errors import ConnectorTimeout, TransportError

        req = _request.Request(url, headers={"User-Agent": self.user_agent, **dict(headers)})
        req.osint_deadline = deadline
        via = " przez proxy (bez połączenia bezpośredniego)" if self.proxy else ""
        try:
            deadline.check()
            with self._opener.open(req, timeout=max(0.001, deadline.remaining())) as resp:
                result = UrllibResponse(resp.status, self._read(resp), dict(resp.headers.items()))
        except _error.HTTPError as exc:
            try:
                result = UrllibResponse(exc.code, self._read(exc.fp), dict(exc.headers.items()) if exc.headers else {})
            except OSError:
                result = None
            finally:
                exc.close()
            if result is None and not deadline.aborted:
                raise TransportError(f"błąd sieci przy odczycie odpowiedzi{via}") from None
        except ConnectorTimeout:
            raise ConnectorTimeout("przekroczono limit czasu" + via) from None
        except (_error.URLError, OSError, _http.HTTPException) as exc:
            reason = getattr(exc, "reason", exc)
            if deadline.aborted or isinstance(reason, (TimeoutError, _socket.timeout)) \
                    or isinstance(exc, (TimeoutError, _socket.timeout)):
                raise ConnectorTimeout("przekroczono limit czasu" + via) from None
            raise TransportError(f"błąd sieci ({type(reason).__name__}){via}") from None
        # Przerwana treść (shutdown po terminie) może wyglądać na krótszą odpowiedź: nigdy nie jest wynikiem.
        if deadline.aborted or deadline.remaining() <= 0:
            raise ConnectorTimeout("przekroczono limit czasu" + via)
        return result

    async def get(self, url, *, headers=None, timeout=None):
        """Żądanie w osobnym wątku demona (nie w domyślnej puli: ``asyncio.run`` nie czeka na nią przy zamknięciu).
        Po terminie albo anulowaniu: przerwanie transportu i krótkie oczekiwanie na koniec wątku."""
        from .errors import ConnectorTimeout

        budget = float(timeout or 10.0)
        deadline = Deadline(budget)
        loop = _asyncio.get_running_loop()
        done = loop.create_future()

        def deliver(ok: bool, value) -> None:
            if not done.done():
                (done.set_result if ok else done.set_exception)(value)

        def work() -> None:
            try:
                outcome = (True, self._get_sync(url, dict(headers or {}), budget, deadline))
            except BaseException as exc:  # noqa: BLE001 - przekazywane do pętli bez zmiany
                outcome = (False, exc)
            finally:
                deadline.finish()
            try:
                loop.call_soon_threadsafe(deliver, *outcome)
            except RuntimeError:            # pętla już zamknięta: wołający dawno dostał timeout
                pass

        worker = _threading.Thread(target=work, name="osint-connectors-http", daemon=True)
        worker.start()
        try:
            # wait_for anuluje `done` po terminie: spóźniony wynik wątku jest wtedy pomijany w deliver()
            return await _asyncio.wait_for(done, max(0.0, deadline.remaining()))
        except _asyncio.TimeoutError:
            deadline.abort()
            worker.join(ABORT_GRACE)
            raise ConnectorTimeout("przekroczono limit czasu" + (" przez proxy (bez połączenia bezpośredniego)"
                                                                 if self.proxy else "")) from None
        except _asyncio.CancelledError:
            deadline.abort()
            worker.join(ABORT_GRACE)
            raise
