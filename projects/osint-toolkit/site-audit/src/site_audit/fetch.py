"""Klient HTTP(S) z budzetem czasu, limitem rozmiaru i kontrola kazdego skoku przekierowania.

Wzorzec web-check, ale bez jego slabosci: jeden wspolny budzet (gniazdo dostaje
min(timeout, pozostaly budzet) przed kazda operacja), osobne rodzaje bledow zamiast
pustego wyniku, rezolucja + straznik adresow dla kazdego skoku.
"""

from __future__ import annotations

import http.client
import socket
import ssl
import threading
import time
from dataclasses import dataclass, field
from typing import Callable
from urllib.parse import urljoin

from . import __version__
from .target import BlockedAddress, Resolver, Target, TargetError, parse_target, resolve_checked, system_resolver

USER_AGENT = f"site-audit/{__version__} (audyt konfiguracji strony)"
REDIRECT_CODES = (301, 302, 303, 307, 308)


class FetchError(Exception):
    def __init__(self, kind: str, message: str):
        super().__init__(message)
        self.kind = kind  # blocked | invalid | timeout | budget | tls | network | redirects


@dataclass
class TlsInfo:
    version: str | None = None
    cipher: str | None = None
    cert: dict | None = None            # getpeercert() po poprawnej weryfikacji
    verify_error: str | None = None     # blad weryfikacji certyfikatu (wtedy cert=None)


@dataclass
class Response:
    url: str
    status: int
    reason: str
    headers: list[tuple[str, str]]
    body: bytes = b""
    truncated: bool = False
    ip: str = ""
    tls: TlsInfo | None = None

    def header(self, name: str) -> str | None:
        n = name.lower()
        for k, v in self.headers:
            if k.lower() == n:
                return v
        return None

    def header_all(self, name: str) -> list[str]:
        n = name.lower()
        return [v for k, v in self.headers if k.lower() == n]

    def text(self) -> str:
        charset = "utf-8"
        ctype = self.header("content-type") or ""
        for part in ctype.split(";")[1:]:
            k, _, v = part.strip().partition("=")
            if k.lower() == "charset" and v:
                charset = v.strip("\"' ")
        try:
            return self.body.decode(charset, errors="replace")
        except (LookupError, UnicodeError, ValueError, TypeError):  # kodek wskazany przez serwer
            return self.body.decode("utf-8", errors="replace")


@dataclass
class Hop:
    url: str
    status: int | None
    location: str | None = None
    tls_error: str | None = None    # blad weryfikacji certyfikatu na tym skoku


@dataclass
class FetchResult:
    url: str
    chain: list[Hop] = field(default_factory=list)
    response: Response | None = None
    error: str | None = None
    error_kind: str | None = None

    @property
    def ok(self) -> bool:
        return self.response is not None


class Deadline:
    def __init__(self, seconds: float, clock=time.monotonic):
        self._clock = clock
        self._end = clock() + seconds

    def remaining(self) -> float:
        return self._end - self._clock()


class _PinnedHTTP(http.client.HTTPConnection):
    def __init__(self, host: str, port: int, ip: str, timeout: float):
        super().__init__(host, port, timeout=timeout)
        self._ip = ip
        self.raw_sock: socket.socket | None = None

    def connect(self):
        self.sock = self.raw_sock = socket.create_connection((self._ip, self.port), self.timeout)


class _PinnedHTTPS(http.client.HTTPSConnection):
    def __init__(self, host: str, port: int, ip: str, timeout: float, context: ssl.SSLContext):
        super().__init__(host, port, timeout=timeout, context=context)
        self._ip = ip
        self.raw_sock: socket.socket | None = None

    def connect(self):
        raw = self.raw_sock = socket.create_connection((self._ip, self.port), self.timeout)
        try:
            self.sock = self._context.wrap_socket(raw, server_hostname=self.host)
        except BaseException:
            raw.close()
            raise


def _verified_context() -> ssl.SSLContext:
    return ssl.create_default_context()


def _unverified_context() -> ssl.SSLContext:
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx


class Fetcher:
    def __init__(
        self,
        timeout: float = 8.0,
        budget: float = 60.0,
        max_bytes: int = 2_000_000,
        allow_private: bool = False,
        resolver: Resolver = system_resolver,
        user_agent: str = USER_AGENT,
        clock=time.monotonic,
    ):
        self.timeout = timeout
        self.deadline = Deadline(budget, clock)
        self.max_bytes = max_bytes
        self.allow_private = allow_private
        self.resolver = resolver
        self.user_agent = user_agent
        self.requests = 0

    # -- publiczne ---------------------------------------------------------
    def get(self, url: str | Target, follow: bool = True, max_redirects: int = 10,
            scope: Callable[[Target], bool] | None = None) -> FetchResult:
        """scope: dozwolone cele przekierowan, sprawdzane PRZED zadaniem (poza zakresem -> 'offhost')."""
        try:
            target = url if isinstance(url, Target) else parse_target(url)
        except TargetError as exc:
            return FetchResult(str(url), error=str(exc), error_kind="invalid")
        result = FetchResult(target.url)
        seen: set[str] = set()
        while True:
            if target.url in seen:
                result.error, result.error_kind = f"pętla przekierowań na {target.url}", "redirects"
                return result
            seen.add(target.url)
            if scope is not None and result.chain and not scope(target):
                result.error, result.error_kind = f"przekierowanie poza zakres ({target.url})", "offhost"
                return result
            try:
                resp = self._one(target)
            except FetchError as exc:
                result.chain.append(Hop(target.url, None))
                result.error, result.error_kind = str(exc), exc.kind
                return result
            location = resp.header("location")
            result.chain.append(Hop(target.url, resp.status, location,
                                    resp.tls.verify_error if resp.tls is not None else None))
            if not (follow and resp.status in REDIRECT_CODES and location):
                result.response = resp
                return result
            if len(result.chain) > max_redirects:
                result.error, result.error_kind = f"więcej niż {max_redirects} przekierowań", "redirects"
                return result
            try:
                target = parse_target(urljoin(target.url, location.strip()))
            except (TargetError, ValueError) as exc:
                result.error, result.error_kind = f"przekierowanie na nieprawidłowy adres: {exc}", "invalid"
                return result

    # -- wewnetrzne --------------------------------------------------------
    def _op_timeout(self) -> float:
        left = self.deadline.remaining()
        if left <= 0:
            raise FetchError("budget", "wyczerpany budżet czasu audytu")
        return max(0.05, min(self.timeout, left))

    def _resolve(self, target: Target) -> list[str]:
        """Rezolucja w watku z limitem: getaddrinfo nie ma timeoutu i nie da sie go przerwac."""
        box: dict = {}

        def work():
            try:
                box["ips"] = resolve_checked(target.host, target.port, self.resolver, self.allow_private)
            except BaseException as exc:  # przekazywane do watku glownego
                box["exc"] = exc

        t = threading.Thread(target=work, daemon=True)
        t.start()
        t.join(self._op_timeout())
        if t.is_alive():
            if self.deadline.remaining() <= 0:
                raise FetchError("budget", "wyczerpany budżet czasu audytu (DNS)")
            raise FetchError("timeout", f"przekroczony czas rozwiązywania nazwy {target.host}")
        exc = box.get("exc")
        if isinstance(exc, BlockedAddress):
            raise FetchError("blocked", str(exc)) from exc
        if isinstance(exc, TargetError):
            raise FetchError("network", str(exc)) from exc
        if exc is not None:
            raise exc
        return box["ips"]

    def _one(self, target: Target) -> Response:
        self._op_timeout()
        ips = self._resolve(target)
        last: FetchError | None = None
        for ip in ips:
            try:
                return self._request(target, ip)
            except FetchError as exc:
                if exc.kind in ("budget", "tls"):
                    raise
                last = exc
        assert last is not None
        raise last

    def _request(self, target: Target, ip: str) -> Response:
        tls = None
        if target.scheme == "https":
            try:
                return self._send(target, ip, _verified_context(), TlsInfo())
            except ssl.SSLCertVerificationError as exc:
                tls = TlsInfo(verify_error=exc.verify_message or str(exc))
            except ssl.SSLError as exc:
                raise FetchError("tls", f"błąd TLS: {exc}") from exc
            # obserwacja odpowiedzi mimo zlego certyfikatu (bez zaufania do niej)
            try:
                return self._send(target, ip, _unverified_context(), tls)
            except ssl.SSLError as exc:
                raise FetchError("tls", f"błąd TLS: {exc}") from exc
        return self._send(target, ip, None, None)

    def _send(self, target: Target, ip: str, ctx: ssl.SSLContext | None, tls: TlsInfo | None) -> Response:
        timeout = self._op_timeout()
        conn = _PinnedHTTPS(target.host, target.port, ip, timeout, ctx) if ctx else _PinnedHTTP(target.host, target.port, ip, timeout)
        self.requests += 1
        # Twardy termin: po wyczerpaniu budzetu gniazdo jest zamykane, takze w trakcie naglowkow,
        # ramek chunked i trailerow (timeout gniazda ogranicza tylko pojedynczy recv).
        killed = threading.Event()

        def kill():
            killed.set()
            if conn.raw_sock is not None:
                try:
                    conn.raw_sock.shutdown(socket.SHUT_RDWR)
                except OSError:
                    pass

        watchdog = threading.Timer(max(0.0, self.deadline.remaining()), kill)
        watchdog.daemon = True
        watchdog.start()
        try:
            conn.request("GET", target.path, headers={
                "User-Agent": self.user_agent,
                "Accept": "text/html,application/xhtml+xml,text/plain,application/xml;q=0.9,*/*;q=0.5",
                "Accept-Encoding": "identity",
                "Connection": "close",
            })
            if tls is not None and isinstance(conn.sock, ssl.SSLSocket):
                tls.version = conn.sock.version()
                c = conn.sock.cipher()
                tls.cipher = c[0] if c else None
                if tls.verify_error is None:
                    tls.cert = conn.sock.getpeercert() or None
            resp = conn.getresponse()
            # przy "Connection: close" conn.sock jest juz zamkniete; gniazdo zyje w strumieniu odpowiedzi
            sock = getattr(getattr(resp.fp, "raw", None), "_sock", None)
            body, truncated = self._read(sock, resp, killed)
            if killed.is_set():
                raise FetchError("budget", "wyczerpany budżet czasu audytu (w trakcie odczytu)")
            return Response(target.url, resp.status, resp.reason, list(resp.getheaders()), body, truncated, ip, tls)
        except FetchError:
            raise
        except Exception as exc:
            if killed.is_set():
                raise FetchError("budget", "wyczerpany budżet czasu audytu (w trakcie odczytu)") from exc
            if isinstance(exc, ssl.SSLError):
                raise
            if isinstance(exc, TimeoutError):
                raise FetchError("timeout", f"przekroczony czas ({target.url})") from exc
            if isinstance(exc, (OSError, http.client.HTTPException)):
                raise FetchError("network", f"błąd połączenia z {target.url}: {exc}") from exc
            raise
        finally:
            watchdog.cancel()
            conn.close()

    def _read(self, sock, resp, killed: threading.Event) -> tuple[bytes, bool]:
        chunks: list[bytes] = []
        size = 0
        while size <= self.max_bytes:
            timeout = self._op_timeout()
            if sock is not None:
                try:
                    sock.settimeout(timeout)
                except OSError:
                    sock = None
            try:
                # read1: tyle, ile juz przyszlo (read() czekalby na pelny bufor i omijal budzet)
                chunk = resp.read1(min(65536, self.max_bytes + 1 - size))
            except (http.client.IncompleteRead, ConnectionError, TimeoutError) as exc:
                if killed.is_set() or self.deadline.remaining() <= 0:
                    raise FetchError("budget", "wyczerpany budżet czasu audytu (w trakcie odczytu)") from exc
                # naglowki juz sa; urwana tresc nie przekresla audytu, tylko jest niepelna
                partial = getattr(exc, "partial", b"") or b""
                return (b"".join(chunks) + partial)[: self.max_bytes], True
            if not chunk:
                break
            chunks.append(chunk)
            size += len(chunk)
        body = b"".join(chunks)
        if len(body) > self.max_bytes:
            return body[: self.max_bytes], True
        return body, False
