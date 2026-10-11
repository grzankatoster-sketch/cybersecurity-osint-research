"""Klient HTTP: systemowy resolver DNS (bez aiodns — działa na Windowsie), limit na domenę,
ponawianie z backoffem i Retry-After. Każdy problem kończy się Response z polem error, nigdy wyjątkiem.

Bezpieczeństwo (baza serwisów jest niezaufanym wejściem):
- cele tylko publiczne: żądania i przekierowania na adresy loopback/prywatne/link-local/multicast/zarezerwowane
  są blokowane (adres sprawdzany po rozwiązaniu DNS, w resolverze połączenia, oraz dla hostów będących literałem IP);
- dozwolone metody: GET, HEAD, POST; przekierowania obsługujemy sami (limit, kontrola celu na każdym skoku);
- błąd certyfikatu TLS: ponowienie bez weryfikacji (świadoma decyzja: ok. 65 serwisów ma zepsute certyfikaty),
  wynik jest oznaczony `insecure` — silnik ogranicza jego pewność. `strict_tls=True` wyłącza ponowienie.

OPSEC (proxy = adres SOCKS5, np. Tor):
- nazwy domen rozwiązuje proxy (socks5/socks5h, rdns), lokalny DNS nie jest nigdy odpytywany o cele;
- awaria proxy to Response z błędem, nigdy cichy powrót do ruchu bezpośredniego;
- przez proxy nie ponawiamy bez weryfikacji TLS (wyjście Tora może podmienić certyfikat), chyba że jawnie
  `allow_insecure_retry=True`;
- bez własnych danych logowania w adresie każdy Fetcher dostaje losowy login SOCKS (Tor IsolateSOCKSAuth =
  osobny obwód); adresu proxy z danymi logowania nie wypisujemy (`proxy_label`)."""
from __future__ import annotations

import asyncio
import ipaddress
import json
import math
import random
import secrets
import socket
import ssl as ssl_module
from dataclasses import dataclass
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
from urllib.parse import quote, unquote, urlsplit

import aiohttp
import aiohttp_socks
import python_socks
from aiohttp.abc import AbstractResolver
from yarl import URL

from .models import Response

DEFAULT_UA = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36"
)
MAX_BODY = 2_000_000
MAX_REDIRECTS = 5
MAX_RETRY_WAIT = 60.0          # dłuższy Retry-After = ERROR „limit zapytań” zamiast czekania
RATE_LIMIT_MAX_WAIT = 30.0     # 429 (np. Reddit): czekamy najwyżej tyle i ponawiamy tylko raz
RATE_LIMIT_RETRIES = 1
RETRY_STATUSES = {429, 502, 503, 504}
REDIRECT_STATUSES = {301, 302, 303, 307, 308}
ALLOWED_METHODS = frozenset({"GET", "HEAD", "POST"})
DNS_ERROR = "DNS: domena nie istnieje"
DNS_TEMP = "DNS: błąd przejściowy"
BLOCKED_PREFIX = "zablokowany cel"
PROXY_PREFIX = "proxy: "
PROXY_DOWN = PROXY_PREFIX + "brak połączenia z proxy"          # proxy martwe: nie ponawiamy, nie młotkujemy
PROXY_UNREACHABLE = PROXY_PREFIX + "host nieosiągalny"          # SOCKS: host/sieć nieosiągalne albo ogólna awaria
PROXY_REFUSED = PROXY_PREFIX + "połączenie odrzucone przez cel"
PROXY_NOT_ALLOWED = PROXY_PREFIX + "połączenie niedozwolone przez proxy"
PROXY_TIMEOUT = PROXY_PREFIX + "timeout"
TLS_NO_RETRY = "certyfikat: weryfikacja TLS nieudana (bez ponowienia przez proxy)"
SOCKS_SCHEMES = ("socks5", "socks5h")
# nazwy, których nie wysyłamy do proxy (wewnętrzne / lokalne / ukryte usługi: poza zakresem skanu)
_BLOCKED_HOST_SUFFIXES = (".localhost", ".local", ".internal", ".onion")
TOR_CHECK_URL = "https://check.torproject.org/api/ip"
BROWSER_HEADERS = {
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.9,pl;q=0.8",
}
# kody gaierror oznaczające trwały brak nazwy (Linux: EAI_NONAME/EAI_NODATA, Windows: WSAHOST_NOT_FOUND/WSANO_DATA)
_DNS_PERMANENT = {c for c in (getattr(socket, "EAI_NONAME", None), getattr(socket, "EAI_NODATA", None),
                              11001, 11004) if c is not None}


class BlockedTarget(OSError):
    """Cel żądania nie jest publicznym adresem."""


class TooManyRedirects(Exception):
    pass


def is_public_address(addr: str) -> bool:
    """Czy adres IP jest publiczny (nie loopback / prywatny / link-local / multicast / zarezerwowany)."""
    try:
        ip = ipaddress.ip_address(addr.strip("[]").split("%", 1)[0])
    except ValueError:
        return False
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped is not None:
        ip = ip.ipv4_mapped
    return not (ip.is_loopback or ip.is_private or ip.is_link_local or ip.is_multicast or ip.is_reserved
                or ip.is_unspecified or not ip.is_global)


# ---------------------------------------------------------------- proxy SOCKS (OPSEC)

def _split_proxy(url: str) -> tuple[str, str, int, str | None, str | None]:
    """Adres proxy -> (schemat, host, port, login, hasło). ValueError (bez danych logowania w treści) przy złym adresie."""
    if not isinstance(url, str) or not url.strip():
        raise ValueError("proxy: pusty adres (oczekiwano socks5://host:port albo socks5h://host:port)")
    try:
        parts = urlsplit(url.strip())
        scheme, host, port = parts.scheme.lower(), parts.hostname, parts.port
    except ValueError:
        raise ValueError("proxy: niepoprawny adres (oczekiwano socks5://host:port albo socks5h://host:port)") from None
    if scheme not in SOCKS_SCHEMES:
        raise ValueError(f"proxy: obsługiwany jest tylko SOCKS5 (socks5:// albo socks5h://), a nie "
                         f"{scheme + '://' if scheme else 'adres bez schematu'}; proxy HTTP przecieka DNS i nie jest wspierane")
    if not host:
        raise ValueError("proxy: brak hosta w adresie")
    if port is None:
        raise ValueError("proxy: brak portu w adresie (np. socks5h://127.0.0.1:9050)")
    user = unquote(parts.username) if parts.username is not None else None
    password = unquote(parts.password) if parts.password is not None else None
    return scheme, host, port, user, password


def validate_proxy(url: str) -> str:
    """Zwraca adres proxy (bez białych znaków), jeśli to socks5://host:port albo socks5h://host:port; inaczej ValueError."""
    _split_proxy(url)
    return url.strip()


def proxy_label(url: str | None) -> str:
    """schemat://host:port bez danych logowania: jedyna postać adresu proxy, jaką wolno wypisać albo zapisać."""
    if not url:
        return ""
    try:
        scheme, host, port, _, _ = _split_proxy(url)
    except ValueError:
        return "proxy"
    shown = f"[{host}]" if ":" in host else host
    return f"{scheme}://{shown}:{port}"


def _with_isolation(url: str, isolation: str | None) -> tuple[str, bool]:
    """Adres proxy gotowy dla aiohttp_socks (schemat socks5) + czy wstrzyknięto login izolacji obwodu.
    Własne dane logowania z adresu zostają; bez nich login = `isolation` (albo losowy), hasło „x”."""
    _, host, port, user, password = _split_proxy(url)
    injected = user is None
    if injected:
        user, password = isolation or secrets.token_hex(8), "x"
    shown = f"[{host}]" if ":" in host else host
    return f"socks5://{quote(user, safe='')}:{quote(password or '', safe='')}@{shown}:{port}", injected


def mask_ip(ip: str | None) -> str | None:
    """Adres wyjścia bez końcówki: IPv4 -> „185.220.x.x”, IPv6 -> pierwsze 2 grupy + „:...”."""
    if not ip:
        return None
    try:
        addr = ipaddress.ip_address(ip.strip().strip("[]"))
    except ValueError:
        return None
    if isinstance(addr, ipaddress.IPv4Address):
        a, b, *_ = str(addr).split(".")
        return f"{a}.{b}.x.x"
    return ":".join(f"{int(g, 16):x}" for g in addr.exploded.split(":")[:2]) + ":..."


def _blocked_proxy_host(host: str) -> bool:
    host = host.rstrip(".")
    return host == "localhost" or host.endswith(_BLOCKED_HOST_SUFFIXES)


def _proxy_error_text(exc: BaseException | None) -> str | None:
    """Błąd z aiohttp_socks / python_socks -> krótki opis „proxy: ...” (None = to nie błąd proxy).
    Przeszukuje też łańcuch przyczyn, bo aiohttp potrafi opakować wyjątek połączenia."""
    for _ in range(5):
        if exc is None:
            break
        if isinstance(exc, (aiohttp_socks.ProxyConnectionError, python_socks.ProxyConnectionError)):
            return PROXY_DOWN
        if isinstance(exc, (aiohttp_socks.ProxyTimeoutError, python_socks.ProxyTimeoutError)):
            return PROXY_TIMEOUT
        if isinstance(exc, (aiohttp_socks.ProxyError, python_socks.ProxyError)):
            code = getattr(exc, "error_code", None)
            if code in (1, 3, 4, 6):          # ogólna awaria, sieć/host nieosiągalne, TTL (RFC 1928)
                return PROXY_UNREACHABLE
            if code == 5:
                return PROXY_REFUSED
            if code == 2:
                return PROXY_NOT_ALLOWED
            return PROXY_PREFIX + (f"błąd SOCKS (kod {int(code)})" if code else "błąd protokołu SOCKS")
        exc = getattr(exc, "os_error", None) or exc.__cause__
    return None


def _is_cert_error(exc: BaseException | None) -> bool:
    """Błąd weryfikacji certyfikatu TLS: bezpośrednio (aiohttp) albo w łańcuchu przyczyn — przez SOCKS aiohttp
    opakowuje go w ClientOSError."""
    for _ in range(5):
        if exc is None:
            return False
        if isinstance(exc, (aiohttp.ClientConnectorCertificateError, ssl_module.SSLCertVerificationError)):
            return True
        exc = exc.__cause__
    return False


@dataclass
class PreflightResult:
    ok: bool
    is_tor: bool | None = None
    exit_ip_masked: str | None = None
    error: str | None = None


class SafeResolver(AbstractResolver):
    """Resolver systemowy, który odrzuca niepubliczne adresy — kontrola w chwili łączenia (odporna na DNS rebinding)."""

    def __init__(self, allow_private: bool = False, allow_hosts: tuple[str, ...] = ()):
        self._inner = aiohttp.ThreadedResolver()
        self.allow_private = allow_private
        self.allow_hosts = {h.lower() for h in allow_hosts}

    async def resolve(self, host: str, port: int = 0, family: socket.AddressFamily = socket.AF_INET):
        infos = await self._inner.resolve(host, port, family)
        if not self.allow_private and host.lower() not in self.allow_hosts:
            for info in infos:
                if not is_public_address(info["host"]):
                    raise BlockedTarget(f"{host} -> {info['host']}")
        return infos

    async def close(self) -> None:
        await self._inner.close()


def _parse_retry_after(value: str | None, now: datetime | None = None) -> float | None:
    """Retry-After w sekundach albo jako data HTTP -> sekundy od teraz (None = brak/nieczytelne)."""
    if not value or not value.strip():
        return None
    value = value.strip()
    try:
        seconds = float(value)
    except ValueError:
        try:
            when = parsedate_to_datetime(value)
        except (TypeError, ValueError):
            return None
        if when.tzinfo is None:
            when = when.replace(tzinfo=timezone.utc)
        seconds = (when - (now or datetime.now(timezone.utc))).total_seconds()
    if not math.isfinite(seconds):
        return None
    return max(0.0, seconds)


def retry_delay(attempt: int, retry_after: str | None = None, base: float = 1.0, cap: float = 10.0,
                max_wait: float = MAX_RETRY_WAIT, now: datetime | None = None) -> float | None:
    """Opóźnienie przed kolejną próbą (attempt liczony od 0): backoff wykładniczy (limit `cap`), a Retry-After
    (sekundy albo data) to MINIMUM. Retry-After dłuższy niż `max_wait` -> None (nie czekamy, wynik to ERROR)."""
    backoff = min(cap, base * (2 ** attempt))
    wait = _parse_retry_after(retry_after, now)
    if wait is None:
        return backoff
    if wait > max_wait:
        return None
    return max(backoff, wait)


class Fetcher:
    def __init__(
        self,
        timeout: float = 15.0,
        per_host: int = 2,
        total: int = 50,
        retries: int = 2,
        user_agent: str = DEFAULT_UA,
        proxy: str | None = None,
        jitter: bool = True,
        strict_tls: bool = False,
        allow_private: bool = False,
        allow_hosts: tuple[str, ...] = (),
        max_redirects: int = MAX_REDIRECTS,
        allow_insecure_retry: bool | None = None,
        isolation: str | None = None,
    ):
        """`proxy`: socks5:// albo socks5h:// (zdalny DNS); inny schemat = ValueError. `allow_insecure_retry`:
        domyślnie True bez proxy, False przez proxy. `isolation`: login SOCKS dla izolacji obwodu Tora (domyślnie
        losowy; ignorowany, gdy adres proxy ma własne dane logowania)."""
        self._proxy_url: str | None = None      # adres dla aiohttp_socks (z loginem izolacji) — nigdy nie wypisywany
        self.proxy: str | None = None           # etykieta bez danych logowania (do komunikatów)
        self.isolated = False
        if proxy:
            self._proxy_url, self.isolated = _with_isolation(validate_proxy(proxy), isolation)
            self.proxy = proxy_label(proxy)
        self.timeout = timeout
        self.per_host = per_host
        self.total = total
        self.retries = retries
        self.user_agent = user_agent
        self.jitter = jitter
        self.strict_tls = strict_tls
        self.allow_insecure_retry = (not self.proxy) if allow_insecure_retry is None else allow_insecure_retry
        self.allow_private = allow_private          # tylko testy lokalne / świadomy skan sieci wewnętrznej
        self.allow_hosts = tuple(h.lower() for h in allow_hosts)
        self.max_redirects = max_redirects
        self._session: aiohttp.ClientSession | None = None
        self._resolver: SafeResolver | None = None

    def __repr__(self) -> str:
        return f"Fetcher(proxy={self.proxy!r})"

    async def __aenter__(self) -> "Fetcher":
        if self._proxy_url:
            # nazwy rozwiązuje proxy (rdns=True): żadnego lokalnego DNS, więc też brak SafeResolver
            connector = aiohttp_socks.ProxyConnector.from_url(
                self._proxy_url, rdns=True, limit=self.total, limit_per_host=self.per_host)
        else:
            self._resolver = SafeResolver(self.allow_private, self.allow_hosts)
            connector = aiohttp.TCPConnector(
                limit=self.total,
                limit_per_host=self.per_host,
                resolver=self._resolver,
            )
        self._session = aiohttp.ClientSession(
            connector=connector,
            timeout=aiohttp.ClientTimeout(total=self.timeout),
            headers={"User-Agent": self.user_agent, **BROWSER_HEADERS},
        )
        return self

    async def __aexit__(self, *exc) -> None:
        if self._session:
            await self._session.close()

    async def _check_target(self, url: URL) -> None:
        """Schemat http(s) i publiczny host. Hosty-literały IP sprawdzamy tu (aiohttp nie woła dla nich resolvera).
        Przez proxy nazw NIE rozwiązujemy lokalnie (DNS robi proxy): blokujemy tylko nazwy lokalne/wewnętrzne."""
        if url.scheme not in ("http", "https") or not url.host:
            raise BlockedTarget(f"schemat {url.scheme or '?'}")
        if self.allow_private:
            return
        host = url.host.lower()
        if host in self.allow_hosts:
            return
        try:
            ipaddress.ip_address(host.strip("[]").split("%", 1)[0])
        except ValueError:
            if self.proxy and _blocked_proxy_host(host):
                raise BlockedTarget(host) from None
            return
        if not is_public_address(host):
            raise BlockedTarget(host)

    def _error_response(self, e: BaseException) -> Response | None:
        """Wyjątek żądania -> Response z błędem (None = nieznany wyjątek, niech leci wyżej)."""
        if isinstance(e, BlockedTarget):
            return Response(status=None, error=f"{BLOCKED_PREFIX}: {e}")
        if isinstance(e, TooManyRedirects):
            return Response(status=None, error=f"zbyt wiele przekierowań (limit {self.max_redirects})")
        text = _proxy_error_text(e)         # przed timeoutem: ProxyTimeoutError jest też TimeoutError
        if text:
            return Response(status=None, error=text)
        if isinstance(e, asyncio.TimeoutError):
            return Response(status=None, error="timeout")
        if isinstance(e, aiohttp.ClientConnectorDNSError):
            cause = e.os_error
            if isinstance(cause, BlockedTarget):
                return Response(status=None, error=f"{BLOCKED_PREFIX}: {cause}")
            if getattr(cause, "errno", None) in _DNS_PERMANENT:
                return Response(status=None, error=DNS_ERROR)
            return Response(status=None, error=f"{DNS_TEMP} ({type(cause).__name__})")
        if isinstance(e, socket.gaierror):      # resolver spoza aiohttp (np. wywołany wprost)
            if e.errno in _DNS_PERMANENT:
                return Response(status=None, error=DNS_ERROR)
            return Response(status=None, error=f"{DNS_TEMP} ({type(e).__name__})")
        if isinstance(e, aiohttp.ClientConnectorError):
            return Response(status=None, error=f"połączenie: {type(e).__name__}")
        if isinstance(e, aiohttp.ClientError):
            return Response(status=None, error=f"HTTP: {type(e).__name__}")
        if isinstance(e, ssl_module.SSLError):
            return Response(status=None, error=f"TLS: {type(e).__name__}")
        if isinstance(e, OSError):
            return Response(status=None, error=f"połączenie: {type(e).__name__}")
        if isinstance(e, (UnicodeError, LookupError, ValueError)):
            return Response(status=None, error=f"kodowanie: {type(e).__name__}")
        return None

    async def _once(self, method: str, url: str, headers: dict, body: str | None) -> Response:
        assert self._session is not None, "Fetcher używaj jako async context manager"
        try:
            return await self._request(method, url, headers, body, ssl=True)
        except Exception as first:
            if not _is_cert_error(first):
                resp = self._error_response(first)
                if resp is None:
                    raise
                return resp
            if self.strict_tls:
                return Response(status=None, error="certyfikat: weryfikacja TLS nieudana (--strict-tls)")
            if not self.allow_insecure_retry:
                # przez proxy (np. Tor) wyjście może podmieniać certyfikaty: bez weryfikacji nie ponawiamy
                return Response(status=None, error=TLS_NO_RETRY)
            # Nieważny certyfikat (pomiar 03.10.2026: ~65 serwisów stale). Strony są publiczne, więc
            # ponawiamy bez weryfikacji TLS i oznaczamy wynik (insecure) — silnik ogranicza jego pewność
            # i nie korzysta z takiej odpowiedzi do ekstrakcji profilu ani korelacji.
            try:
                resp = await self._request(method, url, headers, body, ssl=False)
                resp.insecure = True
                return resp
            except BlockedTarget as e:
                return Response(status=None, error=f"{BLOCKED_PREFIX}: {e}")
            except Exception as e:
                return Response(status=None, error=_proxy_error_text(e) or f"certyfikat: {type(e).__name__}")

    async def _request(self, method: str, url: str, headers: dict, body: str | None, ssl: bool) -> Response:
        current = URL(url)
        for hop in range(self.max_redirects + 1):
            await self._check_target(current)
            async with self._session.request(
                method, current, headers=headers or None, data=body, allow_redirects=False,
                ssl=None if ssl else False,
            ) as r:
                location = r.headers.get("Location")
                if r.status in REDIRECT_STATUSES and location:
                    if hop == self.max_redirects:
                        raise TooManyRedirects()
                    current = r.url.join(URL(location))
                    if r.status == 303 and method != "HEAD" or r.status in (301, 302) and method == "POST":
                        method, body = "GET", None
                    continue
                # read(n) zwraca tylko to, co już dotarło (do n) — trzeba czytać w pętli do końca albo limitu.
                # Błąd z pomiaru 03.10.2026: GOG 128 KB zamiast 481 KB, teksty reguł „znikały” z dużych stron.
                buf = bytearray()
                truncated = False
                async for chunk in r.content.iter_chunked(65536):
                    buf += chunk
                    if len(buf) > MAX_BODY:
                        truncated = True
                        break
                text = bytes(buf[:MAX_BODY]).decode(r.charset or "utf-8", errors="replace")
                return Response(status=r.status, text=text, final_url=str(r.url), headers=dict(r.headers),
                                truncated=truncated)
        raise TooManyRedirects()

    async def fetch(self, method: str, url: str, headers: dict | None = None, body: str | None = None) -> Response:
        method = (method or "GET").upper()
        if method not in ALLOWED_METHODS:
            return Response(status=None, error=f"metoda niedozwolona: {method[:10]}")
        resp = Response(status=None, error="nie wykonano")
        rate_limited = 0
        for attempt in range(self.retries + 1):
            resp = await self._once(method, url, headers or {}, body)
            # nieistniejąca domena nie zacznie istnieć za sekundę, a zablokowany cel nie przestanie być zablokowany
            # martwe proxy / host nieosiągalny przez proxy: ponowienie na tym samym obwodzie nic nie zmieni
            # (nowy obwód to zadanie silnika), a proxy nie wolno młotkować
            permanent = resp.error is not None and resp.error.startswith(
                (DNS_ERROR, BLOCKED_PREFIX, PROXY_DOWN, PROXY_UNREACHABLE, PROXY_REFUSED, PROXY_NOT_ALLOWED, TLS_NO_RETRY))
            retryable = (resp.status is None and not permanent) or resp.status in RETRY_STATUSES
            if not retryable or attempt == self.retries:
                return resp
            limit = MAX_RETRY_WAIT
            if resp.status == 429:
                # ponowne zapytania do serwisu, który właśnie kazał zwolnić, tylko pogłębiają blokadę: jedna próba
                # po Retry-After (do 30 s), potem wynik ERROR „limit zapytań” (nigdy „brak konta”)
                if rate_limited >= RATE_LIMIT_RETRIES:
                    return resp
                rate_limited += 1
                limit = RATE_LIMIT_MAX_WAIT
            delay = retry_delay(attempt, resp.headers.get("Retry-After"), max_wait=limit)
            if delay is None:
                return resp          # Retry-After ponad limit: nie czekamy, klasyfikacja da ERROR „limit zapytań”
            if self.jitter:
                delay *= random.uniform(1.0, 1.2)      # tylko w górę: nigdy wcześniej niż żąda serwer
            if resp.status == 429:
                delay = min(delay, RATE_LIMIT_MAX_WAIT)
            await asyncio.sleep(delay)
        return resp


async def preflight(proxy: str, timeout: float = 30.0, url: str = TOR_CHECK_URL) -> PreflightResult:
    """Kontrola kanału przed skanem (fail-closed): zapytanie o adres wyjścia przez proxy. Każda porażka = ok=False
    (skan nie rusza). `url` można podmienić (testy); jego host jest wtedy jawnie dopuszczony."""
    try:
        validate_proxy(proxy)
    except ValueError as e:
        return PreflightResult(False, error=str(e))
    host = (urlsplit(url).hostname or "").lower()
    allow = () if url == TOR_CHECK_URL else (host,)
    try:
        async with Fetcher(timeout=timeout, retries=1, proxy=proxy, jitter=False, allow_hosts=allow) as f:
            resp = await f.fetch("GET", url, {"Accept": "application/json"})
    except Exception as e:      # preflight nigdy nie rzuca: błąd = brak zgody na skan
        return PreflightResult(False, error=type(e).__name__)
    if resp.status != 200:
        return PreflightResult(False, error=resp.error or f"HTTP {resp.status}")
    try:
        data = json.loads(resp.text)
        is_tor, ip = data.get("IsTor"), data.get("IP")
    except (ValueError, AttributeError):
        return PreflightResult(False, error="odpowiedź kontroli nie jest poprawnym JSON")
    if not isinstance(is_tor, bool) or not isinstance(ip, str) or mask_ip(ip) is None:
        return PreflightResult(False, error="odpowiedź kontroli bez pól IsTor / IP")
    return PreflightResult(True, is_tor=is_tor, exit_ip_masked=mask_ip(ip))
