"""Wspólna warstwa klientów Graph API (Threads, Instagram, Strony Facebooka): transport, redakcja tokenu,
klasyfikacja błędów na statusy kontraktu i pomocnicy czyszczenia pól.

Zasady wspólne dla wszystkich źródeł:
- token tylko w parametrze zapytania, nigdy w wyniku, raporcie ani komunikacie (redakcja `access_token=`);
- brak przekierowań (adres zawiera poświadczenia), limit rozmiaru odpowiedzi, timeout, jedno ponowienie dla błędów
  przejściowych (sieć, 5xx, kody 1/2), BRAK ponowień przy limicie i błędzie autoryzacji;
- bez tokenu (albo innej wymaganej konfiguracji) nic nie idzie do sieci: status not_configured;
- brak automatycznego przejścia na scrapowanie po błędzie API; kolejnych stron (paging) nie pobieramy.
Kody błędów Graph API mapowane wg ogólnej konwencji (190/102 autoryzacja, 10/3/200-299 uprawnienia,
4/17/32/341/613/80001/80002 limit, 1/2 błąd przejściowy)."""
from __future__ import annotations

import base64
import json
import re
import socket
import time
import urllib.error
import urllib.request
from typing import Callable
from urllib.parse import quote, quote_plus, unquote, urlencode, urlsplit

from .config import Config
from .contract import MetaResult, SourceKind, St

USER_AGENT = "osint-meta-search/0.1"
USERNAME = re.compile(r"^[A-Za-z0-9._]{1,30}$")
CONTROL = re.compile(r"[\x00-\x1f\x7f]")
MAX_TEXT = 1000
MAX_BODY = 2 * 1024 * 1024
AUTH_CODES = {190, 102}
PERMISSION_CODES = {10, 3} | set(range(200, 300))
RATE_CODES = {4, 17, 32, 341, 613, 80001, 80002}
TRANSIENT_CODES = {1, 2}

# (status HTTP albo None, nagłówki, treść, opis błędu transportu albo None)
Transport = Callable[[str, float], tuple[int | None, dict, bytes, str | None]]


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        # The request URL contains credentials; never follow a supplied location.
        return None


def _read_response(resp):
    body = resp.read(MAX_BODY + 1)
    if len(body) > MAX_BODY:
        return resp.code, {}, b"", "odpowiedź przekracza limit rozmiaru"
    return resp.code, dict(resp.headers or {}), body, None


def urllib_transport(url: str, timeout: float) -> tuple[int | None, dict, bytes, str | None]:
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT, "Accept": "application/json"})
    try:
        with urllib.request.build_opener(_NoRedirect()).open(req, timeout=timeout) as resp:
            return _read_response(resp)
    except urllib.error.HTTPError as exc:
        try:
            return _read_response(exc)
        finally:
            exc.close()
    except (urllib.error.URLError, socket.timeout, TimeoutError, ConnectionError, OSError) as exc:
        reason = getattr(exc, "reason", exc)
        return None, {}, b"", "timeout" if isinstance(reason, (socket.timeout, TimeoutError)) else type(reason).__name__


class _PinnedProxy(urllib.request.BaseHandler):
    """Trasa przypięta do jednego proxy. Zastępuje urllib.request.ProxyHandler, który pomija proxy dla hostów
    z NO_PROXY/no_proxy (także "*") i z wyjątków systemowych (rejestr Windows): tu żaden wyjątek nie obowiązuje.
    Tylko HTTPS (tunel CONNECT); żądanie, które nie dostało tunelu przez to proxy, jest blokowane."""
    handler_order = 100          # przed HTTPSHandler (500), jak ProxyHandler

    def __init__(self, proxy: str):
        parts = urlsplit(proxy)
        if parts.scheme not in ("http", "https") or not parts.hostname or parts.port is None:
            raise ValueError("META_PROXY: oczekiwane http(s)://host:port")
        self.scheme = parts.scheme
        self.hostport = parts.netloc.rpartition("@")[2]
        self.auth = None
        if parts.username is not None:
            creds = f"{unquote(parts.username)}:{unquote(parts.password or '')}"
            self.auth = "Basic " + base64.b64encode(creds.encode("utf-8")).decode("ascii")

    def https_open(self, req):
        if req.has_proxy() or getattr(req, "_tunnel_host", None):
            raise urllib.error.URLError("żądanie ma już inną trasę proxy - zablokowane")
        if self.auth:
            req.add_header("Proxy-authorization", self.auth)   # urllib przenosi go do nagłówków CONNECT
        req.set_proxy(self.hostport, self.scheme)
        if req.host != self.hostport or not getattr(req, "_tunnel_host", None):
            raise urllib.error.URLError("trasa z pominięciem META_PROXY zablokowana")
        return None              # dalej obsługuje HTTPSHandler: połączenie z proxy i tunel do hosta API

    def http_open(self, req):
        raise urllib.error.URLError("przez META_PROXY wysyłane są tylko zapytania HTTPS")


def proxy_transport(proxy: str | None) -> Transport:
    """Transport wyłącznie przez wskazane proxy HTTP(S) (tunel CONNECT: nazwę hosta API rozwiązuje proxy).
    Brak proxy (None) = transport blokujący: zero ruchu, żadnego fallbacku na połączenie bezpośrednie.
    NO_PROXY/no_proxy, wyjątki systemowe i zmienne *_PROXY środowiska nie zmieniają trasy (środowisko procesu
    nie jest modyfikowane: inne zadania działają współbieżnie)."""
    blocked = lambda url, timeout: (None, {}, b"", "błędna konfiguracja META_PROXY - zapytania nie wysłano")  # noqa: E731
    if not proxy:
        return blocked
    try:
        pinned = _PinnedProxy(proxy)
    except ValueError:
        return blocked
    # Własny zestaw handlerów zamiast build_opener: bez domyślnego ProxyHandler (środowisko, NO_PROXY), bez HTTP,
    # FTP i plików. Błędy HTTP i brak przekierowań jak w urllib_transport.
    opener = urllib.request.OpenerDirector()
    for handler in (pinned, urllib.request.HTTPSHandler(), urllib.request.HTTPDefaultErrorHandler(), _NoRedirect(),
                    urllib.request.HTTPErrorProcessor(), urllib.request.UnknownHandler()):
        opener.add_handler(handler)

    def send(url: str, timeout: float):
        req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT, "Accept": "application/json"})
        try:
            with opener.open(req, timeout=timeout) as resp:
                return _read_response(resp)
        except urllib.error.HTTPError as exc:
            try:
                return _read_response(exc)
            finally:
                exc.close()
        except (urllib.error.URLError, socket.timeout, TimeoutError, ConnectionError, OSError) as exc:
            reason = getattr(exc, "reason", exc)
            kind = "timeout" if isinstance(reason, (socket.timeout, TimeoutError)) else type(reason).__name__
            return None, {}, b"", f"proxy META_PROXY niedostępne ({kind}) - bez połączenia bezpośredniego"
    return send


def redact(text: str, secret: str | None) -> str:
    """Usuwa token (także w parametrach adresu) z tekstu, który może trafić do raportu lub terminala."""
    text = re.sub(r"(access_token=)[^&\s\"']+", r"\1<REDACTED>", str(text))
    if secret:
        for variant in sorted({secret, quote(secret, safe=""), quote_plus(secret)}, key=len, reverse=True):
            text = text.replace(variant, "<REDACTED>")
    return text[:300]


def json_body(body: bytes):
    try:
        return json.loads(body.decode("utf-8"))
    except (UnicodeDecodeError, ValueError):
        return None


def error_info(body: bytes) -> tuple[int | None, int | None, str]:
    """(kod, podkod, komunikat bez znaków sterujących) z ciała błędu Graph API."""
    data = json_body(body)
    err = data.get("error") if isinstance(data, dict) else None
    if not isinstance(err, dict):
        return None, None, ""
    code, sub = err.get("code"), err.get("error_subcode")
    return (code if isinstance(code, int) else None, sub if isinstance(sub, int) else None,
            CONTROL.sub(" ", str(err.get("message") or "")))


def join(head: str, detail: str) -> str:
    return f"{head}. API: {detail}" if detail else head


def clean(value, limit: int = MAX_TEXT) -> str:
    """Tekst z API: bez znaków sterujących, przycięty."""
    return CONTROL.sub(" ", str(value or ""))[:limit]


def https_url(value, limit: int = 500, schemes: tuple[str, ...] = ("https://",)) -> str:
    """Adres z API tylko jeśli ma dozwolony schemat (odrzuca javascript:, data:, ftp: itp.)."""
    text = str(value or "")
    if not text.startswith(schemes) or len(text) > limit or CONTROL.search(text):
        return ""
    try:
        parsed = urlsplit(text)
        if not parsed.hostname or parsed.username or parsed.password or parsed.port not in (None, 80, 443):
            return ""
    except ValueError:
        return ""
    return text


def _scrub(value, secrets):
    if isinstance(value, str):
        value = re.sub(r"(?i)(access_token=)[^&\s\"']+", r"\1<REDACTED>", value)
        for secret in secrets:
            if secret:
                for variant in sorted({secret, quote(secret, safe=""), quote_plus(secret)}, key=len, reverse=True):
                    value = value.replace(variant, "<REDACTED>")
        return value
    if isinstance(value, dict):
        return {k: _scrub(v, secrets) for k, v in value.items()}
    if isinstance(value, list):
        return [_scrub(v, secrets) for v in value]
    return value


def count(value) -> int | None:
    return value if isinstance(value, int) and not isinstance(value, bool) else None


class GraphClient:
    """Baza klientów Graph API. Podklasa ustawia `platform`, `base`, `permissions` oraz `token` i `version`."""
    platform = ""
    base = ""
    permissions: dict[str, str] = {}      # operacja -> wymagane uprawnienia (do komunikatu o braku dostępu)

    def __init__(self, cfg: Config, transport: Transport | None = None, timeout: float = 15.0,
                 retries: int = 1, sleep: Callable[[float], None] = time.sleep):
        if transport is None:
            use_proxy = getattr(cfg, "proxy", None) or getattr(cfg, "proxy_blocked", False)
            transport = proxy_transport(cfg.proxy) if use_proxy else urllib_transport
        self.cfg, self.transport, self.timeout = cfg, transport, timeout
        self.retries, self.sleep = retries, sleep

    @property
    def token(self) -> str | None:
        raise NotImplementedError

    @property
    def version(self) -> str:
        raise NotImplementedError

    def _endpoint(self, path: str) -> str:
        return f"{self.base}/{self.version}/{path}"

    def _result(self, operation: str, query: str, status: St, path: str, **kw) -> MetaResult:
        """`path` to ścieżka POKAZYWANA w wyniku (bez parametrów i bez identyfikatorów konta)."""
        secrets = (self.cfg.threads_token, self.cfg.instagram_token, self.cfg.facebook_token)
        return MetaResult(self.platform, operation, _scrub(query, secrets), status, SourceKind.API,
                          endpoint=_scrub(self._endpoint(path), secrets),
                          api_version=self.version, **_scrub(kw, secrets))

    def _call(self, path: str, params: dict) -> tuple[int | None, dict, bytes, str | None]:
        """Jedno zapytanie z kontrolowanym ponowieniem; `path` to rzeczywista ścieżka (może zawierać id)."""
        url = self._endpoint(path) + "?" + urlencode({**params, "access_token": self.token})
        attempt = 0
        while True:
            status, headers, body, err = self.transport(url, self.timeout)
            transient = err is not None or (status is not None and status >= 500)
            if not transient and status is not None and status >= 400:
                transient = error_info(body)[0] in TRANSIENT_CODES
            if not transient or attempt >= self.retries:
                return status, headers, body, err
            attempt += 1
            self.sleep(1.5 * attempt)

    def _failure(self, operation: str, query: str, path: str, status: int | None, headers: dict, body: bytes,
                 err: str | None) -> MetaResult | None:
        """Wynik dla odpowiedzi nie-200 (albo None, gdy odpowiedź jest poprawna)."""
        token = self.token
        if err is not None:
            return self._result(operation, query, St.SOURCE_ERROR, path, message=f"błąd sieci: {redact(err, token)}")
        payload = json_body(body)
        if status == 200 and not (isinstance(payload, dict) and "error" in payload):
            return None
        code, subcode, msg = error_info(body)
        msg = redact(msg, token)
        kw = {"http_status": status, "error_code": code}
        if status == 429 or code in RATE_CODES:
            retry = headers.get("Retry-After") or headers.get("retry-after")
            head = "limit zapytań API" + (f" (ponów po {redact(retry, token)} s)" if retry else "")
            return self._result(operation, query, St.RATE_LIMITED, path, message=join(head, msg), **kw)
        if status == 401 or code in AUTH_CODES:
            return self._result(operation, query, St.AUTH_ERROR, path,
                                message=join("token nieważny, wygasły lub odwołany", msg), **kw)
        if status == 403 or code in PERMISSION_CODES:
            need = self.permissions.get(operation, "")
            head = f"brak uprawnień (wymagane: {need})" if need else "brak uprawnień"
            return self._result(operation, query, St.PERMISSION_DENIED, path, message=join(head, msg), **kw)
        return self._result(operation, query, St.SOURCE_ERROR, path,
                            message=join(f"nieoczekiwana odpowiedź API (HTTP {status})", msg), **kw)

    def _not_configured(self, operation: str, query: str, path: str, what: str) -> MetaResult:
        extra = ("; " + "; ".join(self.cfg.problems)) if self.cfg.problems else ""
        return self._result(operation, query, St.NOT_CONFIGURED, path,
                            message=f"{what} Zapytania nie wysłano{extra}.")
