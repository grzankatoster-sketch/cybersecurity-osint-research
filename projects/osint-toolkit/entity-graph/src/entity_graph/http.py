"""Cienka warstwa HTTP na urllib. Zasady: zero opcji proxy/rotacji tożsamości, uczciwy User-Agent,
limit szybkości na host, limit rozmiaru odpowiedzi, brak wyjątków (błąd = HttpResponse.error).

Blokady (401/403/429, CAPTCHA) są raportowane jako ERROR przez classify_http. Nie są omijane.
"""
from __future__ import annotations

import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from typing import Callable, Protocol

from . import __version__
from .model import Status

DEFAULT_UA = f"entity-graph/{__version__} (autoryzowany OSINT; narzedzie badawcze)"
MAX_BODY = 5_000_000
RETRY_STATUSES = {429, 502, 503, 504}
MAX_RETRY_AFTER = 10.0


@dataclass
class HttpResponse:
    status: int | None                 # None = brak odpowiedzi (błąd sieci)
    text: str = ""
    headers: dict[str, str] = field(default_factory=dict)
    error: str | None = None           # opis błędu transportu


class Fetcher(Protocol):
    def get(self, url: str, headers: dict[str, str] | None = None) -> HttpResponse: ...


class _SafeRedirect(urllib.request.HTTPRedirectHandler):
    """Przekierowania tylko na http/https (urllib domyślnie dopuszcza też ftp)."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        if urllib.parse.urlsplit(newurl).scheme.lower() not in ("http", "https"):
            raise urllib.error.HTTPError(req.full_url, code, "przekierowanie na niedozwolony schemat", headers, fp)
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def _read_limited(fp, limit: int) -> str | None:
    data = fp.read(limit + 1)
    if len(data) > limit:
        return None
    return data.decode("utf-8", errors="replace")


class HttpClient:
    def __init__(
        self,
        timeout: float = 20.0,
        user_agent: str = DEFAULT_UA,
        max_bytes: int = MAX_BODY,
        min_interval: float = 0.5,
        retries: int = 1,
        sleep: Callable[[float], None] = time.sleep,
        clock: Callable[[], float] = time.monotonic,
    ):
        self.timeout = timeout
        self.user_agent = user_agent
        self.max_bytes = max_bytes
        self.min_interval = min_interval
        self.retries = retries
        self._sleep = sleep
        self._clock = clock
        self._last: dict[str, float] = {}
        self._opener = urllib.request.build_opener(_SafeRedirect)

    def _throttle(self, url: str) -> None:
        host = urllib.parse.urlsplit(url).netloc
        wait = self._last.get(host, -1e9) + self.min_interval - self._clock()
        if wait > 0:
            self._sleep(wait)
        self._last[host] = self._clock()

    def _once(self, url: str, headers: dict[str, str]) -> HttpResponse:
        req = urllib.request.Request(url, headers={"User-Agent": self.user_agent, "Accept": "*/*", **headers})
        try:
            with self._opener.open(req, timeout=self.timeout) as resp:
                body = _read_limited(resp, self.max_bytes)
                hdrs = {k.lower(): v for k, v in resp.headers.items()}
                if body is None:
                    return HttpResponse(resp.status, "", hdrs, error="odpowiedź przekracza limit rozmiaru")
                return HttpResponse(resp.status, body, hdrs)
        except urllib.error.HTTPError as exc:
            body = _read_limited(exc.fp, self.max_bytes) if exc.fp else ""
            return HttpResponse(exc.code, body or "", {k.lower(): v for k, v in exc.headers.items()})
        except TimeoutError:
            return HttpResponse(None, error="timeout")
        except urllib.error.URLError as exc:
            return HttpResponse(None, error=f"sieć: {type(getattr(exc, 'reason', exc)).__name__}")
        except (OSError, ValueError) as exc:
            return HttpResponse(None, error=f"sieć: {type(exc).__name__}")

    def get(self, url: str, headers: dict[str, str] | None = None) -> HttpResponse:
        if urllib.parse.urlsplit(url).scheme.lower() not in ("http", "https"):
            return HttpResponse(None, error="niedozwolony schemat URL (tylko http/https)")
        resp = HttpResponse(None, error="nie wykonano")
        for attempt in range(self.retries + 1):
            self._throttle(url)
            resp = self._once(url, headers or {})
            if resp.status not in RETRY_STATUSES or attempt == self.retries:
                return resp
            try:
                delay = float(resp.headers.get("retry-after", "") or 2.0 * (attempt + 1))
            except ValueError:
                delay = 2.0 * (attempt + 1)
            self._sleep(max(0.0, min(delay, MAX_RETRY_AFTER)))
        return resp


def classify_http(resp: HttpResponse, not_found_ok: bool = True) -> tuple[Status | None, str]:
    """-> (status końcowy albo None gdy odpowiedź 2xx do dalszego parsowania, powód).

    404 daje NOT_FOUND tylko gdy źródło jawnie tak odpowiada (not_found_ok). Błąd sieci, blokada, limit i 5xx
    to ERROR, nigdy NOT_FOUND."""
    if resp.error:
        return Status.ERROR, resp.error
    code = resp.status
    if code is not None and 200 <= code < 300:
        return None, ""
    if code == 404:
        return (Status.NOT_FOUND, "HTTP 404") if not_found_ok else (Status.ERROR, "HTTP 404")
    if code == 429:
        return Status.ERROR, "HTTP 429: limit zapytań (nie omijamy; spróbuj później)"
    if code in (401, 403):
        return Status.ERROR, f"HTTP {code}: dostęp odmówiony lub wymagane uwierzytelnienie (nie omijamy)"
    if code is not None and code >= 500:
        return Status.ERROR, f"HTTP {code}: błąd po stronie serwera"
    return Status.UNKNOWN, f"HTTP {code}: nieoczekiwana odpowiedź"
