"""Minimalny klient HTTP na stdlib (urllib): limit rozmiaru odpowiedzi, brak przekierowan, odpowiedzi 4xx/5xx jako Response.

Wzorzec: hibp-monitor/src/hibp_monitor/http.py. Ponawianie przy 429 realizuje konektor (hibp_catalog.py),
a klient jest wstrzykiwany przez Protocol, wiec testy nie dotykaja sieci.
"""

from __future__ import annotations

import urllib.error
import urllib.request
from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Protocol

MAX_BODY_BYTES = 20 * 1024 * 1024  # katalog HIBP ma ok. 1-2 MB; twardy limit pamieci
DEFAULT_TIMEOUT = 30.0


class NetworkError(Exception):
    """Blad sieci albo API (komunikat bezpieczny do pokazania uzytkownikowi)."""

    def __init__(self, message: str, status: int | None = None):
        super().__init__(message)
        self.status = status


@dataclass
class Response:
    status: int
    text: str = ""
    headers: dict[str, str] = field(default_factory=dict)

    def header(self, name: str, default: str | None = None) -> str | None:
        for key, value in self.headers.items():
            if key.lower() == name.lower():
                return value
        return default


class Client(Protocol):
    def get(self, url: str, headers: Mapping[str, str] | None = None) -> Response: ...


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise NetworkError(
            f"Serwer zwrócił przekierowanie (HTTP {code}); odrzucono je ze względów bezpieczeństwa.", code
        )


_OPENER = urllib.request.build_opener(_NoRedirect)


def read_limited(fp, limit: int = MAX_BODY_BYTES) -> bytes:
    data = fp.read(limit + 1)
    if len(data) > limit:
        raise NetworkError(f"Odpowiedź serwera przekracza limit rozmiaru ({limit // (1024 * 1024)} MB); przerwano.")
    return data


class UrllibClient:
    """Domyslny klient: GET z timeoutem i limitem rozmiaru."""

    def __init__(self, timeout: float = DEFAULT_TIMEOUT, max_bytes: int = MAX_BODY_BYTES):
        self.timeout = timeout
        self.max_bytes = max_bytes

    def get(self, url: str, headers: Mapping[str, str] | None = None) -> Response:
        req = urllib.request.Request(url, headers=dict(headers or {}), method="GET")
        try:
            with _OPENER.open(req, timeout=self.timeout) as resp:
                body = read_limited(resp, self.max_bytes).decode("utf-8", errors="replace")
                return Response(resp.status, body, {k: v for k, v in resp.headers.items()})
        except urllib.error.HTTPError as exc:
            body = read_limited(exc.fp, self.max_bytes).decode("utf-8", errors="replace") if exc.fp else ""
            return Response(exc.code, body, {k: v for k, v in exc.headers.items()})
        except (urllib.error.URLError, TimeoutError, OSError) as exc:
            reason = getattr(exc, "reason", exc)
            raise NetworkError(f"Błąd sieci: {reason}") from None
