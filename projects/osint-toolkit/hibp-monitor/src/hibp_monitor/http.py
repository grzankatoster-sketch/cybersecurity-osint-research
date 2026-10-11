"""Minimalny klient HTTP na stdlib z obsluga 429 Retry-After.

Klient ma wstrzykiwalny transport i sleep, wiec testy nie dotykaja sieci.
Naglowki z kluczem API nigdy nie trafiaja do komunikatow bledow.
"""
from __future__ import annotations

import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from typing import Callable, Mapping, Protocol

DEFAULT_USER_AGENT = "hibp-monitor/0.1 (monitor wlasnych domen)"
MAX_RETRY_AFTER = 120.0
# Katalog /breaches ma ok. 1,1 MB (2026); 20 MB to zapas na wzrost i twardy limit pamieci.
MAX_BODY_BYTES = 20 * 1024 * 1024
KEY_HOST = "haveibeenpwned.com"


class HibpError(Exception):
    """Blad komunikacji z API (komunikat bezpieczny do pokazania uzytkownikowi)."""

    def __init__(self, message: str, status: int | None = None):
        super().__init__(message)
        self.status = status


@dataclass
class Response:
    status: int
    text: str = ""
    headers: dict[str, str] = field(default_factory=dict)


class Client(Protocol):
    def get(self, url: str, headers: Mapping[str, str] | None = None) -> Response: ...


Transport = Callable[[str, dict[str, str], float], Response]


class NoRedirectHandler(urllib.request.HTTPRedirectHandler):
    """Odrzuca kazde przekierowanie: urllib przenosi naglowki (w tym hibp-api-key) na nowy adres."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise HibpError(
            f"Serwer zwrocil przekierowanie (HTTP {code}); odrzucono je ze wzgledow bezpieczenstwa "
            "(naglowki z kluczem API nie sa wysylane pod inny adres).",
            code,
        )


_OPENER = urllib.request.build_opener(NoRedirectHandler)


def read_limited(fp, limit: int = MAX_BODY_BYTES) -> bytes:
    """Czyta cialo odpowiedzi, ale najwyzej `limit` bajtow; wiecej -> HibpError."""
    data = fp.read(limit + 1)
    if len(data) > limit:
        raise HibpError(f"Odpowiedz serwera przekracza limit rozmiaru ({limit // (1024 * 1024)} MB); przerwano.")
    return data


def urllib_transport(url: str, headers: dict[str, str], timeout: float) -> Response:
    req = urllib.request.Request(url, headers=headers, method="GET")
    try:
        with _OPENER.open(req, timeout=timeout) as resp:
            body = read_limited(resp, MAX_BODY_BYTES).decode("utf-8", errors="replace")
            return Response(resp.status, body, {k.lower(): v for k, v in resp.headers.items()})
    except urllib.error.HTTPError as exc:
        body = read_limited(exc.fp, MAX_BODY_BYTES).decode("utf-8", errors="replace") if exc.fp else ""
        return Response(exc.code, body, {k.lower(): v for k, v in exc.headers.items()})
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        reason = getattr(exc, "reason", exc)
        raise HibpError(f"Blad sieci: {reason}") from None


def check_key_target(url: str) -> None:
    """Dopuszcza zapytania z kluczem API tylko do https://haveibeenpwned.com na porcie 443, bez danych logowania w adresie."""
    parts = urllib.parse.urlsplit(url)
    if parts.scheme != "https":
        raise HibpError(
            f"Klucz API nie moze byc wyslany schematem '{parts.scheme}'; wymagane https do hosta {KEY_HOST}."
        )
    if parts.hostname != KEY_HOST:
        raise HibpError(
            f"Klucz API moze byc wysylany tylko do hosta {KEY_HOST}, a nie do '{parts.hostname}'."
        )
    if parts.username or parts.password:
        raise HibpError(
            f"Adres z danymi logowania w URL jest niedozwolony dla zapytan z kluczem API do hosta {KEY_HOST}."
        )
    try:
        port = parts.port
    except ValueError:
        raise HibpError(
            f"Niepoprawny port w adresie docelowym zapytania z kluczem API do hosta {KEY_HOST}."
        ) from None
    if port is not None and port != 443:
        raise HibpError(
            f"Klucz API moze byc wysylany tylko na standardowym porcie 443 hosta {KEY_HOST} (otrzymano port {port})."
        )


def parse_retry_after(value: str | None, default: float = 2.0) -> float:
    try:
        seconds = float(value) if value is not None else default
    except ValueError:
        seconds = default
    return max(0.0, min(seconds, MAX_RETRY_AFTER))


class HttpClient:
    def __init__(
        self,
        user_agent: str = DEFAULT_USER_AGENT,
        *,
        transport: Transport = urllib_transport,
        sleep: Callable[[float], None] = time.sleep,
        max_retries: int = 3,
        timeout: float = 30.0,
    ):
        self.user_agent = user_agent
        self._transport = transport
        self._sleep = sleep
        self.max_retries = max_retries
        self.timeout = timeout

    def get(self, url: str, headers: Mapping[str, str] | None = None) -> Response:
        merged = {"User-Agent": self.user_agent, **(headers or {})}
        if any(name.lower() == "hibp-api-key" for name in merged):
            check_key_target(url)
        attempt = 0
        while True:
            resp = self._transport(url, merged, self.timeout)
            if resp.status != 429:
                return resp
            if attempt >= self.max_retries:
                raise HibpError("Limit zapytan HIBP (429): spróbuj ponownie pozniej.", 429)
            self._sleep(parse_retry_after(resp.headers.get("retry-after"), default=2.0 * (attempt + 1)))
            attempt += 1
