"""Jedna maleńka funkcja pobierania (stdlib urllib) wstrzykiwana do wszystkich zrodel.

Testy podstawiaja wlasna funkcje o tej samej sygnaturze, wiec nie dotykaja sieci.
Bledy transportu to FetchError z komunikatem bezpiecznym do pokazania (bez naglowkow i tokenow).
"""

from __future__ import annotations

import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from typing import Callable, Mapping

from . import __version__

USER_AGENT = f"net-intel/{__version__} (defensywny, pasywny audyt publicznej infrastruktury)"
MAX_BODY_BYTES = 30 * 1024 * 1024  # crt.sh dla duzych domen bywa wielomegabajtowe


class FetchError(Exception):
    """Blad transportu (siec, timeout, za duza odpowiedz, niedozwolone przekierowanie)."""


@dataclass
class Response:
    status: int
    text: str = ""
    headers: dict[str, str] = field(default_factory=dict)


# fetch(url, headers=None, timeout=15.0) -> Response; rzuca FetchError przy bledzie transportu
Fetch = Callable[..., Response]


class _SafeRedirect(urllib.request.HTTPRedirectHandler):
    """Przekierowania tylko na https; naglowek Authorization nie jedzie pod inny host."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        new = urllib.parse.urlsplit(newurl)
        if new.scheme != "https":
            raise FetchError(f"odrzucono przekierowanie na niezabezpieczony adres (HTTP {code})")
        nxt = super().redirect_request(req, fp, code, msg, headers, newurl)
        if nxt is not None and new.hostname != urllib.parse.urlsplit(req.full_url).hostname:
            nxt.remove_header("Authorization")
        return nxt


_OPENER = urllib.request.build_opener(_SafeRedirect)


def _read_limited(fp, limit: int = MAX_BODY_BYTES) -> bytes:
    data = fp.read(limit + 1)
    if len(data) > limit:
        raise FetchError(f"odpowiedź przekracza limit rozmiaru ({limit // (1024 * 1024)} MB)")
    return data


def urllib_fetch(url: str, headers: Mapping[str, str] | None = None, timeout: float = 15.0) -> Response:
    merged = {"User-Agent": USER_AGENT, "Accept": "*/*", **(headers or {})}
    req = urllib.request.Request(url, headers=merged, method="GET")
    try:
        with _OPENER.open(req, timeout=timeout) as resp:
            body = _read_limited(resp).decode("utf-8", errors="replace")
            return Response(resp.status, body, {k.lower(): v for k, v in resp.headers.items()})
    except urllib.error.HTTPError as exc:
        body = _read_limited(exc.fp).decode("utf-8", errors="replace") if exc.fp else ""
        return Response(exc.code, body, {k.lower(): v for k, v in exc.headers.items()})
    except FetchError:
        raise
    except TimeoutError:
        raise FetchError("przekroczono limit czasu") from None
    except (urllib.error.URLError, OSError) as exc:
        reason = getattr(exc, "reason", exc)
        if isinstance(reason, TimeoutError):
            raise FetchError("przekroczono limit czasu") from None
        raise FetchError(f"błąd sieci: {reason}") from None
    except ValueError as exc:  # np. zly adres URL
        raise FetchError(f"nieprawidłowe zapytanie: {exc}") from None
