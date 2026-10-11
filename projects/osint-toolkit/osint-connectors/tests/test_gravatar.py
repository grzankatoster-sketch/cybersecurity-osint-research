"""Test kontraktowy konektora Gravatar — atrapa HTTP, zero ruchu sieciowego.

Odpowiedzi pochodzą z zredagowanego, syntetycznego fixture lub są budowane w
teście. Nie wykonujemy żadnego połączenia do gravatar.com.
"""
import asyncio
import json
import os

import pytest

from osint_connectors import Context, InputKind, Status, Subject, run
from osint_connectors.errors import RateLimited, TransportError

import osint_connectors.connectors.gravatar_public  # noqa: F401  (rejestruje konektor)
from osint_connectors import registry

FIXTURES = os.path.join(os.path.dirname(__file__), "fixtures")


class FakeResponse:
    def __init__(self, status_code, payload=None, raise_json=False):
        self.status_code = status_code
        self._payload = payload
        self._raise_json = raise_json

    def json(self):
        if self._raise_json:
            raise ValueError("zły JSON")
        return self._payload

    @property
    def text(self):
        return json.dumps(self._payload) if self._payload is not None else ""


class FakeHttp:
    """Atrapa klienta: oddaje zaprogramowaną odpowiedź albo rzuca wyjątek sieci."""

    def __init__(self, response=None, exc=None):
        self.response = response
        self.exc = exc
        self.calls = []

    async def get(self, url, *, headers=None, timeout=None):
        self.calls.append(url)
        if self.exc is not None:
            raise self.exc
        return self.response


def _run(http):
    ctx = Context(salt="sol", http=http, timeout=1.0)
    subj = Subject(InputKind.EMAIL, "ktos@example.com")
    return asyncio.run(run([registry.get("gravatar_public")], subj, ctx))[0]


def test_found_from_fixture():
    with open(os.path.join(FIXTURES, "gravatar_found.json"), encoding="utf-8") as fh:
        payload = json.load(fh)
    f = _run(FakeHttp(FakeResponse(200, payload)))
    assert f.status == Status.FOUND
    assert f.confidence == 0.95
    assert f.extra["public_profile_url"].startswith("https://gravatar.com/")


def test_not_found_on_404():
    f = _run(FakeHttp(FakeResponse(404)))
    assert f.status == Status.NOT_FOUND and f.confidence < 1.0


def test_rate_limit_maps_to_unknown():
    f = _run(FakeHttp(FakeResponse(429)))
    assert f.status == Status.UNKNOWN and f.error_kind == "rate_limited"


def test_server_error_maps_to_error():
    f = _run(FakeHttp(FakeResponse(503)))
    assert f.status == Status.ERROR and f.error_kind == "transport"


def test_network_exception_maps_to_error():
    f = _run(FakeHttp(exc=ConnectionError("brak sieci")))
    assert f.status == Status.ERROR and f.error_kind == "transport"


def test_bad_json_maps_to_error():
    f = _run(FakeHttp(FakeResponse(200, raise_json=True)))
    assert f.status == Status.ERROR and f.error_kind == "parse"


def test_200_without_entry_is_schema_changed():
    f = _run(FakeHttp(FakeResponse(200, {"foo": "bar"})))
    assert f.status == Status.ERROR and f.error_kind == "schema_changed"


def test_no_http_client_is_unknown():
    ctx = Context(salt="sol")  # http=None
    subj = Subject(InputKind.EMAIL, "ktos@example.com")
    f = asyncio.run(run([registry.get("gravatar_public")], subj, ctx))[0]
    assert f.status == Status.UNKNOWN and f.error_kind == "no_http"


def test_raw_email_never_in_finding():
    with open(os.path.join(FIXTURES, "gravatar_found.json"), encoding="utf-8") as fh:
        payload = json.load(fh)
    f = _run(FakeHttp(FakeResponse(200, payload)))
    assert "ktos@example.com" not in json.dumps(f.to_dict())
    # Skrót md5 e-maila jest w URL żądania (schemat Gravatara), ale nie w wyniku.
    assert "@" not in f.subject_ref
