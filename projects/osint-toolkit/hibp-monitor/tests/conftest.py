from __future__ import annotations

from pathlib import Path

import pytest

from hibp_monitor.http import Response

FIXTURES = Path(__file__).parent / "fixtures"


def fixture_text(name: str) -> str:
    return (FIXTURES / name).read_text(encoding="utf-8")


class FakeClient:
    """Falszywy klient HTTP: zwraca zaprogramowane odpowiedzi, zapamietuje zapytania. Zero sieci."""

    def __init__(self, routes: dict[str, Response | list[Response]] | None = None, default: Response | None = None):
        self.routes = routes or {}
        self.default = default
        self.calls: list[tuple[str, dict[str, str]]] = []

    def get(self, url, headers=None):
        self.calls.append((url, dict(headers or {})))
        for prefix, resp in self.routes.items():
            if url.startswith(prefix):
                if isinstance(resp, list):
                    return resp.pop(0) if len(resp) > 1 else resp[0]
                return resp
        if self.default is not None:
            return self.default
        raise AssertionError(f"Nieoczekiwane zapytanie (brak trasy): {url}")


@pytest.fixture
def fake():
    return FakeClient


@pytest.fixture
def ok():
    return lambda text, status=200, headers=None: Response(status, text, headers or {})
