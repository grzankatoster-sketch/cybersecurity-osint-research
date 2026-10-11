"""Falszywy fetch: HTTP za interfejsem, testy bez sieci."""

from pathlib import Path

import pytest

from net_intel.http import FetchError, Response

FIXTURES = Path(__file__).parent / "fixtures"


def fixture_text(name: str) -> str:
    return (FIXTURES / name).read_text(encoding="utf-8")


def ok(name: str, status: int = 200) -> Response:
    return Response(status, fixture_text(name))


class FakeFetch:
    """Trasy: (fragment adresu, odpowiedz | wyjatek | lista odpowiedzi kolejno | funkcja(url)). Brak trasy = blad testu."""

    def __init__(self):
        self.routes: list[tuple[str, object]] = []
        self.calls: list[tuple[str, dict]] = []

    def on(self, fragment: str, result):
        self.routes.append((fragment, result))
        return self

    def __call__(self, url, headers=None, timeout=15.0):
        self.calls.append((url, dict(headers or {})))
        for fragment, result in self.routes:
            if fragment in url:
                if isinstance(result, list):
                    result = result.pop(0) if len(result) > 1 else result[0]
                if callable(result):
                    result = result(url)
                if isinstance(result, Exception):
                    raise result
                return result
        raise AssertionError(f"nieoczekiwane zapytanie sieciowe w tescie: {url}")

    def urls(self) -> list[str]:
        return [u for u, _ in self.calls]


def subdomain_fetch(ht=None, cs=None, crt=None) -> FakeFetch:
    """Domyslnie wszystkie trzy zrodla odpowiadaja poprawnie."""
    f = FakeFetch()
    f.on("hackertarget.com", ht or ok("hackertarget_ok.txt"))
    f.on("certspotter.com", cs or [ok("certspotter_page1.json"), ok("certspotter_page2.json"), ok("certspotter_empty.json")])
    f.on("crt.sh", crt or ok("crtsh_ok.json"))
    return f


def rdap_fetch(domain_json=None) -> FakeFetch:
    f = FakeFetch()
    f.on("data.iana.org", ok("rdap_bootstrap.json"))
    f.on("rdap.example-pir.test", domain_json or ok("rdap_domain.json"))
    return f


@pytest.fixture
def fake():
    return FakeFetch()


__all__ = ["FakeFetch", "FetchError", "Response", "ok", "fixture_text", "subdomain_fetch", "rdap_fetch"]
