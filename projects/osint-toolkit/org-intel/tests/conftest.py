from __future__ import annotations

import copy
import json
from pathlib import Path

import pytest

from org_intel.http import Response
from org_intel.parsers import ParseResult, parse_data
from org_intel.store import Store

FIXTURES = Path(__file__).parent / "fixtures"

# Wymyslone numery z POPRAWNYMI sumami kontrolnymi.
KRS = "0000123456"
NIP = "5271001238"
REGON = "360123459"


def load_fixture(name: str):
    return json.loads((FIXTURES / name).read_text(encoding="utf-8"))


class FakeClient:
    """Falszywy klient HTTP: zaprogramowane odpowiedzi, zapamietuje zapytania. Zero sieci."""

    def __init__(self, responses: list[Response] | Response):
        self.responses = responses if isinstance(responses, list) else [responses]
        self.calls: list[tuple[str, dict[str, str]]] = []

    def get(self, url, headers=None):
        self.calls.append((url, dict(headers or {})))
        if len(self.responses) > 1:
            return self.responses.pop(0)
        return self.responses[0]


class FakeResolver:
    def __init__(self, records: list[str] | None = None):
        self.records = records or []
        self.calls: list[str] = []

    def txt(self, name: str) -> list[str]:
        self.calls.append(name)
        return list(self.records)


class ForbiddenClient:
    """Klient, ktorego uzycie oznacza blad testu (polecenia offline nie moga dotykac sieci)."""

    def __init__(self):
        self.calls = 0

    def get(self, url, headers=None):
        self.calls += 1
        raise AssertionError("niedozwolone zapytanie sieciowe w trybie offline")


@pytest.fixture
def own_doc():
    return load_fixture("own_format.json")


@pytest.fixture
def hibp_api():
    return load_fixture("hibp_api.json")


@pytest.fixture
def hibp_monitor():
    return load_fixture("hibp_monitor.json")


@pytest.fixture
def ingest(tmp_path):
    def run(doc, store: Store | None = None) -> tuple[Store, ParseResult]:
        store = store or Store(tmp_path / "store.json")
        result = parse_data(copy.deepcopy(doc), known_orgs=list(store.organizations.values()))
        store.apply(result)
        return store, result

    return run


@pytest.fixture
def loaded(own_doc, ingest):
    return ingest(own_doc)[0]
