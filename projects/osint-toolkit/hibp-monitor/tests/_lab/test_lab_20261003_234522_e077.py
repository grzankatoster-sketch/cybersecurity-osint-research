"""Specyfikacja: odpowiedz 200 breacheddomain z wartoscia o zlym typie (tekst/obiekt zamiast listy) to blad, nie wynik."""
from __future__ import annotations

import json

import pytest

from hibp_monitor.cli import main
from hibp_monitor.domain_search import ENV_KEY, domain_search
from hibp_monitor.http import HibpError, Response

KEY = "atrapa-klucza-testowego"  # nie jest prawdziwym kluczem


class _StaticClient:
    """Klient bez sieci: na kazde zapytanie zwraca te sama odpowiedz."""

    def __init__(self, resp: Response):
        self.resp = resp
        self.calls: list[str] = []

    def get(self, url, headers=None):
        self.calls.append(url)
        return self.resp


@pytest.mark.parametrize("payload", [
    {"alice": "Adobe"},
    {"alice": {"Adobe": 1}},
    {"alice": ["Adobe"], "bob": "LinkedIn"},
])
def test_wrong_value_type_is_error_not_result(payload):
    c = _StaticClient(Response(200, json.dumps(payload)))
    result = None
    raised = None
    try:
        result = domain_search(c, "example.com", KEY)
    except HibpError as exc:
        raised = exc
    assert raised is not None, f"zly format odpowiedzi stal sie wynikiem: {result!r}"


def test_valid_response_still_aggregates():
    c = _StaticClient(Response(200, json.dumps({"alice": ["Adobe"], "bob": ["Adobe", "LinkedIn"]})))
    res = domain_search(c, "example.com", KEY)
    assert res.total_accounts == 2
    assert res.per_breach == {"Adobe": 2, "LinkedIn": 1}


def test_cli_wrong_value_type_returns_error_code(capsys):
    c = _StaticClient(Response(200, json.dumps({"alice": "Adobe"})))
    code = main(["domain-search", "example.com"], client=c, environ={ENV_KEY: KEY})
    cap = capsys.readouterr()
    assert code != 0, f"zly format zakonczony kodem 0 jak poprawny wynik: {cap.out!r}"
    assert "- A: 1" not in cap.out
    assert KEY not in cap.out + cap.err
