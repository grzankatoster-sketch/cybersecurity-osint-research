from __future__ import annotations

import pytest

from hibp_monitor.breaches import fetch_catalog
from hibp_monitor.cli import main
from hibp_monitor.http import HibpError, Response


class _StaticClient:
    """Klient bez sieci: na kazde zapytanie zwraca te sama odpowiedz."""

    def __init__(self, resp: Response):
        self.resp = resp
        self.calls: list[str] = []

    def get(self, url, headers=None):
        self.calls.append(url)
        return self.resp


def test_catalog_404_is_error_not_empty_catalog():
    c = _StaticClient(Response(404, ""))
    result = None
    raised = None
    try:
        result = fetch_catalog(c)
    except HibpError as exc:
        raised = exc
    assert raised is not None, f"404 dla pelnego katalogu stal sie wynikiem: {result!r}"
    assert raised.status == 404


def test_cli_catalog_404_returns_error_code_and_no_empty_listing(capsys):
    c = _StaticClient(Response(404, ""))
    code = main(["breaches", "--catalog"], client=c, pause=lambda s: None)
    cap = capsys.readouterr()
    assert code != 0, "blad 404 katalogu zakonczony kodem 0 jak poprawny wynik"
    assert "0 wyciekow" not in cap.out
