from __future__ import annotations

import pytest

from hibp_monitor.breaches import empty_state, check_domain, fetch_domain_breaches
from hibp_monitor.http import HibpError, Response


class _Fixed:
    """Klient zwracajacy zawsze te sama odpowiedz. Zero sieci."""

    def __init__(self, resp: Response):
        self.resp = resp

    def get(self, url, headers=None):
        return self.resp


BAD_BODIES = [
    '["Adobe"]',
    '[1, 2]',
    '[null]',
    '[["Adobe"]]',
    '[{"Title": "Bez nazwy"}]',
]


@pytest.mark.parametrize("body", BAD_BODIES)
def test_unexpected_item_types_are_error_not_empty(body):
    client = _Fixed(Response(200, body, {}))
    result = None
    raised = False
    try:
        result = fetch_domain_breaches(client, "adobe.com")
    except HibpError:
        raised = True
    assert raised, f"Odpowiedz 200 z nieoczekiwanymi elementami {body!r} dala wynik {result!r} zamiast bledu"


@pytest.mark.parametrize("body", BAD_BODIES)
def test_check_domain_does_not_record_empty_baseline(body):
    client = _Fixed(Response(200, body, {}))
    state = empty_state()
    raised = False
    try:
        check_domain(client, state, "adobe.com")
    except HibpError:
        raised = True
    assert raised and "adobe.com" not in state["domains"], (
        f"Zepsuta odpowiedz {body!r} zostala zapisana jako brak wyciekow"
    )


def test_genuinely_empty_list_is_still_no_breaches():
    client = _Fixed(Response(200, "[]", {}))
    assert fetch_domain_breaches(client, "adobe.com") == []
