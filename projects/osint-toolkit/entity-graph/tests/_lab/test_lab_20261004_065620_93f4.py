"""hibp-monitor: częściowy wpis domeny (brak total_breaches/new albo null) nie może dać NOT_FOUND."""
from entity_graph.importers import hibp
from entity_graph.importers.base import ImportCtx
from entity_graph.model import Status

NOW = "2026-10-03T12:00:00+00:00"


def _statuses(data):
    imp = hibp.parse(data, ImportCtx(hibp.TOOL, "h.json", NOW))
    return [s for _, s, _ in imp.runs]


def test_monitor_explicit_zero_is_not_found():
    data = {"domains": [{"domain": "acme-testowa.example", "total_breaches": 0, "new": []}]}
    assert _statuses(data) == [Status.NOT_FOUND]


def test_monitor_entry_with_null_sections_is_not_negative():
    data = {"domains": [{"domain": "acme-testowa.example", "total_breaches": None, "new": None}]}
    statuses = _statuses(data)
    assert len(statuses) == 1
    assert statuses[0] is not Status.NOT_FOUND


def test_monitor_entry_without_sections_is_not_negative():
    data = {"domains": [{"domain": "acme-testowa.example"}]}
    statuses = _statuses(data)
    assert len(statuses) == 1
    assert statuses[0] is not Status.NOT_FOUND
