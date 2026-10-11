"""username_scan: pewność spoza zakresu (Infinity) to wynik niejednoznaczny, nie trafienie FOUND."""
import json
import math
from pathlib import Path

from entity_graph.model import Node, Status
from entity_graph.normalize import EntityType as T
from entity_graph.transforms import REGISTRY


def _writes(payload: str):
    from conftest import writes_json_to_flag   # zapis w podkatalogu --results-dir, jak prawdziwy username-engine
    return writes_json_to_flag(payload)


def _scan(make_ctx, rows):
    payload = json.dumps({"results": {"x": rows}})   # json.dumps zapisuje inf jako literał Infinity
    ctx = make_ctx(handlers={"username_engine": _writes(payload)})
    return REGISTRY["username_scan"].run(Node.make(T.USERNAME, "x"), ctx)


def test_infinite_confidence_is_not_a_found_hit(make_ctx):
    rows = [
        {"site": "GitHub", "url": "https://github.com/x", "status": "FOUND", "confidence": float("inf")},
        {"site": "Twitter", "url": "https://x.com/x", "status": "NOT_FOUND", "confidence": 0.0},
    ]
    r = _scan(make_ctx, rows)
    assert r.status in (Status.UNKNOWN, Status.ERROR), r.status
    assert all(math.isfinite(e.confidence) and 0.0 <= e.confidence <= 1.0 for e in r.edges), \
        [e.confidence for e in r.edges]


def test_infinite_confidence_as_text_is_not_a_found_hit(make_ctx):
    rows = [
        {"site": "GitHub", "url": "https://github.com/x", "status": "FOUND", "confidence": "Infinity"},
        {"site": "Twitter", "url": "https://x.com/x", "status": "NOT_FOUND", "confidence": 0.0},
    ]
    r = _scan(make_ctx, rows)
    assert r.status in (Status.UNKNOWN, Status.ERROR), r.status
    assert all(math.isfinite(e.confidence) and 0.0 <= e.confidence <= 1.0 for e in r.edges), \
        [e.confidence for e in r.edges]
