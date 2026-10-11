from entity_graph.model import Status
from entity_graph.transforms.username import aggregate_status, parse_scan


def _scan(rows):
    return {"results": {"jan_kowalski": rows}}


def test_lowercase_found_above_threshold_is_a_hit():
    payload = _scan([
        {"site": "GitHub", "url": "https://github.com/jan_kowalski", "status": "found", "confidence": 0.99},
        {"site": "GitLab", "url": "https://gitlab.com/jan_kowalski", "status": "NOT_FOUND", "confidence": 0},
    ])
    hits, counts = parse_scan(payload, 0.6)
    status, _ = aggregate_status(hits, counts)
    assert [h["site"] for h in hits] == ["GitHub"], "pewne trafienie (status małymi literami) zostało zgubione"
    assert status is Status.FOUND


def test_lowercase_error_never_becomes_not_found():
    payload = _scan([
        {"site": "Reddit", "url": "https://reddit.com/u/jan_kowalski", "status": "error", "confidence": 0,
         "reason": "HTTP 429"},
        {"site": "X", "url": "https://x.com/jan_kowalski", "status": " Error ", "confidence": 0,
         "reason": "timeout"},
        {"site": "GitLab", "url": "https://gitlab.com/jan_kowalski", "status": "NOT_FOUND", "confidence": 0},
    ])
    hits, counts = parse_scan(payload, 0.6)
    status, _ = aggregate_status(hits, counts)
    assert not hits
    assert status in (Status.UNKNOWN, Status.ERROR), (
        f"błędy serwisów (429/timeout) zamieniły się w wynik negatywny: {status}")
