"""dns_audit: raport bez sekcji rekordów DNS (pusty/okrojony JSON) to błąd formatu, nie 'domena nie istnieje'."""
import json

from entity_graph.model import Node, Status
from entity_graph.normalize import EntityType as T
from entity_graph.transforms import REGISTRY

DOM = lambda v="example.com": Node.make(T.DOMAIN, v)  # noqa: E731


def runner_with(stdout):
    return {"dns_audit": lambda cmd: (0, stdout, "")}


def run_dns(make_ctx, payload):
    ctx = make_ctx(handlers=runner_with(json.dumps(payload)))
    return REGISTRY["dns_audit"].run(DOM(), ctx)


def test_explicit_empty_zone_is_still_not_found(make_ctx):
    # kontrola: jawnie puste sekcje rekordów = prawdziwy brak rekordów
    payload = {"domain": "example.com", "summary": {"a": [], "aaaa": [], "ns": [], "soa": None,
                                                   "mx": [], "txt": [], "failed": {}}}
    assert run_dns(make_ctx, payload).status is Status.NOT_FOUND


def test_summary_without_record_sections_is_not_negative(make_ctx):
    payloads = [
        {"summary": {}},
        {"domain": "example.com", "summary": {"failed": {}}},
        {"domain": "example.com", "summary": {"spf": {"all": "-all"}}},
    ]
    for payload in payloads:
        r = run_dns(make_ctx, payload)
        assert r.status is not Status.NOT_FOUND, payload
        assert r.status is Status.ERROR and r.error, payload
