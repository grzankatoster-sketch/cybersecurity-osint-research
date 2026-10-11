from conftest import ok
from entity_graph.model import Node, Status
from entity_graph.normalize import EntityType as T
from entity_graph.transforms import REGISTRY

PARTIAL = [
    '{"status":"ok","data":{}}',
    '{"status":"ok","data":{"resource":"1.1.1.0/24"}}',
    '{"status":"ok","data":{"announced":true,"asns":[]}}',
    '{"status":"ok","data":{"asns":null,"resource":"1.1.1.0/24"}}',
    '{"status":"ok","data":{"announced":false,"asns":"brak"}}',
]


def test_partial_ripestat_is_not_negative(make_ctx):
    for body in PARTIAL:
        ctx = make_ctx(routes=[("stat.ripe.net", ok(body))])
        r = REGISTRY["ip_asn"].run(Node.make(T.IP, "1.1.1.1"), ctx)
        assert r.status is not Status.NOT_FOUND, f"częściowa odpowiedź dała wynik negatywny: {body}"
        assert r.status in (Status.ERROR, Status.UNKNOWN), body
        assert (r.node_attrs or {}).get("announced") is not False, body


def test_explicit_unannounced_still_not_found(make_ctx):
    body = '{"status":"ok","data":{"announced":false,"asns":[],"resource":"203.0.113.0/24"}}'
    ctx = make_ctx(routes=[("stat.ripe.net", ok(body))])
    r = REGISTRY["ip_asn"].run(Node.make(T.IP, "8.8.4.4"), ctx)
    assert r.status is Status.NOT_FOUND
