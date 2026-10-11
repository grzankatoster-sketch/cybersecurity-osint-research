"""Regresja po niezależnej weryfikacji (04.10): Gravatar, supported_inputs, mostek do grafu.

Każdy test najpierw opisuje stare (błędne) zachowanie, przechodzi po poprawce. Zero sieci:
klient HTTP to atrapa. Test modelu konsumenta importuje prawdziwy entity_graph (albo pomija z powodem).
"""
import asyncio
import json
import os
import sys

import pytest

from osint_connectors import Context, Finding, InputKind, SourceKind, Status, Subject, run
from osint_connectors.connectors.gravatar_public import GravatarPublic
from osint_connectors.integration import finding_to_run


class FakeHTTP:
    def __init__(self, payload, status_code=200):
        self.payload = payload
        self.status_code = status_code
        self.calls = 0

    async def get(self, url, *, headers=None, timeout=None):
        self.calls += 1
        return _Resp(self.status_code, self.payload)


class _Resp:
    def __init__(self, status_code, payload):
        self.status_code = status_code
        self._payload = payload

    def json(self):
        return self._payload


def _check(payload, kind=InputKind.EMAIL, status_code=200):
    http = FakeHTTP(payload, status_code)
    ctx = Context(salt="synthetic-review", http=http, timeout=1.0)
    result = asyncio.run(run([GravatarPublic()], Subject(kind, "fixture@example.test"), ctx))[0]
    return result, http


# --- Gravatar: wadliwy schemat NIE jest trafieniem (stare: wszystkie dawały FOUND 0.95) ---

@pytest.mark.parametrize("payload", [
    {"entry": "invalid"},     # entry nie jest listą
    {"entry": [None]},        # element nie jest obiektem
    {"entry": [{}]},          # obiekt bez pola identyfikującego
    {"entry": []},            # pusta lista
    {},                       # brak entry
])
def test_malformed_gravatar_not_found_as_hit(payload):
    result, _ = _check(payload)
    assert result.status is Status.ERROR, f"wadliwy schemat {payload} nie może dawać FOUND"
    assert result.error_kind == "schema_changed"


def test_valid_gravatar_is_found():
    result, _ = _check({"entry": [{"profileUrl": "https://gravatar.com/przyklad", "hash": "x"}]})
    assert result.status is Status.FOUND
    assert result.confidence == 0.95
    assert result.extra["public_profile_url"].endswith("/przyklad")


# --- runner egzekwuje supported_inputs PRZED wywołaniem konektora (stare: HTTP był wołany, FOUND) ---

def test_unsupported_input_does_not_call_client():
    http = FakeHTTP({"entry": [{"profileUrl": "https://x", "hash": "y"}]})
    ctx = Context(salt="s", http=http, timeout=1.0)
    result = asyncio.run(run([GravatarPublic()], Subject(InputKind.PHONE, "+000000000"), ctx))[0]
    assert result.status is Status.UNKNOWN
    assert result.error_kind == "unsupported_input"
    assert http.calls == 0, "konektor nie może dotknąć klienta HTTP dla niewspieranego typu wejścia"


# --- mostek do grafu: test na PRAWDZIWYM modelu entity-graph, nie przepisanych stałych ---

def _load_entity_graph():
    root = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    eg_src = os.path.join(root, "entity-graph", "src")
    if eg_src not in sys.path:
        sys.path.insert(0, eg_src)
    return pytest.importorskip("entity_graph.model", reason="entity-graph niedostępny w ścieżce")


def test_mapped_run_roundtrips_through_real_graph():
    model = _load_entity_graph()
    Graph, RunRecord, EGStatus = model.Graph, model.RunRecord, model.Status

    finding = Finding("gravatar_public", SourceKind.PASSIVE, Status.FOUND, 0.95, "refhash",
                      evidence="publiczny profil Gravatara istnieje",
                      extra={"public_profile_url": "https://gravatar.com/x"})
    mapped = finding_to_run(finding, "email:jan@example.test")

    # RunRecord(**mapped) NIE zadziała (node vs node_id, tekst vs enum) — budujemy poprawnie:
    with pytest.raises(TypeError):
        RunRecord(**mapped)

    rr = RunRecord(transform=mapped["transform"], node_id=mapped["node"],
                   status=EGStatus(mapped["status"]), timestamp=mapped["timestamp"],
                   note=mapped["note"], error=mapped["error"], stats=mapped["stats"])
    g = Graph()
    g.runs.append(rr)
    # round-trip przez prawdziwą serializację/deserializację modelu konsumenta
    g2 = Graph.from_dict(g.to_dict())
    assert len(g2.runs) == 1
    assert g2.runs[0].node_id == "email:jan@example.test"
    assert g2.runs[0].status is EGStatus.FOUND
    # zserializowany rekord modelu musi być identyczny z wyjściem mappera
    assert g2.runs[0].to_dict() == mapped


def test_status_names_match_entity_graph_values():
    model = _load_entity_graph()
    assert {s.name for s in Status} == {s.value for s in model.Status}
