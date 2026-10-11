"""Rozszerzanie rekordów: test SIECIOWY (prawdziwy username-engine, publiczne serwisy). Domyślnie pomijany.

Uruchomienie: EG_NETWORK_TESTS=1 py -m pytest -q tests/test_expand_network.py
Cel: konto publicznej ORGANIZACJI (mozilla) z kotwicą https://github.com/mozilla, mały zakres (kategoria coding,
30 serwisów), jedna runda. Sprawdza kontrakt na prawdziwych odpowiedziach, nie skuteczność dopasowania."""
from __future__ import annotations

import os

import pytest

from entity_graph.expand import UNRESOLVED, Scope, Seed, expand
from entity_graph.guardrails import AuditLog, verify_audit
from entity_graph.model import Graph
from entity_graph.transforms import Context, Settings

pytestmark = pytest.mark.skipif(os.environ.get("EG_NETWORK_TESTS") != "1",
                                reason="test sieciowy: ustaw EG_NETWORK_TESTS=1")


def test_live_expansion_contract(tmp_path):
    audit = AuditLog(tmp_path / "audit.jsonl", "test-sieciowy")
    audit.start("test kontraktu rozszerzania na publicznym koncie organizacji", [], {})
    ctx = Context(settings=Settings(ue_tags="coding", ue_limit=30, ue_timeout=300), tmp_dir=tmp_path)
    graph = Graph({"purpose": "test sieciowy"})
    seed = Seed("mozilla", profiles=("https://github.com/mozilla",), website="https://www.mozilla.org",
                entity_kind="organization")
    rep = expand(graph, seed, ctx, audit, Scope(max_rounds=1, max_queries=1, max_seconds=600))
    [q] = rep["rounds"][0]["queries"]
    assert q["adapter"] == "username_scan" and q["status"] in ("FOUND", "NOT_FOUND", "UNKNOWN", "ERROR")
    if q["status"] in ("UNKNOWN", "ERROR"):
        assert q["interpretation"] == UNRESOLVED
    # A network test that only accepts ERROR/UNKNOWN does not prove the real integration works.
    assert q["status"] == "FOUND", q
    assert "github.com/mozilla" in rep["anchors_found"], rep["anchors_missing"]
    for c in rep["rounds"][0]["candidates"]:
        if c.get("decision") == "rozwin":
            assert c["level"] == "mocne" and not c["contradictions"]
    ok, msg = verify_audit(tmp_path / "audit.jsonl")
    assert ok, msg
    print({"status": q["status"], "candidates": len(rep["rounds"][0]["candidates"]),
           "decisions": rep["totals"]["decisions"], "anchors_found": rep["anchors_found"],
           "stop": rep["stop_reason"]})
