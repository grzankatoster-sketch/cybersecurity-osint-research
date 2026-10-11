"""Integralność obserwacji (R1-A) i kontrakt pewności krawędzi (R1-B). Dane syntetyczne, zero sieci."""
from __future__ import annotations

import copy
import json
import math

import pytest

from entity_graph.correlate import record_from_node
from entity_graph.evidence import Decision, assess
from entity_graph.expand import HELD, Scope, Seed, expand
from entity_graph.export import render_html
from entity_graph.guardrails import AuditLog
from entity_graph.importers.base import finite_confidence
from entity_graph.model import Edge, Graph, Node, Status, check_confidence, parse_confidence
from entity_graph.normalize import EntityType as T
from entity_graph.transforms import Transform, TransformResult
from entity_graph.transforms.username import parse_scan

A = "https://alpha.example/u/ziarno7"      # kotwica (profil wskazany przez operatora)
B = "https://beta.example/u/ziarno_7"
C = "https://gamma.example/@zi7"
D = "https://delta.example/u/ziarno77"
E = "https://epsilon.example/u/eps7"


def profile(url, source, **attrs):
    return Node.make(T.URL, url, {"kind": "profile", "site": url.split("/")[2], **attrs}, source)


def merged(first: Node, second: Node) -> Node:
    g = Graph()
    g.add_node(copy.deepcopy(first))
    return g.add_node(copy.deepcopy(second))


def as_sets(node: Node) -> dict:
    return {k: {(str(e["value"]), frozenset(e["sources"])) for e in v} for k, v in node.observations.items()}


# --- R1-A: model obserwacji ---

OBS_A = dict(entity_kind="person", website="https://ziarno.example", insecure=False)
OBS_B = dict(entity_kind="organization", website="https://inna.example", insecure=True)


@pytest.mark.parametrize("order", ["AB", "BA"])
def test_conflicting_scalars_keep_both_provenances(order):
    a, b = profile(B, "zrodlo_a", **OBS_A), profile(B, "zrodlo_b", **OBS_B)
    node = merged(a, b) if order == "AB" else merged(b, a)
    obs = as_sets(node)
    for name in ("entity_kind", "website", "insecure"):
        assert {src for _, srcs in obs[name] for src in srcs} == {"zrodlo_a", "zrodlo_b"}
        assert len(obs[name]) == 2
    # żadna wartość nie wygrywa: sporne pola są nieznane, flaga TLS ostrożna
    assert "entity_kind" not in node.attrs and "website" not in node.attrs and node.attrs["insecure"] is True
    assert [c.split(":")[0] for c in node.conflicts()] == ["entity_kind", "website", "insecure"]


def test_merge_order_gives_identical_observation_record():
    a, b = profile(B, "zrodlo_a", **OBS_A), profile(B, "zrodlo_b", **OBS_B)
    ab, ba = merged(a, b), merged(b, a)
    assert as_sets(ab) == as_sets(ba) and ab.conflicts() == ba.conflicts() and ab.attrs == ba.attrs


def _decision_for(first: Node, second: Node):
    g = Graph()
    seed = g.add_node(Node.make(T.USERNAME, "ziarno7"))
    g.add_node(copy.deepcopy(first))
    cand = g.add_node(copy.deepcopy(second))
    g.add_edge(Edge(seed.id, cand.id, "has_account", "test", 0.95, "syntetyczne"))
    anchor = Seed("ziarno7", profiles=(A,), entity_kind="person").record()
    anchor = type(anchor)(**{**anchor.__dict__, "links": (B,)})   # kotwica deklaruje kandydata: mocny dowód kontroli
    return assess([anchor], record_from_node(g, cand))


def test_conflict_gives_same_cautious_decision_in_both_orders():
    a, b = profile(B, "zrodlo_a", **OBS_A), profile(B, "zrodlo_b", **OBS_B)
    ab, ba = _decision_for(a, b), _decision_for(b, a)
    assert ab.decision is ba.decision is Decision.REVIEW
    assert ab.level == ba.level and ab.reasons == ba.reasons
    assert [c.to_dict() for c in ab.contradictions] == [c.to_dict() for c in ba.contradictions]
    assert any(c.kind == "observations" and c.hard for c in ab.contradictions)
    # ten sam scenariusz bez sprzeczności nadal pozwala rozwinąć
    assert _decision_for(a, profile(B, "zrodlo_c", **OBS_A)).decision is Decision.EXPAND


def test_same_value_written_differently_is_not_a_conflict():
    a = profile(B, "zrodlo_a", website="https://ziarno.example/", display_name="Ala  Testowa")
    b = profile(B, "zrodlo_b", website="ziarno.example", display_name="ala testowa")
    node = merged(a, b)
    assert node.conflicts() == []
    assert node.attrs["website"] and node.attrs["display_name"]
    assert set(node.observations["website"][0]["sources"]) == {"zrodlo_a", "zrodlo_b"}


def test_observations_roundtrip_and_old_graph_reads_deliberately(tmp_path):
    g = Graph()
    g.add_node(profile(B, "zrodlo_a", **OBS_A))
    g.add_node(profile(B, "zrodlo_b", **OBS_B))
    path = tmp_path / "graph.json"
    g.save(path)
    data = json.loads(path.read_text(encoding="utf-8"))
    assert data["schema"] == 1 and data["observation_model"] == 1
    again = Graph.load(path)
    assert not again.legacy_observations
    assert again.nodes[f"url:{B.split('//')[1]}"].conflicts() == g.nodes[f"url:{B.split('//')[1]}"].conflicts()

    # graf zapisany przed modelem obserwacji: czytany, oznaczony, wartość attrs = jedna obserwacja jego źródeł
    old = {"schema": 1, "meta": {}, "nodes": [{"id": "url:beta.example/u/ziarno_7", "type": "url",
                                               "value": B, "attrs": {"kind": "profile", "entity_kind": "person"},
                                               "sources": ["stare_zrodlo"], "first_seen": "2026-10-01"}],
           "edges": [], "runs": []}
    legacy = Graph.from_dict(old)
    assert legacy.legacy_observations
    node = legacy.nodes["url:beta.example/u/ziarno_7"]
    assert node.attrs["entity_kind"] == "person" and node.conflicts() == []
    legacy.add_node(profile(B, "nowe_zrodlo", entity_kind="organization"))
    assert node.conflicts() == ["entity_kind: organization [nowe_zrodlo] / person [stare_zrodlo]"]


@pytest.mark.parametrize("mutate", [
    lambda d: d.pop("observation_model"),                                       # obserwacje bez deklaracji modelu
    lambda d: d.__setitem__("observation_model", 2),
    lambda d: d["nodes"][0].__setitem__("observations", {"nie_pole": [{"value": "x", "sources": []}]}),
    lambda d: d["nodes"][0]["observations"]["insecure"][0].__setitem__("value", "tak"),
    lambda d: d["nodes"][0]["observations"]["entity_kind"].__setitem__(0, {"value": "", "sources": ["s"]}),
])
def test_malformed_observations_are_rejected(mutate):
    g = Graph()
    g.add_node(profile(B, "zrodlo_a", **OBS_A))
    g.add_node(profile(B, "zrodlo_b", **OBS_B))
    data = json.loads(json.dumps(g.to_dict()))
    mutate(data)
    with pytest.raises(ValueError):
        Graph.from_dict(data)


# --- R1-A: rozszerzanie rekordów ---

class TaggedAdapter:
    """Atrapa adaptera: źródło węzła zawiera odpytany identyfikator, więc pochodzenie obserwacji jest rozróżnialne."""

    def __init__(self, world):
        self.world, self.calls = world, []

    def __call__(self, node, ctx):
        self.calls.append(node.value)
        found = self.world.get(node.value)
        if not found:
            return TransformResult(Status.NOT_FOUND, note="atrapa: jawnie brak")
        res = TransformResult(Status.FOUND)
        for url, attrs in found:
            p = Node.make(T.URL, url, {"kind": "profile", "site": url.split("/")[2], **attrs}, f"fake:{node.value}")
            res.nodes.append(p)
            res.edges.append(ctx.edge("fake_scan", node, p, "has_account", 0.95, "atrapa"))
        return res

    def registry(self):
        return {"fake_scan": Transform("fake_scan", (T.USERNAME,), "atrapa", False, self)}


def run(tmp_path, make_ctx, world, **scope):
    adapter = TaggedAdapter(world)
    audit = AuditLog(tmp_path / "audit.jsonl", "tester")
    audit.start("test integralności obserwacji na danych syntetycznych", [], {})
    graph = Graph({"purpose": "test"})
    rep = expand(graph, Seed("ziarno7", profiles=(A,)), make_ctx(), audit,
                 Scope(adapters=("fake_scan",), auto_continue=True, **scope), registry=adapter.registry())
    return graph, rep, adapter


def rows_for(rep, url):
    return [c for rd in rep["rounds"] for c in rd["candidates"] if c.get("profile") == url]


def late_conflict_world(first_kind, later_kind):
    """Runda 1: kotwica A deklaruje D i B; D i B linkują do A -> obie "rozwin". Z D wynika zapytanie eps7, z B: zi7.
    Runda 2: eps7 (odpytany pierwszy) przynosi nową, sprzeczną obserwację B; zi7 zależy od B."""
    return {
        "ziarno7": [(A, {"links": [D, B]}), (D, {"links": [A, E]}), (B, {"links": [A, C], "entity_kind": first_kind})],
        "eps7": [(B, {"links": [A, C], "entity_kind": later_kind})],
        "zi7": [(C, {})],
    }


def test_later_conflict_forces_reassessment_and_holds_dependent_expansion(tmp_path, make_ctx):
    graph, rep, adapter = run(tmp_path, make_ctx, late_conflict_world("person", "organization"), max_rounds=3)
    first, *later = rows_for(rep, B)
    assert first["decision"] == "rozwin" and first["round"] == 1
    assert later and later[0]["reassessed"] and later[0]["decision"] == "przeglad"
    assert later[0]["previous"]["decision"] == "rozwin" and later[0]["basis"] != first["basis"]
    assert any(c["kind"] == "observations" for c in later[0]["contradictions"])
    # zapytanie zależne od B nie zostało wykonane
    assert "zi7" not in adapter.calls and adapter.calls == ["ziarno7", "eps7"]
    assert [h["identifier"] for h in rep["held"]] == ["zi7"] and rep["held"][0]["why"] == HELD
    assert rep["totals"]["held"] == 1 and rep["totals"]["decisions"]["rozwin"] == 1   # tylko D
    # czytelny zapis wcześniejszej decyzji: w raporcie rundy 1 i w dowodzie krawędzi
    assert rep["rounds"][0]["candidates"][-1]["decision"] == "rozwin"
    edge = next(e for e in graph.edges.values() if e.relation == "candidate_match" and e.dst.endswith("ziarno_7"))
    assert "runda 1: decyzja rozwin" in edge.evidence and "ponowna ocena" in edge.evidence
    assert "Wstrzymane rozwinięcia" in render_html(graph)


@pytest.mark.parametrize("kinds", [("person", "organization"), ("organization", "person")])
def test_conflict_order_gives_same_decision_and_both_provenances(tmp_path, make_ctx, kinds):
    graph, rep, adapter = run(tmp_path, make_ctx, late_conflict_world(*kinds), max_rounds=3)
    node = graph.nodes["url:beta.example/u/ziarno_7"]
    srcs = {s for e in node.observations["entity_kind"] for s in e["sources"]}
    assert {"fake:ziarno7", "fake:eps7"} <= srcs
    assert rows_for(rep, B)[-1]["decision"] == "przeglad" and "zi7" not in adapter.calls


def test_new_observation_without_conflict_still_expands(tmp_path, make_ctx):
    world = late_conflict_world("person", "person")
    graph, rep, adapter = run(tmp_path, make_ctx, world, max_rounds=3)
    assert "zi7" in adapter.calls and not rep["held"]
    assert rows_for(rep, B)[-1]["decision"] == "rozwin"
    assert graph.nodes["url:beta.example/u/ziarno_7"].conflicts() == []


def test_same_values_from_new_source_reassess_without_conflict(tmp_path, make_ctx):
    world = {"ziarno7": [(A, {"links": [B]}), (B, {"links": [A, C]})], "zi7": [(B, {"links": [A, C]})]}
    _, rep, _ = run(tmp_path, make_ctx, world)
    first, second = rows_for(rep, B)
    assert second["reassessed"] and second["decision"] == first["decision"] == "rozwin" and not rep["held"]
    assert set(second["sources"]) == {"fake:ziarno7", "fake:zi7"}


def test_pending_from_demoted_candidate_is_marked(tmp_path, make_ctx):
    graph, rep, adapter = run(tmp_path, make_ctx, late_conflict_world("person", "organization"), max_rounds=2)
    assert "zi7" not in adapter.calls
    assert not any(p["identifier"] == "zi7" and "held" not in p for p in rep["pending"])


# --- R1-B: kontrakt pewności ---

@pytest.mark.parametrize("bad", [float("nan"), float("inf"), float("-inf"), True, False, "0.5", None, 1.5, -0.1])
def test_edge_rejects_values_outside_contract(bad):
    with pytest.raises(ValueError):
        Edge("a", "b", "r", "s", bad, "")
    with pytest.raises(ValueError):
        check_confidence(bad)


def test_valid_confidence_survives_json_roundtrip(tmp_path):
    g = Graph()
    a, b = g.add_node(Node.make(T.DOMAIN, "a.example")), g.add_node(Node.make(T.DOMAIN, "b.example"))
    g.add_edge(Edge(a.id, b.id, "r", "s", 0.1234, ""))
    g.add_edge(Edge(b.id, a.id, "r", "s", 1, ""))
    g.save(tmp_path / "g.json")
    again = Graph.load(tmp_path / "g.json")
    assert sorted(e.confidence for e in again.edges.values()) == [0.123, 1.0]


@pytest.mark.parametrize("raw", ["NaN", "Infinity", "-Infinity", "true", '"0.9"', "null", "7"])
def test_graph_file_with_invalid_confidence_is_rejected(tmp_path, raw):
    text = ('{"schema": 1, "nodes": [{"id": "domain:a.example", "type": "domain", "value": "a.example"},'
            '{"id": "domain:b.example", "type": "domain", "value": "b.example"}], "edges": [{"src": "domain:a.example",'
            f'"dst": "domain:b.example", "relation": "r", "source": "s", "confidence": {raw}}}], "runs": []}}')
    (tmp_path / "g.json").write_text(text, encoding="utf-8")
    with pytest.raises(ValueError, match="pewność"):
        Graph.load(tmp_path / "g.json")


def test_save_never_writes_nan(tmp_path):
    g = Graph()
    g.add_node(Node.make(T.DOMAIN, "a.example", {"x": float("nan")}))
    with pytest.raises(ValueError):
        g.save(tmp_path / "g.json")
    assert not (tmp_path / "g.json").exists()


@pytest.mark.parametrize("raw,expected", [
    (0.7, 0.7), ("0.7", 0.7), (None, 0.0), ("", 0.0), (1, 1.0),
    (float("nan"), None), ("Infinity", None), (True, None), (1.5, None), ("abc", None), ([0.5], None)])
def test_external_confidence_parser(raw, expected):
    assert parse_confidence(raw) == expected and finite_confidence(raw) == expected


def test_scan_rows_with_invalid_confidence_are_errors_not_hits():
    rows = [{"site": f"S{i}", "url": f"https://s{i}.example/x", "status": "FOUND", "confidence": c}
            for i, c in enumerate([True, float("nan"), "Infinity", 1.5, 0.9])]
    hits, counts = parse_scan({"results": {"x": rows}}, 0.6)
    assert [h["site"] for h in hits] == ["S4"] and counts["ERROR"] == 4
    assert all(isinstance(h["confidence"], float) and math.isfinite(h["confidence"]) for h in hits)
