"""Rozszerzanie rekordów sterowane dowodami: testy SYMULOWANE (atrapa adaptera, zero sieci).
Testy sieciowe są osobno: test_expand_network.py (tylko z EG_NETWORK_TESTS=1)."""
from __future__ import annotations

import json

import pytest

from entity_graph.cli import build_parser, cmd_rozszerz
from entity_graph.evidence import (COPYABLE_CAP, Decision, Level, Record, assess, compare, handle_from_url, weight)
from entity_graph.expand import UNRESOLVED, Scope, Seed, expand
from entity_graph.export import render_html
from entity_graph.guardrails import AuditLog, verify_audit
from entity_graph.model import Graph, Node, Status
from entity_graph.normalize import EntityType as T
from entity_graph.transforms import Transform, TransformResult

A = "https://alpha.example/u/ziarno7"      # profil wskazany przez operatora (kotwica)
B = "https://beta.example/u/ziarno_7"
C = "https://gamma.example/@zi7"
D = "https://delta.example/zi7"
SITE = "https://ziarno.example"
AV = "u-" + "a" * 32


def prof(url, conf=0.95, **attrs):
    return (url, attrs, conf)


class FakeAdapter:
    """Atrapa skonfigurowanego adaptera: {identyfikator: [profile]} albo {identyfikator: Status} (błąd źródła)."""

    def __init__(self, world, raise_on=None):
        self.world, self.calls, self.raise_on = world, [], raise_on

    def __call__(self, node, ctx):
        self.calls.append(node.value)
        if node.value == self.raise_on:
            raise KeyboardInterrupt
        found = self.world.get(node.value)
        if isinstance(found, Status):
            return TransformResult.failed(found, "atrapa: źródło niedostępne (HTTP 429)")
        if not found:
            return TransformResult(Status.NOT_FOUND, note="atrapa: jawnie brak")
        res = TransformResult(Status.FOUND)
        for url, attrs, conf in found:
            p = Node.make(T.URL, url, {"kind": "profile", "site": url.split("/")[2], **attrs}, "fake_scan")
            res.nodes.append(p)
            res.edges.append(ctx.edge("fake_scan", node, p, "has_account", conf, "atrapa"))
        return res

    def registry(self):
        return {"fake_scan": Transform("fake_scan", (T.USERNAME,), "atrapa", False, self)}


def run(tmp_path, make_ctx, world, seed=None, raise_on=None, clock=None, should_stop=None, **scope):
    adapter = FakeAdapter(world, raise_on)
    audit = AuditLog(tmp_path / "audit.jsonl", "tester")
    audit.start("test rozszerzania rekordów na danych syntetycznych", [], {})
    graph = Graph({"purpose": "test"})
    kwargs = {}
    if clock:
        kwargs["clock"] = clock
    if should_stop:
        kwargs["should_stop"] = should_stop
    rep = expand(graph, seed or Seed("ziarno7", profiles=(A,)), make_ctx(), audit,
                 Scope(adapters=("fake_scan",), **scope), registry=adapter.registry(), **kwargs)
    return graph, rep, adapter


def cands(rep, rnd=1):
    return {c["profile"]: c for c in rep["rounds"][rnd - 1]["candidates"]}


# --- ocena dowodów (evidence.py) ---

def test_copied_fields_never_reach_strong_and_are_one_dependent_group():
    copy = dict(display_name="Ala Testowa", avatar_hash=AV, website="https://pracodawca.example",
                bio_fingerprint=tuple("abcdef"))
    a, b = Record(url="alpha.example/x", site="A", **copy), Record(url="beta.example/x", site="B", **copy)
    signals, _ = compare(a, b)
    assert {s.kind for s in signals} == {"name_and_avatar", "same_domain", "similar_bio"}
    assert all(s.copyable for s in signals)
    assert weight(signals) <= COPYABLE_CAP          # dawniej 0.93/0.90: kopie sumowały się jak niezależne dowody
    out = assess([Record(anchor=True, **copy)], Record(url="beta.example/x", site="B", reliability=0.95, **copy))
    assert out.level is Level.MODERATE and out.decision is Decision.REVIEW
    assert any("skopiować" in r for r in out.reasons)


def test_one_way_link_from_candidate_is_only_a_claim_but_from_anchor_is_strong():
    anchor = Record(url="alpha.example/u/ziarno7", links=(B,), anchor=True, reliability=0.95)
    cand = Record(url="beta.example/u/ziarno_7", reliability=0.95)
    assert assess([anchor], cand).decision is Decision.EXPAND
    claimant = Record(url="beta.example/u/ziarno_7", links=(A,), reliability=0.95)
    out = assess([Record(url="alpha.example/u/ziarno7", anchor=True)], claimant)
    assert out.level is Level.MODERATE and out.decision is Decision.REVIEW


def test_contradiction_and_weak_source_go_to_review():
    anchor = Record(url="alpha.example/u/ziarno7", links=(B,), entity_kind="person", anchor=True)
    org = Record(url="beta.example/u/ziarno_7", links=(A,), entity_kind="organization", reliability=0.95)
    out = assess([anchor], org)
    assert out.decision is Decision.REVIEW and any(c.hard for c in out.contradictions)
    assert weight(*compare(anchor, org)) <= 0.3
    weak = Record(url="beta.example/u/ziarno_7", links=(A,), reliability=0.4)
    assert assess([anchor], weak).decision is Decision.REVIEW
    insecure = Record(url="beta.example/u/ziarno_7", links=(A,), reliability=0.95, insecure=True)
    assert assess([anchor], insecure).decision is Decision.REVIEW


def test_nick_only_and_shared_employer_site():
    assert assess([Record(anchor=True)], Record(url="beta.example/x", reliability=0.9)).decision is Decision.STOP
    employer = assess([Record(website="https://pracodawca.example", anchor=True)],
                      Record(url="beta.example/x", website="https://pracodawca.example", reliability=0.9))
    assert employer.decision is Decision.REVIEW and employer.copy_only


def test_handle_from_url():
    assert handle_from_url("https://gamma.example/@zi7") == "zi7"
    assert handle_from_url("https://alpha.example/u/ziarno7") == "ziarno7"
    assert handle_from_url("https://x.example/a/b/c") is None
    assert handle_from_url("https://x.example/login") is None


# --- silnik rund (expand.py) ---

def test_strong_match_expands_and_candidate_stays_hypothesis(tmp_path, make_ctx):
    world = {"ziarno7": [prof(A, links=[B]), prof(B, links=[A])]}
    graph, rep, _ = run(tmp_path, make_ctx, world)
    c = cands(rep)
    assert c[A.replace("https://", "https://")]["role"] == "kotwica"
    assert c[B]["decision"] == "rozwin" and c[B]["level"] == "mocne"
    edges = [e for e in graph.edges.values() if e.relation == "candidate_match"]
    assert edges and all(e.confidence == 0.0 and "hipoteza" in e.evidence for e in edges)
    assert not any(e.relation in ("confirmed_profile",) for e in graph.edges.values())


def test_copied_profile_goes_to_review_not_expansion(tmp_path, make_ctx):
    copy = dict(display_name="Ala Testowa", avatar_hash=AV, website=SITE)
    seed = Seed("ziarno7", display_name="Ala Testowa", website=SITE)
    world = {"ziarno7": [prof(B, **copy), prof(C, **copy)]}
    _, rep, _ = run(tmp_path, make_ctx, world, seed=seed, auto_continue=True)
    assert {c["decision"] for c in cands(rep).values()} == {"przeglad"}
    assert all(c["copy_only"] for c in cands(rep).values())
    assert len(rep["rounds"]) == 1 and rep["stop_reason"] == "brak nowych identyfikatorów do zbadania"


def test_conflicting_entity_kind_blocks_expansion(tmp_path, make_ctx):
    seed = Seed("ziarno7", profiles=(A,), entity_kind="person")
    world = {"ziarno7": [prof(A, links=[B]), prof(B, links=[A, C], entity_kind="organization")]}
    _, rep, adapter = run(tmp_path, make_ctx, world, seed=seed, auto_continue=True)
    assert cands(rep)[B]["decision"] == "przeglad"
    assert any(x["hard"] for x in cands(rep)[B]["contradictions"])
    assert adapter.calls == ["ziarno7"]          # sprzeczność: brak dalszych zapytań


def test_missing_data_nick_only_stops(tmp_path, make_ctx):
    world = {"ziarno7": [prof(B, links=[C]), prof(D)]}
    _, rep, adapter = run(tmp_path, make_ctx, world, seed=Seed("ziarno7"), auto_continue=True)
    assert {c["decision"] for c in cands(rep).values()} == {"zatrzymaj"}
    assert adapter.calls == ["ziarno7"]


def test_chain_ab_bc_does_not_confirm_ac_but_direct_evidence_does(tmp_path, make_ctx):
    world = {
        "ziarno7": [prof(A, links=[B, D]), prof(B, links=[A, C])],
        "zi7": [prof(C, links=[B]), prof(D)],            # C: mocne tylko z B; D: kotwica A linkuje bezpośrednio
    }
    _, rep, adapter = run(tmp_path, make_ctx, world, auto_continue=True, max_rounds=3)
    assert adapter.calls == ["ziarno7", "zi7"]
    r2 = cands(rep, 2)
    assert r2[C]["decision"] == "przeglad" and r2[C]["chain"]
    assert any("łańcuch" in r for r in r2[C]["reasons"])
    assert r2[D]["decision"] == "rozwin"
    assert rep["totals"]["decisions"]["rozwin"] == 2


def test_cycle_is_detected_and_not_queried_again(tmp_path, make_ctx):
    world = {
        "ziarno7": [prof(A, links=[B]), prof(B, links=[A, "https://gamma.example/ziarno7", C])],
        "zi7": [prof(C, links=["https://beta.example/u/ziarno7"])],
    }
    _, rep, adapter = run(tmp_path, make_ctx, world, auto_continue=True, max_rounds=5)
    assert adapter.calls == ["ziarno7", "zi7"]
    statuses = {f["identifier"]: f["status"] for f in rep["rounds"][0]["followups"]}
    assert "cykl" in statuses["ziarno7"] and statuses["zi7"] == "zaplanowany"


def test_duplicate_candidate_is_assessed_once(tmp_path, make_ctx):
    world = {"ziarno7": [prof(A, links=[B, C]), prof(B, links=[A, C])], "zi7": [prof(B, links=[A])]}
    _, rep, _ = run(tmp_path, make_ctx, world, auto_continue=True)
    assert B not in cands(rep, 2)
    assert any("duplikat" in s["why"] for s in rep["rounds"][1]["skipped"])


def test_auto_continue_off_only_proposes(tmp_path, make_ctx):
    world = {"ziarno7": [prof(A, links=[B]), prof(B, links=[A, C])], "zi7": [prof(D)]}
    _, rep, adapter = run(tmp_path, make_ctx, world)
    assert adapter.calls == ["ziarno7"]
    assert rep["pending"] == [{"identifier": "zi7", "origin": B}]
    assert "wyłączona" in rep["stop_reason"]


@pytest.mark.parametrize("limit, expected", [
    ({"max_queries": 1}, "limit zapytań"),
    ({"max_cost": 1.5}, "limit kosztu"),
    ({"max_rounds": 1}, "limit rund"),
])
def test_limits_stop_and_keep_pending(tmp_path, make_ctx, limit, expected):
    world = {"ziarno7": [prof(A, links=[B]), prof(B, links=[A, C])], "zi7": [prof(D)]}
    _, rep, adapter = run(tmp_path, make_ctx, world, auto_continue=True, **limit)
    assert adapter.calls == ["ziarno7"]
    assert rep["stop_reason"].startswith(expected)
    assert {p["identifier"] for p in rep["pending"]} == {"zi7"}


def test_time_limit_uses_clock(tmp_path, make_ctx):
    ticks = iter([0.0, 0.0, 100.0, 100.0, 100.0])
    world = {"ziarno7": [prof(A, links=[B]), prof(B, links=[A, C])], "zi7": [prof(D)]}
    _, rep, adapter = run(tmp_path, make_ctx, world, clock=lambda: next(ticks, 100.0), auto_continue=True,
                          max_seconds=50)
    assert adapter.calls == ["ziarno7"] and rep["stop_reason"].startswith("limit czasu")


def test_candidate_limit_per_round(tmp_path, make_ctx):
    world = {"ziarno7": [prof(B), prof(C), prof(D)]}
    _, rep, _ = run(tmp_path, make_ctx, world, max_candidates=1)
    assert len(cands(rep)) == 1
    assert sum("limit kandydatów" in s["why"] for s in rep["rounds"][0]["skipped"]) == 2


def test_cancel_via_should_stop(tmp_path, make_ctx):
    world = {"ziarno7": [prof(A, links=[B]), prof(B, links=[A, C])], "zi7": [prof(D)]}
    calls = []

    def stop():
        calls.append(1)
        return len(calls) > 1

    _, rep, adapter = run(tmp_path, make_ctx, world, should_stop=stop, auto_continue=True)
    assert adapter.calls == ["ziarno7"] and rep["stop_reason"] == "zatrzymane na żądanie użytkownika"


def test_ctrl_c_keeps_report(tmp_path, make_ctx):
    world = {"ziarno7": [prof(A, links=[B]), prof(B, links=[A, C])], "zi7": [prof(D)]}
    graph, rep, _ = run(tmp_path, make_ctx, world, raise_on="zi7", auto_continue=True)
    assert "Ctrl+C" in rep["stop_reason"] and graph.meta["expansion"] is rep
    ok, _ = verify_audit(tmp_path / "audit.jsonl")
    assert ok


def test_source_error_is_not_absence(tmp_path, make_ctx):
    world = {"ziarno7": [prof(A, links=[B]), prof(B, links=[A, C])], "zi7": Status.ERROR}
    _, rep, _ = run(tmp_path, make_ctx, world, auto_continue=True)
    q = rep["rounds"][1]["queries"][0]
    assert q["status"] == "ERROR" and q["interpretation"] == UNRESOLVED
    assert rep["totals"]["unresolved_queries"] == 1
    assert not rep["rounds"][1]["candidates"]          # błąd nie tworzy kandydatów ani decyzji "brak"


def test_missing_anchor_profile_is_reported(tmp_path, make_ctx):
    _, rep, _ = run(tmp_path, make_ctx, {"ziarno7": [prof(B, links=[A])]})
    assert rep["anchors_missing"] == ["alpha.example/u/ziarno7"]
    assert cands(rep)[B]["decision"] == "przeglad"     # link kandydata do kotwicy to tylko jego twierdzenie


def test_report_has_no_percentages_and_html_explains(tmp_path, make_ctx):
    world = {"ziarno7": [prof(A, links=[B]), prof(B, links=[A, C], display_name="<script>x</script>")]}
    graph, rep, _ = run(tmp_path, make_ctx, world)
    assert "%" not in json.dumps(rep, ensure_ascii=False)
    html = render_html(graph)
    assert "Rozszerzanie rekordów" in html and "<script>" not in html
    assert "rozwiń (dalsze zapytania)" in html and "Niewykonane propozycje" in html


def test_cli_rozszerz_writes_outputs_and_audit(tmp_path, make_ctx):
    adapter = FakeAdapter({"ziarno7": [prof(A, links=[B]), prof(B, links=[A])]})
    out = tmp_path / "sprawa"
    args = build_parser().parse_args(["rozszerz", "ziarno7", "--purpose", "audyt własnych kont firmy, zlecenie 2026/9",
                                      "--profile", A, "--adapters", "fake_scan", "--out", str(out)])
    assert cmd_rozszerz(args, make_ctx(), registry=adapter.registry()) == 0
    graph = json.loads((out / "graph.json").read_text(encoding="utf-8"))
    assert graph["meta"]["expansion"]["totals"]["decisions"]["rozwin"] == 1
    assert "Rozszerzanie rekordów" in (out / "report.html").read_text(encoding="utf-8")
    ok, _ = verify_audit(out / "audit.jsonl")
    lines = [json.loads(x) for x in (out / "audit.jsonl").read_text(encoding="utf-8").splitlines()]
    assert ok and lines[0]["event"] == "start" and any(x["event"] == "expansion_decision" for x in lines)


def test_cli_rozszerz_requires_purpose_and_known_adapter(tmp_path):
    from entity_graph.guardrails import GuardrailError
    args = build_parser().parse_args(["rozszerz", "x1", "--purpose", "test", "--out", str(tmp_path / "o")])
    with pytest.raises(GuardrailError):
        cmd_rozszerz(args)
    args = build_parser().parse_args(["rozszerz", "x1", "--purpose", "audyt własnych kont firmy X",
                                      "--adapters", "nie_ma", "--out", str(tmp_path / "o")])
    with pytest.raises(GuardrailError):
        cmd_rozszerz(args)
    assert not (tmp_path / "o").exists()


@pytest.mark.parametrize("confidence,insecure", [(0.2, False), (None, False), (0.95, True), (float('inf'), False)])
def test_unreliable_anchor_cannot_authorize_followup(confidence, insecure):
    anchor = Record(url="alpha.example/u/ziarno7", links=(B,), anchor=True,
                    reliability=confidence, insecure=insecure)
    cand = Record(url="beta.example/u/ziarno_7", links=(A,), reliability=0.95)
    result = assess([anchor], cand)
    assert result.decision is Decision.REVIEW
    assert any("kotwic" in reason for reason in result.reasons)


def test_insecure_anchor_does_not_launch_second_round(tmp_path, make_ctx):
    world = {"ziarno7": [prof(A, links=[B], insecure=True), prof(B, links=[A, C])]}
    _, rep, adapter = run(tmp_path, make_ctx, world, auto_continue=True)
    assert cands(rep)[B]["decision"] == "przeglad" and adapter.calls == ["ziarno7"]


@pytest.mark.parametrize("status", [Status.ERROR, Status.UNKNOWN, Status.NOT_FOUND])
def test_unsuccessful_adapter_cannot_inject_profiles(tmp_path, make_ctx, monkeypatch, status):
    original = FakeAdapter.__call__
    def with_bad_status(self, node, ctx):
        result = original(self, node, ctx)
        result.status = status
        return result
    monkeypatch.setattr(FakeAdapter, "__call__", with_bad_status)
    graph, rep, adapter = run(tmp_path, make_ctx,
                              {"ziarno7": [prof(A, links=[B]), prof(B, links=[A, C])]}, auto_continue=True)
    assert adapter.calls == ["ziarno7"] and not rep["rounds"][0]["candidates"]
    assert not [n for n in graph.nodes.values() if n.attrs.get("kind") == "profile"]


@pytest.mark.parametrize("field,value", [("max_seconds", float('nan')), ("max_cost", float('inf')),
                                         ("max_rounds", 1.5), ("max_queries", True)])
def test_invalid_budget_is_rejected_before_adapter_call(tmp_path, make_ctx, field, value):
    with pytest.raises(ValueError):
        run(tmp_path, make_ctx, {}, **{field: value})


def test_incompatible_adapter_is_rejected_before_creating_output(tmp_path):
    from entity_graph.guardrails import GuardrailError
    args = build_parser().parse_args(["rozszerz", "example.org", "--type", "domain",
                                      "--purpose", "audyt wlasnej domeny i konfiguracji",
                                      "--adapters", "username_scan", "--out", str(tmp_path / "out")])
    with pytest.raises(GuardrailError):
        cmd_rozszerz(args)
    assert not (tmp_path / "out").exists()
