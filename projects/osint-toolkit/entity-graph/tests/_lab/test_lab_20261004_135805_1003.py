"""Wiek dowodu w korelacji: stare dowody istnienia konta obniżają pewność same_person i są oznaczane [stale]."""
from entity_graph.correlate import MAX_SCORE, correlate, evidence_age_days, score_pair, signals_between
from entity_graph.engine import Options, investigate, new_graph
from entity_graph.export import render_html
from entity_graph.guardrails import AuditLog
from entity_graph.model import Edge, Graph, Node
from entity_graph.normalize import EntityType as T

NOW = "2026-10-03T12:00:00+00:00"
DAYS_400_AGO = "2025-08-29T12:00:00+00:00"     # 400 dni przed NOW
DAYS_365_AGO = "2025-10-03T12:00:00+00:00"     # dokładnie 365 dni
FRESH = "2026-09-30T12:00:00+00:00"


def profile(graph, url, site, ts, conf=0.95, user="u", **attrs):
    u = graph.add_node(Node.make(T.USERNAME, user))
    p = graph.add_node(Node.make(T.URL, url, {"kind": "profile", "site": site, **attrs}, "username_scan"))
    graph.add_edge(Edge(u.id, p.id, "has_account", "username_scan", conf, "test", ts))
    return p


def pair(ts_a, ts_b, conf_a=0.95, conf_b=0.95):
    g = Graph()
    a = profile(g, "https://a.example/jan", "A", ts_a, conf_a, links=["https://b.example/jan"])
    b = profile(g, "https://b.example/jan", "B", ts_b, conf_b, links=["https://a.example/jan"])
    return g, a, b


def sp(g):
    return [e for e in g.edges.values() if e.relation == "same_person"]


def test_old_evidence_lowers_confidence_and_marks_stale():
    g, a, b = pair(DAYS_400_AGO, DAYS_400_AGO)
    [edge] = correlate(g, NOW)
    assert edge.confidence == 0.425                       # 0.85 * 0.5
    assert "[stale]" in edge.evidence and "400 dni" in edge.evidence
    assert "cross_link" in edge.evidence                 # dotychczasowy dowód zostaje


def test_fresh_evidence_unchanged_and_not_marked():
    g, _, _ = pair(FRESH, FRESH)
    [edge] = correlate(g, NOW)
    assert edge.confidence == 0.85 and "stale" not in edge.evidence


def test_one_stale_account_is_enough_and_cap_by_weakest_still_applies():
    g, a, b = pair(FRESH, DAYS_400_AGO, conf_a=0.9, conf_b=0.62)
    [edge] = correlate(g, NOW)
    assert edge.confidence == 0.31                        # min(0.85, 0.62) * 0.5, nigdy powyżej dowodu
    assert "[stale]" in edge.evidence and "B" in edge.evidence.split("[stale]", 1)[1]


def test_exactly_365_days_is_not_stale():
    g, _, _ = pair(DAYS_365_AGO, DAYS_365_AGO)
    [edge] = correlate(g, NOW)
    assert edge.confidence == 0.85 and "stale" not in edge.evidence


def test_unknown_or_broken_timestamp_is_not_treated_as_stale():
    for bad in ("", "zepsuty"):
        g, a, b = pair(FRESH, FRESH)
        for e in g.edges.values():
            if e.relation == "has_account":
                e.timestamp = bad                         # luka w danych: wiek nieznany
        assert evidence_age_days(g, a, NOW) is None
        [edge] = correlate(g, NOW)
        assert edge.confidence == 0.85 and "stale" not in edge.evidence


def test_naive_and_date_only_timestamps_are_utc():
    g, a, b = pair("2024-01-01", "2024-01-01T00:00:00")
    assert evidence_age_days(g, a, NOW) > 365 and evidence_age_days(g, b, NOW) > 365
    [edge] = correlate(g, NOW)
    assert edge.confidence == 0.425 and "[stale]" in edge.evidence


def test_future_timestamp_is_age_zero_and_never_raises_score():
    g, a, b = pair("2030-01-01T00:00:00+00:00", FRESH)
    assert evidence_age_days(g, a, NOW) == 0
    [edge] = correlate(g, NOW)
    assert edge.confidence == 0.85 and "stale" not in edge.evidence


def test_freshest_account_evidence_wins_over_older_conflicting_one():
    g, a, b = pair(DAYS_400_AGO, FRESH)
    other = g.add_node(Node.make(T.USERNAME, "jan_k"))
    g.add_edge(Edge(other.id, a.id, "has_account", "username_scan", 0.95, "ponowny skan", FRESH))
    assert evidence_age_days(g, a, NOW) < 30
    [edge] = correlate(g, NOW)
    assert edge.confidence == 0.85 and "stale" not in edge.evidence


def test_stale_never_exceeds_cap_or_fresh_score():
    av = "u-" + "3" * 32
    kw = dict(display_name="Jan Kowalski", avatar_hash=av, website="https://jankowalski.dev")
    g = Graph()
    profile(g, "https://a.example/jan", "A", DAYS_400_AGO, 1.0, links=["https://b.example/jan"], **kw)
    profile(g, "https://b.example/jan", "B", DAYS_400_AGO, 1.0, links=["https://a.example/jan"], **kw)
    [edge] = correlate(g, NOW)
    assert edge.confidence == round(MAX_SCORE * 0.5, 3) == 0.475


def test_score_pair_without_now_keeps_old_behaviour():
    g, a, b = pair(DAYS_400_AGO, DAYS_400_AGO)
    assert score_pair(g, a, b, signals_between(g, a, b)) == 0.85
    assert score_pair(g, a, b, signals_between(g, a, b), now=NOW) == 0.425


def test_recorrelation_later_lowers_existing_link():
    g, _, _ = pair(FRESH, FRESH)
    correlate(g, NOW)
    assert sp(g)[0].confidence == 0.85
    correlate(g, "2028-01-01T00:00:00+00:00")             # ten sam graf wczytany po ponad roku
    [edge] = sp(g)
    assert edge.confidence == 0.425 and "[stale]" in edge.evidence
    correlate(g, "2028-01-01T00:00:00+00:00")
    assert len(sp(g)) == 1 and sp(g)[0].confidence == 0.425   # nadal idempotentne


def _investigate(make_ctx, tmp_path, ts, now):
    ctx = make_ctx()
    ctx.now = lambda: now
    audit = AuditLog(tmp_path / "audit.jsonl", "ala")
    audit.start("audyt własnej firmy X", [], {})
    g = new_graph("audyt własnej firmy X", "ala", "", [], {}, now)
    profile(g, "https://a.example/jan", "A", ts, links=["https://b.example/jan"])
    profile(g, "https://b.example/jan", "B", ts, links=["https://a.example/jan"])
    investigate(g, [], ctx, audit, Options(), registry={})
    return g


def test_engine_marks_stale_links_visible_in_html(make_ctx, tmp_path):
    g = _investigate(make_ctx, tmp_path, DAYS_400_AGO, NOW)
    [edge] = sp(g)
    assert edge.confidence == 0.425 and "[stale]" in edge.evidence
    assert "[stale]" in render_html(g)


def test_engine_uses_investigation_clock(make_ctx, tmp_path):
    # względem zegara badania dowód jest świeży (31 dni), względem zegara systemowego byłby stary
    g = _investigate(make_ctx, tmp_path, "2020-05-01T00:00:00+00:00", "2020-06-01T00:00:00+00:00")
    [edge] = sp(g)
    assert edge.confidence == 0.85 and "stale" not in edge.evidence
