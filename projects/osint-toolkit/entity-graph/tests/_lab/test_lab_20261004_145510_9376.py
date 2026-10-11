from entity_graph.engine import Options, investigate, new_graph
from entity_graph.export import render_html
from entity_graph.guardrails import AuditLog
from entity_graph.model import Node, Status
from entity_graph.normalize import EntityType as T
from entity_graph.transforms import REGISTRY

CYR_A = "\u0430"   # cyrylickie 'а', wizualnie jak łacińskie 'a'


def run(node, ctx):
    return REGISTRY["email_idn"].run(node, ctx)


def test_mixed_script_label_flagged_as_homograph(make_ctx):
    node = Node.make(T.EMAIL, f"support@p{CYR_A}ypal.com")
    assert "xn--" in node.key                       # normalizacja trzyma domenę w punycode
    r = run(node, make_ctx())
    assert r.status is Status.FOUND
    a = r.node_attrs
    assert a["email_idn"] is True
    assert a["email_domain_unicode"] == f"p{CYR_A}ypal.com"
    assert a["email_idn_scripts"] == ["CYRILLIC", "LATIN"]
    assert a["email_idn_mixed_labels"] == [f"p{CYR_A}ypal"]
    assert a["email_idn_mixed_script"] is True
    assert "homograf" in r.note
    assert r.nodes == [] and r.edges == []


def test_polish_idn_single_script_not_flagged(make_ctx):
    r = run(Node.make(T.EMAIL, "jan@\u017c\u00f3\u0142w.pl"), make_ctx())   # żółw.pl
    assert r.status is Status.FOUND
    assert r.node_attrs["email_domain_unicode"] == "\u017c\u00f3\u0142w.pl"
    assert r.node_attrs["email_idn_scripts"] == ["LATIN"]
    assert r.node_attrs["email_idn_mixed_script"] is False
    assert r.node_attrs["email_idn_mixed_labels"] == []
    assert "homograf" not in r.note


def test_scripts_mixed_across_labels_only_is_not_homograph(make_ctx):
    r = run(Node.make(T.EMAIL, "biuro@\u043f\u0440\u0438\u043c\u0435\u0440.com"), make_ctx())   # пример.com
    assert r.status is Status.FOUND
    assert r.node_attrs["email_idn_scripts"] == ["CYRILLIC", "LATIN"]
    assert r.node_attrs["email_idn_mixed_script"] is False
    assert r.node_attrs["email_idn_mixed_labels"] == []


def test_ascii_domain_is_not_idn(make_ctx):
    r = run(Node.make(T.EMAIL, "jan@example.com"), make_ctx())
    assert r.status is Status.NOT_FOUND
    assert r.node_attrs == {} and r.nodes == [] and r.edges == []


def test_undecodable_punycode_is_unknown_not_negative(make_ctx):
    r = run(Node.make(T.EMAIL, "jan@xn--999.com"), make_ctx())
    assert r.status is Status.UNKNOWN
    assert r.status is not Status.NOT_FOUND
    assert "punycode" in r.note
    assert "email_domain_unicode" not in r.node_attrs


def test_wired_into_offline_investigation_and_html_report(make_ctx, tmp_path):
    t = REGISTRY["email_idn"]
    assert t.network is False and T.EMAIL in t.inputs
    ctx = make_ctx()
    audit = AuditLog(tmp_path / "audit.jsonl", "ala")
    audit.start("audyt własnej firmy X", [], {})
    g = new_graph("audyt własnej firmy X", "ala", "", [], {}, "2026-10-04")
    seed = Node.make(T.EMAIL, f"support@p{CYR_A}ypal.com")
    investigate(g, [seed], ctx, audit, Options(offline=True))
    assert ctx.fetch.calls == [] and ctx.runner.calls == []
    runs = {(r.transform, r.node_id): r.status for r in g.runs}
    assert runs[("email_idn", seed.id)] is Status.FOUND
    node = g.nodes[seed.id]
    assert node.attrs["email_idn_mixed_script"] is True
    html = render_html(g)
    assert "email_idn_mixed_script" in html and f"p{CYR_A}ypal.com" in html
    assert '"transform": "email_idn"' in (tmp_path / "audit.jsonl").read_text(encoding="utf-8")
