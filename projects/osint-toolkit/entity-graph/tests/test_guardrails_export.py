import json
import xml.etree.ElementTree as ET

import pytest

from entity_graph.export import render_html, to_graphml, xml_safe
from entity_graph.guardrails import AuditLog, GuardrailError, validate_purpose, verify_audit
from entity_graph.model import Edge, Graph, Node, RunRecord, Status
from entity_graph.normalize import EntityType as T


# ------------------------------------------------------------------ cel badania

@pytest.mark.parametrize("bad", [None, "", "   ", "test", "xxx", "krótkie", "ab cd", "12345 67890", "to"])
def test_purpose_rejected(bad):
    with pytest.raises(GuardrailError):
        validate_purpose(bad)


def test_purpose_accepted_and_normalized():
    assert validate_purpose("  audyt   własnej infrastruktury firmy X ") == "audyt własnej infrastruktury firmy X"


# ------------------------------------------------------------------ dziennik audytu

def test_audit_log_chain_and_content(tmp_path):
    log = AuditLog(tmp_path / "a.jsonl", operator="ala")
    start = log.start("audyt własnej firmy X", [{"type": "domain", "value": "example.com"}], {"depth": 1}, "ZL-1")
    log.write("transform", transform="dns_audit", status="FOUND")
    log.write("end", nodes=3)
    ok, msg = verify_audit(tmp_path / "a.jsonl")
    assert ok, msg
    first = json.loads((tmp_path / "a.jsonl").read_text(encoding="utf-8").splitlines()[0])
    assert first["operator"] == "ala" and first["purpose"] == "audyt własnej firmy X" and first["case_ref"] == "ZL-1"
    assert first["inputs"] == [{"type": "domain", "value": "example.com"}] and first["ts"] and first["event"] == "start"
    assert start["prev"] == "0" * 64


def test_audit_detects_tampering_and_deletion(tmp_path):
    path = tmp_path / "a.jsonl"
    log = AuditLog(path, operator="ala")
    log.start("audyt własnej firmy X", [], {})
    log.write("transform", transform="t1", status="ERROR")
    log.write("end")
    lines = path.read_text(encoding="utf-8").splitlines()
    path.write_text("\n".join([lines[0], lines[1].replace("ERROR", "FOUND"), lines[2]]) + "\n", encoding="utf-8")
    assert not verify_audit(path)[0]
    path.write_text("\n".join([lines[0], lines[2]]) + "\n", encoding="utf-8")
    assert not verify_audit(path)[0]
    path.write_text("", encoding="utf-8")
    assert not verify_audit(path)[0]
    assert not verify_audit(tmp_path / "brak.jsonl")[0]


def test_audit_log_appends_to_existing_chain(tmp_path):
    path = tmp_path / "a.jsonl"
    AuditLog(path, "ala").start("audyt własnej firmy X", [], {})
    AuditLog(path, "ala").write("end")        # nowy obiekt kontynuuje łańcuch
    assert verify_audit(path)[0]


# ------------------------------------------------------------------ GraphML

def sample_graph():
    g = Graph({"purpose": "audyt <script>alert(1)</script>", "operator": "ala", "started": "2026-10-03",
               "inputs": [{"type": "url", "value": "https://x.com/<b>"}]})
    evil = g.add_node(Node.make(T.USERNAME, "jan", {"display_name": "<img src=x onerror=alert(1)>", "ctl": "a\x00b\x1bc"}, "t"))
    url = g.add_node(Node.make(T.URL, "https://x.com/jan", {"kind": "profile", "site": '"><script>1</script>'}, "t"))
    bad = g.add_node(Node.make(T.URL, "https://evil.example/a?x=1&y=<script>", {}, "t"))
    org = g.add_node(Node.make(T.ORGANIZATION, "<b>Evil & Co</b>", {}, "t"))
    g.add_edge(Edge(evil.id, url.id, "has_account", "username_scan", 0.9,
                    'dowód <script>alert("x")</script> & "cudzysłów"\x07'))
    g.add_edge(Edge(url.id, org.id, "r", "t", 0.5, "e"))
    g.add_edge(Edge(url.id, bad.id, "r", "t", 0.5, "e"))
    g.runs.append(RunRecord("username_scan", evil.id, Status.ERROR, "2026-10-03T12:00:00+00:00", "", "<script>x</script>"))
    person = g.add_node(Node.make(T.PERSON, "Jan Kowalski", {"manual_review_links": [
        {"engine": "google", "label": "x", "query": '"Jan" <b>', "url": "https://www.google.com/search?q=%22Jan%22"},
        {"engine": "evil", "label": "y", "query": "q", "url": "javascript:alert(1)"}]}, "t"))
    g.add_edge(Edge(person.id, evil.id, "candidate_username", "t", 0.0, "hipoteza"))
    return g


def test_graphml_is_wellformed_with_hostile_data():
    xml = to_graphml(sample_graph())
    root = ET.fromstring(xml)                       # parsuje się = poprawny XML (znaki sterujące usunięte)
    ns = {"g": "http://graphml.graphdrawing.org/xmlns"}
    nodes = root.findall(".//g:node", ns)
    edges = root.findall(".//g:edge", ns)
    assert len(nodes) == 5 and len(edges) == 4
    keys = {k.get("attr.name") for k in root.findall("g:key", ns)}
    assert {"relation", "source", "confidence", "evidence", "timestamp", "type", "label"} <= keys
    conf = [d.text for e in edges for d in e.findall("g:data", ns) if d.get("key") == "e_confidence"]
    assert "0.900" in conf and "0.000" in conf
    assert "\x00" not in xml and "\x1b" not in xml and "\x07" not in xml
    ids = {n.get("id") for n in nodes}
    assert all(e.get("source") in ids and e.get("target") in ids for e in edges)


def test_xml_safe():
    assert xml_safe("a\x00b\x0bc\ud800d\u0085e") == "abcd\u0085e"
    assert xml_safe("zażółć\n\t") == "zażółć\n\t"


# ------------------------------------------------------------------ HTML

def test_html_report_escapes_everything_and_has_no_scripts():
    page = render_html(sample_graph())
    assert "<script" not in page.lower()                                 # żadnego żywego <script>
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in page               # a dane są widoczne jako tekst
    assert "<img" not in page and "<b>" not in page
    assert 'href="javascript:' not in page
    assert 'href="https://www.google.com/search?q=%22Jan%22"' in page and 'rel="noopener noreferrer nofollow"' in page
    assert "Content-Security-Policy" in page
    assert "<iframe" not in page.lower() and "<link" not in page.lower() and "<img" not in page.lower()
    assert "ERROR" in page and "trop, nie dowód" in page
    assert page.count("<table") == page.count("</table>")


def test_html_lists_statuses_and_exclusions():
    g = Graph({"purpose": "audyt własnej firmy"})
    for i, s in enumerate(Status):
        g.runs.append(RunRecord(f"t{i}", "domain:a.com", s, "2026-10-03T12:00:00+00:00"))
    page = render_html(g)
    for s in Status:
        assert f"st-{s.value}" in page
    assert "CallApp" in page and "Truecaller" in page      # sekcja "czego narzędzie nie robi"
    assert "nie oznacza braku danych" in page
