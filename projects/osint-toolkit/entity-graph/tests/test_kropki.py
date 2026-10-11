import xml.etree.ElementTree as ET

import pytest

from entity_graph.cli import main
from entity_graph.kropki import layout, render_svg
from entity_graph.model import Edge, Graph, Node
from entity_graph.normalize import EntityType as T

SVG = "{http://www.w3.org/2000/svg}"


def _graph() -> Graph:
    g = Graph({"purpose": "audyt własnej infrastruktury firmy X"})
    d = g.add_node(Node.make(T.DOMAIN, "example.com"))
    ip = g.add_node(Node.make(T.IP, "93.184.216.34"))
    em = g.add_node(Node.make(T.EMAIL, "biuro@example.com"))
    u = g.add_node(Node.make(T.USERNAME, "kowalski_test"))
    g.add_edge(Edge(d.id, ip.id, "resolves_to", "dns_audit", 0.9, "A"))
    g.add_edge(Edge(em.id, d.id, "mailbox_at", "email_domain", 1.0, "domena adresu"))
    g.add_edge(Edge(u.id, em.id, "candidate", "person_candidates", 0.0, "hipoteza"))
    return g


def test_svg_is_valid_xml_with_dot_per_node_and_line_per_edge():
    root = ET.fromstring(render_svg(_graph(), iterations=50))
    dots = [c for c in root.iter(f"{SVG}circle") if c.find(f"{SVG}title") is not None]
    lines = list(root.iter(f"{SVG}line"))
    assert len(dots) == 4
    assert len(lines) == 3
    dashed = [ln for ln in lines if ln.get("stroke-dasharray")]
    assert len(dashed) == 1  # hipoteza (pewność 0) przerywana


def test_layout_deterministic_and_inside_canvas():
    ids = [f"n{i}" for i in range(12)]
    pairs = [(f"n{i}", f"n{i + 1}") for i in range(11)]
    a = layout(ids, pairs, 60)
    assert a == layout(ids, pairs, 60)
    assert render_svg(_graph(), iterations=30) == render_svg(_graph(), iterations=30)
    for x, y in a.values():
        assert 0 <= x <= 1000 and 0 <= y <= 1000


def test_hostile_values_escaped():
    g = Graph()
    g.add_node(Node.make(T.USERNAME, "<script>alert(1)</script>"))
    svg = render_svg(g, iterations=5)
    assert "<script>" not in svg
    ET.fromstring(svg)


def test_max_nodes_cut_and_min_confidence():
    g = _graph()
    svg = render_svg(g, max_nodes=2, min_confidence=0.5, iterations=5)
    root = ET.fromstring(svg)
    assert len([c for c in root.iter(f"{SVG}circle") if c.find(f"{SVG}title") is not None]) == 2
    assert "pominięto 2" in svg
    with pytest.raises(ValueError):
        render_svg(g, max_nodes=0)


def test_empty_graph():
    ET.fromstring(render_svg(Graph()))


def test_cli_kropki_writes_svg_next_to_graph(tmp_path, capsys):
    path = tmp_path / "graph.json"
    _graph().save(path)
    assert main(["kropki", str(path)]) == 0
    assert (tmp_path / "kropki.svg").read_text(encoding="utf-8").startswith("<svg")
    assert main(["kropki", str(tmp_path / "brak.json")]) == 2
