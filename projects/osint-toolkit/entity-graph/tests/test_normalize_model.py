import json

import pytest

from entity_graph.model import Edge, Graph, Node, Status
from entity_graph.normalize import (EntityType as T, avatar_hash_from_url, fold, is_public_ip, normalize,
                                    normalize_phone)


@pytest.mark.parametrize("etype,raw,key", [
    (T.DOMAIN, " HTTPS://User@WWW.Example.COM:8443/path?q=1 ", "www.example.com"),
    (T.DOMAIN, "*.dev.example.com.", "dev.example.com"),
    (T.DOMAIN, "bücher.example", "xn--bcher-kva.example"),
    (T.IP, "::ffff:1.2.3.4", "1.2.3.4"),
    (T.IP, "[2001:DB8:0:0:0:0:0:1]", "2001:db8::1"),
    (T.EMAIL, "mailto:Jan.Kowalski@Example.COM", "jan.kowalski@example.com"),
    (T.PHONE, "603 123-456", "+48603123456"),
    (T.PHONE, "0048 603 123 456", "+48603123456"),
    (T.USERNAME, "@JKowalski", "jkowalski"),
    (T.PERSON, "  Łukasz   Żółć ", "lukasz zolc"),
    (T.ORGANIZATION, "Example Sp. z o.o. ", "example sp. z o.o"),
])
def test_normalize_keys(etype, raw, key):
    assert normalize(etype, raw)[0] == key


@pytest.mark.parametrize("etype,raw", [
    (T.DOMAIN, "nodots"), (T.DOMAIN, "-bad-.com"), (T.IP, "999.1.1.1"), (T.EMAIL, "a@b@c.com"), (T.EMAIL, "no-at"),
    (T.PHONE, "123"), (T.PHONE, "+12"), (T.PHONE, "12345678"), (T.USERNAME, "has space"), (T.PERSON, "ab"),
    (T.URL, "ftp://example.com/x"), (T.URL, "javascript:alert(1)"), (T.DOMAIN, ""), (T.IP, "x" * 5000),
])
def test_normalize_rejects(etype, raw):
    with pytest.raises(ValueError):
        normalize(etype, raw)


def test_url_normalization_merges_equivalent_forms():
    keys = {normalize(T.URL, u)[0] for u in [
        "http://www.twitter.com/jan/", "https://x.com/jan?utm_source=a&fbclid=z#frag", "https://mobile.twitter.com/jan",
        "https://user:pass@x.com/jan"]}
    assert keys == {"x.com/jan"}
    # dane logowania i fragment nie trafiają do wartości pokazywanej
    assert normalize(T.URL, "https://user:pass@x.com/jan#f")[1] == "https://x.com/jan"
    # różne parametry zapytania to różne adresy; kolejność nie ma znaczenia
    assert normalize(T.URL, "https://a.com/p?b=1&a=2")[0] == normalize(T.URL, "https://a.com/p?a=2&b=1")[0]


def test_phone_region_rules():
    assert normalize_phone("603123456", "PL") == "+48603123456"
    with pytest.raises(ValueError):
        normalize_phone("603123456", "DE")   # bez + poza PL nie zgadujemy
    assert normalize_phone("+49 30 901820", "DE") == "+4930901820"


def test_fold_and_public_ip():
    assert fold("Łódź Żółć") == "lodz zolc"
    assert is_public_ip("8.8.8.8") and not is_public_ip("10.0.0.1") and not is_public_ip("127.0.0.1")


def test_avatar_hash():
    h = "a" * 64
    assert avatar_hash_from_url(f"https://www.gravatar.com/avatar/{h.upper()}?s=80") == h
    assert avatar_hash_from_url("https://cdn.x/u/1?s=64") == avatar_hash_from_url("https://cdn.x/u/1?s=400")
    assert avatar_hash_from_url("https://cdn.x/u/1") != avatar_hash_from_url("https://cdn.x/u/2")


# ------------------------------------------------------------------ model

def test_add_node_merges_same_key_and_attrs():
    g = Graph()
    a = g.add_node(Node.make(T.DOMAIN, "Example.com", {"tags": ["a"], "x": 1}, "t1"))
    b = g.add_node(Node.make(T.DOMAIN, "https://example.com/", {"tags": ["b"], "x": 2, "y": 3}, "t2"))
    assert a is b and len(g.nodes) == 1
    assert a.attrs == {"tags": ["a", "b"], "x": 1, "y": 3}      # skalar: pierwszy wygrywa
    assert a.sources == ["t1", "t2"]


def test_edges_dedupe_keep_highest_confidence():
    g = Graph()
    a = g.add_node(Node.make(T.DOMAIN, "a.com"))
    b = g.add_node(Node.make(T.IP, "8.8.8.8"))
    g.add_edge(Edge(a.id, b.id, "resolves_to", "dns", 0.4, "r1"))
    g.add_edge(Edge(a.id, b.id, "resolves_to", "dns", 0.9, "r2"))
    assert len(g.edges) == 1
    e = next(iter(g.edges.values()))
    assert e.confidence == 0.9 and "r1" in e.evidence and "r2" in e.evidence
    for bad in (7, -1, 1.0001):   # liczba spoza 0-1 to błąd danych, nie "pewność 1.0" ani "0.0"
        with pytest.raises(ValueError):
            Edge("a", "b", "r", "s", bad, "")
    assert g.add_edge(Edge(a.id, "ip:nie-ma", "r", "s", 1, "")) is None   # brak węzła docelowego


def test_merge_into_redirects_edges():
    g = Graph()
    a = g.add_node(Node.make(T.PHONE, "603123456"))
    c = g.add_node(Node.make(T.PHONE, "+48603123457"))
    d = g.add_node(Node.make(T.DOMAIN, "a.com"))
    g.add_edge(Edge(d.id, a.id, "r", "s", 0.5, "x"))
    g.merge_into(c.id, a.id)
    assert a.id not in g.nodes
    assert next(iter(g.edges.values())).dst == c.id


def test_json_roundtrip_and_validation(tmp_path):
    g = Graph({"purpose": "x"})
    a = g.add_node(Node.make(T.DOMAIN, "a.com"))
    b = g.add_node(Node.make(T.IP, "8.8.8.8"))
    g.add_edge(Edge(a.id, b.id, "resolves_to", "dns", 0.9, "ev"))
    path = tmp_path / "g.json"
    g.save(path)
    g2 = Graph.load(path)
    assert g2.to_dict() == g.to_dict()
    with pytest.raises(ValueError):
        Graph.from_dict({"schema": 99})
    bad = g.to_dict()
    bad["edges"][0]["dst"] = "ip:nie-ma"
    with pytest.raises(ValueError):
        Graph.from_dict(bad)
    (tmp_path / "x.json").write_text("{nie json", encoding="utf-8")
    with pytest.raises(ValueError):
        Graph.load(tmp_path / "x.json")
    assert not list(tmp_path.glob(".*.tmp"))   # zapis atomowy nie zostawia plików tymczasowych
    assert json.loads(path.read_text(encoding="utf-8"))["schema"] == 1


def test_status_values():
    assert {s.value for s in Status} == {"FOUND", "NOT_FOUND", "UNKNOWN", "ERROR"}
