from entity_graph.correlate import (MAX_SCORE, attach_gravatar_emails, combine, correlate, merge_duplicates,
                                    signals_between)
from entity_graph.model import Edge, Graph, Node
from entity_graph.normalize import EntityType as T, avatar_hash_from_url
from entity_graph.transforms.email import gravatar_hashes


def profile(graph, url, site, conf=0.95, user="u", **attrs):
    """Konto znalezione pod nazwą `user` z pewnością conf."""
    u = graph.add_node(Node.make(T.USERNAME, user))
    p = graph.add_node(Node.make(T.URL, url, {"kind": "profile", "site": site, **attrs}, "username_scan"))
    graph.add_edge(Edge(u.id, p.id, "has_account", "username_scan", conf, "test"))
    return p


def same_person_edges(g):
    return [e for e in g.edges.values() if e.relation == "same_person"]


def test_no_signal_no_link():
    g = Graph()
    profile(g, "https://a.example/u", "A", display_name="Jan Kowalski")
    profile(g, "https://b.example/u", "B", display_name="Jan Kowalski")    # sama nazwa wyświetlana to za mało
    assert correlate(g) == [] and same_person_edges(g) == []


def test_same_username_alone_is_not_a_signal():
    g = Graph()
    profile(g, "https://a.example/jan", "A", user="jan")
    profile(g, "https://b.example/jan", "B", user="jan")
    assert correlate(g) == []


def test_cross_links_one_way_and_reciprocal():
    g = Graph()
    a = profile(g, "https://a.example/jan", "A", links=["https://b.example/jan"])
    b = profile(g, "https://b.example/jan", "B")
    [s] = signals_between(g, a, b)
    assert s.kind == "cross_link" and s.score == 0.7
    b.attrs["links"] = ["https://www.A.example/jan/?utm_source=z"]
    [s] = signals_between(g, a, b)
    assert s.score == 0.85
    [edge] = correlate(g)
    assert edge.relation == "same_person" and edge.confidence == 0.85 and "cross_link" in edge.evidence


def test_same_email_via_gravatar_match():
    g = Graph()
    email = g.add_node(Node.make(T.EMAIL, "jan@example.com"))
    h = gravatar_hashes("jan@example.com")["md5"]
    a = profile(g, "https://a.example/jan", "A", avatar_hash=avatar_hash_from_url(f"https://gravatar.com/avatar/{h}?s=80"))
    g_prof = g.add_node(Node.make(T.URL, f"https://gravatar.com/{gravatar_hashes('jan@example.com')['sha256']}",
                                  {"kind": "gravatar", "site": "Gravatar"}, "email_gravatar"))
    g.add_edge(Edge(email.id, g_prof.id, "has_gravatar", "email_gravatar", 0.95, "e"))
    assert attach_gravatar_emails(g) == 1
    [edge] = correlate(g)
    assert "same_email" in edge.evidence and "jan@example.com" in edge.evidence
    assert {edge.src, edge.dst} == {a.id, g_prof.id} and edge.confidence == 0.8


def test_same_own_website_but_not_platform():
    g = Graph()
    a = profile(g, "https://a.example/jan", "A", website="https://jankowalski.dev/")
    b = profile(g, "https://b.example/jan", "B", website="http://www.jankowalski.dev")
    assert [s.kind for s in signals_between(g, a, b)] == ["same_domain"]
    c = profile(g, "https://c.example/x", "C", website="https://github.com/jan")
    d = profile(g, "https://d.example/x", "D", website="https://github.com/jan")
    assert signals_between(g, c, d) == []                 # link do platformy nie świadczy o własnej stronie


def test_name_plus_avatar_needs_both_and_different_sites():
    g = Graph()
    av = "u-" + "1" * 32
    a = profile(g, "https://a.example/jan", "A", display_name="Jan Kowalski", avatar_hash=av)
    b = profile(g, "https://b.example/jan", "B", display_name="JAN  kowalski", avatar_hash=av)
    assert [s.kind for s in signals_between(g, a, b)] == ["name_and_avatar"]
    only_avatar = profile(g, "https://c.example/x", "C", display_name="Ktoś Inny", avatar_hash=av)
    assert signals_between(g, a, only_avatar) == []
    same_site = profile(g, "https://a.example/jan2", "A", display_name="Jan Kowalski", avatar_hash=av)
    assert signals_between(g, a, same_site) == []         # ten sam serwis: wspólny awatar to zwykle domyślny


def test_score_never_exceeds_evidence():
    g = Graph()
    av = "u-" + "2" * 32
    kw = dict(display_name="Jan Kowalski", avatar_hash=av, website="https://jankowalski.dev")
    a = profile(g, "https://a.example/jan", "A", conf=0.9, links=["https://b.example/jan"], **kw)
    b = profile(g, "https://b.example/jan", "B", conf=0.62, links=["https://a.example/jan"], **kw)
    sigs = signals_between(g, a, b)
    assert {s.kind for s in sigs} == {"cross_link", "same_domain", "name_and_avatar"}
    assert min(MAX_SCORE, combine([s.score for s in sigs])) == MAX_SCORE
    [edge] = correlate(g)
    assert edge.confidence == 0.62                          # ogranicza je najsłabsze konto
    g2 = Graph()
    a2 = profile(g2, "https://a.example/jan", "A", conf=1.0, links=["https://b.example/jan"], **kw)
    profile(g2, "https://b.example/jan", "B", conf=1.0, links=["https://a.example/jan"], **kw)
    assert correlate(g2)[0].confidence == MAX_SCORE        # nigdy 1.0


def test_correlate_is_idempotent_and_evidence_always_present():
    g = Graph()
    profile(g, "https://a.example/jan", "A", links=["https://b.example/jan"])
    profile(g, "https://b.example/jan", "B")
    correlate(g)
    correlate(g)
    edges = same_person_edges(g)
    assert len(edges) == 1 and edges[0].evidence and edges[0].timestamp and edges[0].source == "correlate"


def test_persons_are_never_merged():
    g = Graph()
    g.add_node(Node.make(T.PERSON, "Jan Kowalski"))
    g.add_node(Node.make(T.PERSON, "Jan Kowalski-Nowak"))
    correlate(g)
    assert len(g.nodes_of_type(T.PERSON)) == 2


def test_merge_duplicates_after_manual_edit():
    g = Graph()
    a = g.add_node(Node.make(T.DOMAIN, "example.com"))
    b = g.add_node(Node.make(T.IP, "8.8.8.8"))
    g.add_edge(Edge(a.id, b.id, "resolves_to", "t", 0.9, "e"))
    # ręczna edycja: ten sam URL zapisany dwa razy w różnych formach
    u1 = g.add_node(Node.make(T.URL, "https://x.com/jan"))
    u2 = Node(T.URL, "twitter.com/jan", "http://twitter.com/jan/", {"site": "X"}, ["edit"])
    g.nodes[u2.id] = u2
    g.add_edge(Edge(b.id, u2.id, "hosted_on", "t", 0.5, "e2"))
    assert merge_duplicates(g) == 1
    assert u2.id not in g.nodes and u1.attrs["site"] == "X"
    assert any(e.dst == u1.id for e in g.edges.values())
