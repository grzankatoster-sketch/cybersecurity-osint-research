"""Łączenie kropek: scalanie po identyfikatorach i reguły powiązań (każda z dowodem, bez zawyżania pewności)."""
import json
from pathlib import Path

import pytest

from entity_graph import links
from entity_graph.correlate import correlate
from entity_graph.export import render_html
from entity_graph.importers import import_files
from entity_graph.model import Edge, Graph, Node
from entity_graph.normalize import EntityType as T

IMP = Path(__file__).parent / "fixtures" / "import"
NOW = "2026-10-03T12:00:00+00:00"


def full_graph(*names) -> Graph:
    g = Graph({"purpose": "test łączenia kropek"})
    import_files(g, [IMP / n for n in names], NOW)
    return g


def org(g, name, attrs, source="seed") -> Node:
    return g.add_node(Node.make(T.ORGANIZATION, name, {"kind": "company", **attrs}, source), NOW)


def link_edges(g, relation=None):
    return [e for e in g.edges.values() if e.source == links.SOURCE and (relation is None or e.relation == relation)]


# ------------------------------------------------------------------ scalanie po identyfikatorach

def test_company_from_krs_vat_and_snapshot_merged_by_nip_with_all_sources():
    g = full_graph("krs_acme.json", "vat_acme.json", "teczka_acme.json")
    assert len([n for n in g.nodes.values() if n.type is T.ORGANIZATION]) == 2     # różne nazwy w trzech plikach
    merges = links.merge_identifiers(g)
    orgs = [n for n in g.nodes.values() if n.type is T.ORGANIZATION]
    assert len(orgs) == 1 and len(merges) == 1
    node = orgs[0]
    assert {s.split(":")[2] for s in node.sources} == {"krs_acme.json", "vat_acme.json", "teczka_acme.json"}
    assert node.attrs["bank_accounts"] and node.attrs["krs"] == "0000999001" and node.attrs["aliases"]
    assert "NIP 5260000007" in merges[0]["identifier"] and merges[0]["evidence"]
    assert g.meta["merges"] == merges


def test_regon_9_matches_regon_14_prefix_and_krs_pads_zeros():
    g = Graph()
    org(g, "Firma Jeden", {"regon": "12345678500000"})
    org(g, "Firma Jeden Sp. z o.o.", {"regon": "123456785"})
    org(g, "Firma Trzy", {"krs": "999"})
    org(g, "Firma Trzy SA", {"krs": "0000000999"})
    assert len(links.merge_identifiers(g)) == 2
    assert len(g.nodes) == 2


def test_regon_with_different_prefix_or_bad_length_does_not_merge():
    g = Graph()
    org(g, "A", {"regon": "123456785"})
    org(g, "B", {"regon": "123456786"})
    org(g, "C", {"regon": "12345"})         # nieprawidłowa długość: ignorowany
    org(g, "D", {"regon": "12345"})
    assert links.merge_identifiers(g) == [] and len(g.nodes) == 4


def test_conflicting_nip_in_one_group_is_not_merged_and_is_recorded():
    g = Graph()
    org(g, "Alfa", {"nip": "1111111111", "regon": "123456785"})
    org(g, "Beta", {"nip": "2222222222", "regon": "12345678500000"})
    assert links.merge_identifiers(g) == []
    assert len(g.nodes) == 2 and "NIP" in g.meta["conflicts"][0]["reason"]


def test_nip_with_prefix_and_dashes_normalizes():
    g = Graph()
    org(g, "Alfa", {"nip": "PL 526-000-00-07"})
    org(g, "Alfa Sp. z o.o.", {"nip": "5260000007"})
    assert len(links.merge_identifiers(g)) == 1


def test_same_username_email_domain_phone_merge_across_sources_with_all_sources():
    g = full_graph("ue_acme.json", "ue_acme.csv", "phone.json", "phone.csv", "hibp_domain_search.json", "krs_acme.json")
    user = g.nodes["username:acme_testowa"]
    assert {s.split(":")[2] for s in user.sources} == {"ue_acme.json", "ue_acme.csv"}
    phone = g.nodes["phone:+48603123456"]
    assert {s.split(":")[2] for s in phone.sources} == {"phone.json", "phone.csv"}
    assert len([n for n in g.nodes.values() if n.type is T.PHONE]) == 1
    dom = g.nodes["domain:acme-testowa.example"]
    assert {s.split(":")[2] for s in dom.sources} == {"hibp_domain_search.json", "krs_acme.json"}


def test_username_casefold_idn_domain_and_email_case_merge_across_files(tmp_path):
    (tmp_path / "a.json").write_text(json.dumps({"query": "x", "results": {"JanKowalski": [
        {"site": "S", "url": "https://s.example/JanKowalski", "status": "FOUND", "confidence": 0.8}]}}), encoding="utf-8")
    (tmp_path / "b.json").write_text(json.dumps({"query": "x", "results": {"jankowalski": [
        {"site": "T", "url": "https://t.example/jankowalski", "status": "FOUND", "confidence": 0.6}]}}), encoding="utf-8")
    (tmp_path / "h.json").write_text(json.dumps({"domain": "ZAŻÓŁĆ.example", "total_accounts": 1, "per_breach": {"B": 1},
                                                 "addresses": {"Jan@ZAŻÓŁĆ.example": ["B"]}}), encoding="utf-8")
    (tmp_path / "d.json").write_text(json.dumps({"domain": "zażółć.example".encode("idna").decode(), "summary": {"a": ["192.0.2.1"]}}), encoding="utf-8")
    g = Graph()
    import_files(g, [tmp_path], NOW)
    assert len([n for n in g.nodes.values() if n.type is T.USERNAME]) == 1
    domains = [n for n in g.nodes.values() if n.type is T.DOMAIN and n.key.startswith("xn--")]
    assert len(domains) == 1 and domains[0].key.endswith(".example")
    assert any(n.type is T.EMAIL and n.key.startswith("jan@xn--") for n in g.nodes.values())


def test_breach_nodes_with_same_name_but_different_title_merge():
    g = full_graph("hibp_monitor.json", "hibp_domain_search.json")
    assert len(links.merge_identifiers(g)) == 1
    breaches = [n for n in g.nodes.values() if n.attrs.get("kind") == "breach"]
    assert len(breaches) == 1 and len(breaches[0].sources) == 2


# ------------------------------------------------------------------ e-mail <-> organizacja

def test_email_domain_equal_to_company_website_links_email_and_organization():
    g = full_graph("krs_acme.json", "hibp_domain_search.json")
    links.merge_identifiers(g)
    links.connect(g, NOW)
    rel = link_edges(g, "email_matches_org_domain")
    assert {e.src for e in rel} == {"email:jan.testowy@acme-testowa.example", "email:biuro@acme-testowa.example",
                                    "email:kontakt@acme-testowa.example"}
    for e in rel:
        assert 0 < e.confidence <= 0.9 and "acme-testowa.example" in e.evidence and "nie dowodzi" in e.evidence
        assert e.confidence <= g.edges[next(k for k in g.edges if k[2] == "has_website")].confidence   # nie ponad dowód strony


def test_email_on_generic_provider_or_other_domain_is_not_linked():
    g = full_graph("krs_acme.json")
    for addr in ("ktos@gmail.com", "ktos@inna-domena.example"):
        g.add_node(Node.make(T.EMAIL, addr, {}, "seed"), NOW)
    links.connect(g, NOW)
    assert not [e for e in link_edges(g, "email_matches_org_domain") if e.src.endswith(("gmail.com", "inna-domena.example"))]


def test_email_subdomain_gets_lower_confidence_than_exact_domain():
    g = Graph()
    o = org(g, "Firma", {"website": "https://firma.example"})
    exact = g.add_node(Node.make(T.EMAIL, "a@firma.example", {}, "seed"), NOW)
    sub = g.add_node(Node.make(T.EMAIL, "a@mail.firma.example", {}, "seed"), NOW)
    links.connect(g, NOW)
    conf = {e.src: e.confidence for e in link_edges(g, "email_matches_org_domain")}
    assert 0 < conf[sub.id] < conf[exact.id] <= 0.9 and all(e.dst == o.id for e in link_edges(g, "email_matches_org_domain"))


def test_mailbox_at_links_email_to_domain_present_in_graph():
    g = full_graph("dns_acme.json", "hibp_domain_search.json")
    links.connect(g, NOW)
    edge = next(e for e in link_edges(g, "mailbox_at") if e.src == "email:biuro@acme-testowa.example")
    assert edge.dst == "domain:acme-testowa.example" and edge.confidence == 1.0 and edge.evidence


# ------------------------------------------------------------------ IP / NS / ASN

def test_shared_ip_links_domains_with_evidence_and_modest_confidence():
    g = full_graph("dns_acme.json", "dns_sklep.json", "dns_other.json")
    links.connect(g, NOW)
    rel = link_edges(g, "shares_ip")
    assert len(rel) == 1 and {rel[0].src, rel[0].dst} == {"domain:acme-testowa.example", "domain:sklep-acme.example"}
    assert "192.0.2.10" in rel[0].evidence and rel[0].confidence <= 0.5


def test_shared_nameserver_weaker_for_partial_overlap_and_listed_with_evidence():
    g = full_graph("dns_acme.json", "dns_sklep.json", "dns_other.json")
    links.connect(g, NOW)
    ns = {frozenset((e.src, e.dst)): e for e in link_edges(g, "shares_nameserver")}
    both = ns[frozenset(("domain:acme-testowa.example", "domain:sklep-acme.example"))]
    one = ns[frozenset(("domain:acme-testowa.example", "domain:inna-firma.example"))]
    assert one.confidence < both.confidence <= 0.4 and "ns1.hosting-test.example" in one.evidence


def test_wide_sharing_above_fanout_limit_is_not_linked():
    g = Graph()
    ip = g.add_node(Node.make(T.IP, "192.0.2.50", {}, "seed"), NOW)
    for i in range(links.MAX_FANOUT + 1):
        d = g.add_node(Node.make(T.DOMAIN, f"d{i}.example", {}, "seed"), NOW)
        g.add_edge(Edge(d.id, ip.id, "resolves_to", "seed", 0.95, "A", NOW))
    links.connect(g, NOW)
    assert not link_edges(g, "shares_ip")


def test_shared_asn_links_domains_on_different_ips_only_weakly():
    g = Graph()
    asn = g.add_node(Node.make(T.ORGANIZATION, "Operator Test", {"kind": "asn_holder", "asn": ["AS64500"]}, "seed"), NOW)
    for i, (dom, ip) in enumerate((("a.example", "192.0.2.1"), ("b.example", "192.0.2.2"))):
        d = g.add_node(Node.make(T.DOMAIN, dom, {}, "seed"), NOW)
        n = g.add_node(Node.make(T.IP, ip, {}, "seed"), NOW)
        g.add_edge(Edge(d.id, n.id, "resolves_to", "seed", 0.95, "A", NOW))
        g.add_edge(Edge(n.id, asn.id, "announced_by", "seed", 0.95, "BGP", NOW))
    links.connect(g, NOW)
    rel = link_edges(g, "shares_asn")
    assert len(rel) == 1 and rel[0].confidence <= 0.2 and "Operator Test" in rel[0].evidence and not link_edges(g, "shares_ip")


# ------------------------------------------------------------------ konta i bio

def test_profile_link_to_domain_in_graph_is_linked_capped_by_account_confidence():
    g = full_graph("ue_acme.json", "dns_acme.json", "dns_sklep.json")
    links.connect(g, NOW)
    rel = {(e.src, e.dst): e for e in link_edges(g, "links_to_domain")}
    gh = rel[("url:github.com/acme_testowa", "domain:acme-testowa.example")]
    tw = rel[("url:x.com/acme_testowa", "domain:acme-testowa.example")]
    assert gh.confidence == 0.6 and tw.confidence == 0.6 and ("url:github.com/acme_testowa", "domain:sklep-acme.example") in rel
    assert "deklaracja" in gh.evidence
    assert not [e for e in link_edges(g, "links_to_domain") if e.dst.endswith("x.com")]    # platformy nie są własną stroną


def test_weak_account_cannot_yield_stronger_link_than_the_account_itself():
    g = Graph()
    d = g.add_node(Node.make(T.DOMAIN, "wlasna.example", {}, "seed"), NOW)
    u = g.add_node(Node.make(T.USERNAME, "jan", {}, "seed"), NOW)
    p = g.add_node(Node.make(T.URL, "https://s.example/jan", {"kind": "profile", "site": "S", "website": "https://wlasna.example"}, "seed"), NOW)
    g.add_edge(Edge(u.id, p.id, "has_account", "x", 0.3, "słabe", NOW))
    links.connect(g, NOW)
    assert link_edges(g, "links_to_domain")[0].confidence == 0.3 and d.id


def test_cross_linked_profiles_still_correlate_with_capped_score():
    g = full_graph("ue_acme.json")
    correlate(g, NOW)
    same = [e for e in g.edges.values() if e.relation == "same_person"]
    assert len(same) == 1 and same[0].confidence <= 0.7       # nie wyżej niż najsłabsze konto (Twitter 0.7)


# ------------------------------------------------------------------ rachunki

def test_same_iban_in_two_different_organizations_links_without_merging():
    g = full_graph("vat_acme.json", "vat_inna.json")
    assert links.merge_identifiers(g) == [] and len([n for n in g.nodes.values() if n.type is T.ORGANIZATION]) == 2
    links.connect(g, NOW)
    rel = link_edges(g, "shares_bank_account")
    assert len(rel) == 1 and rel[0].confidence <= 0.7 and "812874" in rel[0].evidence
    assert "PL61109010140000071219812874" not in rel[0].evidence      # tylko końcówka rachunku w dowodzie


# ------------------------------------------------------------------ własności ogólne

def test_every_link_edge_has_evidence_and_confidence_never_above_limit():
    g = full_graph(*[p.name for p in IMP.iterdir() if p.suffix in (".json", ".csv", ".txt")])
    links.merge_identifiers(g)
    correlate(g, NOW)
    links.connect(g, NOW)
    made = link_edges(g)
    assert len(made) >= 10
    for e in made:
        assert e.evidence.strip() and 0 <= e.confidence <= (1.0 if e.relation == "mailbox_at" else links.MAX_CONFIDENCE)
        assert e.relation not in ("same_person",)


def test_connect_is_idempotent_and_does_not_inflate():
    g = full_graph("dns_acme.json", "dns_sklep.json", "krs_acme.json", "hibp_domain_search.json")
    links.connect(g, NOW)
    first = {k: (e.confidence, e.evidence) for k, e in g.edges.items()}
    links.merge_identifiers(g)
    links.connect(g, NOW)
    assert {k: (e.confidence, e.evidence) for k, e in g.edges.items()} == first


def test_no_person_nodes_or_phone_links_are_ever_created():
    g = full_graph(*[p.name for p in IMP.iterdir() if p.suffix in (".json", ".csv", ".txt")])
    links.merge_identifiers(g)
    links.connect(g, NOW)
    assert not [n for n in g.nodes.values() if n.type is T.PERSON]
    phones = {n.id for n in g.nodes.values() if n.type is T.PHONE}
    assert not [e for e in g.edges.values() if e.src in phones or e.dst in phones]
    parcels = {n.id for n in g.nodes.values() if n.type is T.PARCEL}
    assert not [e for e in g.edges.values() if (e.src in parcels or e.dst in parcels) and e.relation != "related_parcel"]


# ------------------------------------------------------------------ raport HTML

def test_html_report_has_links_section_with_counts_evidence_and_source_files():
    g = full_graph("krs_acme.json", "hibp_domain_search.json", "dns_acme.json", "dns_sklep.json", "unknown.json", "broken.json",
                   "empty.json")
    links.merge_identifiers(g)
    links.connect(g, NOW)
    html = render_html(g)
    assert "<h2>Powiązania między źródłami</h2>" in html
    assert "IMPORTED=4, SKIPPED=2" in html and "ERROR=1" in html
    assert "email_matches_org_domain" in html and "krs_acme.json (osint-poland)" in html
    assert "domena adresu" in html and "shares_ip" in html
    # kolejność wg pewności: pierwszy wiersz tabeli powiązań ma najwyższą pewność
    section = html.split("<h3>Powiązania (")[1].split("</table>")[0]
    confs = [float(x.split("</span>")[0]) for x in section.split('<span class="conf">')[1:]]
    assert confs == sorted(confs, reverse=True)


def test_html_report_escapes_hostile_values_in_links_section():
    g = full_graph("hibp_breach_list.json")
    g.meta["imports"][0]["reason"] = "<script>alert(1)</script>"
    g.meta["merges"] = [{"kept": "<b>x</b>", "merged": ["<i>y</i>"], "identifier": "<u>z</u>", "sources": ["<s>"], "evidence": ""}]
    html = render_html(g)
    assert "<script>alert(1)</script>" not in html and "<b>x</b>" not in html and "<img src=x" not in html
    assert "&lt;script&gt;" in html


def test_plain_run_report_has_no_links_section():
    g = Graph({"purpose": "audyt"})
    g.add_node(Node.make(T.DOMAIN, "example.com", {}, "seed"), NOW)
    assert "Powiązania między źródłami" not in render_html(g)
