"""Import eksportu / store.json pakietu org-intel do grafu i sprawy (`import-org-intel`).

Wyłącznie dane syntetyczne (tests/fixtures/org_intel/, wygenerowane prawdziwym org-intel: `ingest` + `export --format json`)
i zero ruchu sieciowego (gniazda zablokowane w całym module)."""

from __future__ import annotations

import copy
import json
import os
import re
import shutil
import socket
import xml.etree.ElementTree as ET
from pathlib import Path

import pytest

from entity_graph import cli, importers
from entity_graph.guardrails import AuditLog, verify_audit
from entity_graph.importers import import_files, org_intel
from entity_graph.importers.base import ImportCtx
from entity_graph.model import Edge, Graph, Node
from entity_graph.normalize import EntityType as T

FX = Path(__file__).parent / "fixtures" / "org_intel"
NOW = "2026-10-05T12:00:00+00:00"
PURPOSE = "due diligence kontrahenta na zlecenie klienta, sprawa 2026/57"
EMAIL = "jan.kowalski@example.test"
GRAPHML = "{http://graphml.graphdrawing.org/xmlns}"
CERT_URL = "https://cert.pl/posts/2026/10/demo-wyciek-stealer"
KRS_URL = "https://prs.ms.gov.pl/krs/odpis/0000123456"
ORG = "organization:example sp. z o.o"
BREACH = "organization:demobreach"


@pytest.fixture(autouse=True)
def no_network(monkeypatch):
    def blocked(*_a, **_k):
        raise AssertionError("test próbował użyć sieci")

    monkeypatch.setattr(socket.socket, "connect", blocked)
    monkeypatch.setattr(socket, "create_connection", blocked)


# ------------------------------------------------------------------ pomocnicze


def load(name: str) -> dict:
    return json.loads((FX / name).read_text(encoding="utf-8"))


def write(tmp_path: Path, data, name: str = "wejscie.json") -> Path:
    path = tmp_path / name
    path.write_text(json.dumps(data, ensure_ascii=False), encoding="utf-8")
    return path


def import_graph(tmp_path: Path, data, graph: Graph | None = None, name: str = "wejscie.json"):
    """Import przez import_files (ścieżka `polacz`): -> (graf, raport pliku)."""
    graph = graph if graph is not None else Graph({"purpose": "test"})
    reports = import_files(graph, [write(tmp_path, data, name)], NOW)
    return graph, reports[0]


def parsed(data, existing: Graph | None = None, **kw):
    return org_intel.parse(data, ImportCtx(org_intel.TOOL, "x.json", NOW), existing=existing, **kw)


def make_case(tmp_path: Path, name: str = "sprawa", graph: Graph | None = None) -> Path:
    case = tmp_path / name
    case.mkdir()
    (graph or Graph({"purpose": PURPOSE})).save(case / "graph.json")
    AuditLog(case / "audit.jsonl", "ala").start(PURPOSE, [], {})
    return case


def run_cli(case: Path, source, *extra: str) -> int:
    return cli.main(["import-org-intel", "--input", str(source), "--case", str(case), "--operator", "ala", *extra])


def case_graph(case: Path) -> Graph:
    return Graph.load(case / "graph.json")


def by_relation(g: Graph, relation: str):
    return [e for e in g.edges.values() if e.relation == relation]


def nodes_of(g: Graph, etype: T):
    return [n for n in g.nodes.values() if n.type is etype]


def snapshot(g: Graph) -> dict:
    return {
        "nodes": {n.id: (json.dumps(n.attrs, sort_keys=True), tuple(n.sources)) for n in g.nodes.values()},
        "edges": {e.key: (e.confidence, e.evidence, e.timestamp) for e in g.edges.values()},
    }


# ------------------------------------------------------------------ 1. firma, domena, incydent


def test_company_domain_incident_nodes_and_relations(tmp_path):
    g, report = import_graph(tmp_path, load("export_basic.json"))
    assert report.format == "org-intel" and report.status == "IMPORTED"  # nie hibp-monitor mimo klucza "domain"
    org, dom, breach = g.nodes[ORG], g.nodes["domain:example.test"], g.nodes[BREACH]
    assert org.attrs["kind"] == "company" and (org.attrs["krs"], org.attrs["nip"], org.attrs["regon"]) == (
        "0000123456",
        "5271001238",
        "360123459",
    )
    assert org.attrs["country"] == "PL" and org.attrs["org_intel_id"].startswith("org_")
    assert dom.attrs["verification_status"] == "unverified" and "verified_at" not in dom.attrs
    assert breach.attrs["kind"] == "breach" and breach.attrs["breach_name"] == "DemoBreach"
    assert breach.attrs["incident_date"] == "2026-08-15" and breach.attrs["affected_accounts_count"] == 12345
    assert breach.attrs["data_classes"] == ["Email addresses"] and breach.attrs["is_verified"] is True
    assert breach.attrs["affected_domain"] == "example.test"
    sources = {n.id: n for n in nodes_of(g, T.URL)}
    assert set(sources) == {"url:prs.ms.gov.pl/krs/odpis/0000123456", "url:cert.pl/posts/2026/10/demo-wyciek-stealer"}
    assert all(n.attrs["kind"] == "source" for n in sources.values())
    cert = sources["url:cert.pl/posts/2026/10/demo-wyciek-stealer"]
    assert cert.attrs["source_type"] == "cert_advisory" and cert.attrs["retrieved_at"] == "2026-10-05T10:10:00Z"
    assert (
        cert.attrs["reliability"] == "high" and cert.attrs["license"] == "CC BY 4.0" and cert.attrs["quality"] == "high"
    )
    owns = by_relation(g, "owns_domain")
    assert [(e.src, e.dst, e.confidence) for e in owns] == [(org.id, dom.id, 0.9)]
    assoc = by_relation(g, "associated_with_incident")
    assert [(e.src, e.dst, e.confidence) for e in assoc] == [(dom.id, breach.id, 0.9)]
    assert assoc[0].evidence.startswith("direct; cert_advisory; 2026-10-05T10:10:00Z; " + CERT_URL)
    assert (
        "evidence_hash=" in assoc[0].evidence
        and assoc[0].source == "org-intel:cert.pl/posts/2026/10/demo-wyciek-stealer"
    )
    has = {(e.src, e.dst) for e in by_relation(g, "has_source")}
    assert has == {
        (org.id, "url:prs.ms.gov.pl/krs/odpis/0000123456"),
        (dom.id, "url:prs.ms.gov.pl/krs/odpis/0000123456"),
        (breach.id, "url:cert.pl/posts/2026/10/demo-wyciek-stealer"),
    }
    prov = org.attrs["provenance"][0]
    assert set(prov) == {
        "source_url_original",
        "source_url_normalized",
        "source_name",
        "source_type",
        "source_category",
        "retrieved_at",
        "confidence",
        "derivation",
        "evidence_hash",
        "quality",
        "import_id",
    }
    assert prov["source_category"] == "official_registry" and prov["source_name"] == "Odpis z KRS (syntetyczny)"
    assert prov["import_id"].startswith("imp_") and len(prov["import_id"]) == 16
    assert prov["source_url_original"] == KRS_URL
    assert prov["source_url_normalized"] == "prs.ms.gov.pl/krs/odpis/0000123456"
    assert (
        sources["url:prs.ms.gov.pl/krs/odpis/0000123456"].attrs["source_url_original"] == KRS_URL
        and prov["derivation"] == "direct"
        and prov["quality"] == "high"
    )


def test_company_domain_incident_through_cli(tmp_path, capsys):
    case = make_case(tmp_path)
    assert run_cli(case, FX / "export_basic.json") == 0
    out = capsys.readouterr().out
    assert "Węzły:     utworzone 5" in out and "Krawędzie: utworzone 5" in out
    assert "Pominięte: osoba – poza zakresem importu: 1" in out and "DRY-RUN" not in out
    g = case_graph(case)
    assert {ORG, "domain:example.test", BREACH} <= set(g.nodes)
    assert verify_audit(case / "audit.jsonl")[0]
    events = [json.loads(x) for x in (case / "audit.jsonl").read_text(encoding="utf-8").splitlines()]
    assert [(e["event"], e.get("phase")) for e in events[1:]] == [
        ("org_intel_import", "przed"),
        ("org_intel_import", "po"),
    ]
    assert events[1]["file"] == "export_basic.json" and len(events[1]["sha256"]) == 64
    assert events[2]["nodes_created"] == 5 and events[2]["result"] == "zmieniono"


def test_local_store_json_is_recognised_like_export(tmp_path):
    g, report = import_graph(tmp_path, load("store_basic.json"))
    assert report.format == "org-intel" and ORG in g.nodes and BREACH in g.nodes
    assert (
        org_intel.kind_of(load("store_basic.json")) == "store"
        and org_intel.kind_of(load("export_basic.json")) == "export"
    )


# ------------------------------------------------------------------ 2. subdomena = inferred


def test_incident_on_subdomain_gives_inferred_edge_from_parent_domain(tmp_path):
    g, _ = import_graph(tmp_path, load("export_subdomain.json"))
    assoc = {e.src: e for e in by_relation(g, "associated_with_incident")}
    assert set(assoc) == {"domain:example.test", "domain:shop.example.test"}
    inferred, direct = assoc["domain:example.test"], assoc["domain:shop.example.test"]
    assert inferred.evidence.startswith("inferred;") and inferred.confidence <= 0.6
    assert direct.evidence.startswith("direct;") and direct.confidence == 0.9
    assert g.nodes[BREACH].attrs["affected_domain"] == "shop.example.test"
    owns = {e.dst: e for e in by_relation(g, "owns_domain")}
    assert set(owns) == {"domain:example.test", "domain:shop.example.test"}


# ------------------------------------------------------------------ 3. idempotencja


def test_reimport_same_file_even_under_another_name_changes_nothing(tmp_path):
    g, _ = import_graph(tmp_path, load("export_subdomain.json"), name="pierwszy.json")
    before = snapshot(g)
    n_nodes, n_edges = len(g.nodes), len(g.edges)
    import_graph(tmp_path, load("export_subdomain.json"), graph=g, name="zupelnie-inna-nazwa.json")
    assert (len(g.nodes), len(g.edges)) == (n_nodes, n_edges) and snapshot(g) == before


def test_reimport_through_cli_reports_no_changes_and_keeps_graph_bytes(tmp_path, capsys):
    case = make_case(tmp_path)
    assert run_cli(case, FX / "export_subdomain.json") == 0
    first = (case / "graph.json").read_bytes()
    other = tmp_path / "kopia-pod-inna-nazwa.json"
    shutil.copy(FX / "export_subdomain.json", other)
    capsys.readouterr()
    assert run_cli(case, other, "--json") == 0
    report = json.loads(capsys.readouterr().out)
    assert (report["nodes_created"], report["nodes_updated"], report["nodes_unchanged"]) == (0, 0, 7)
    assert (report["edges_created"], report["edges_updated"], report["edges_unchanged"]) == (0, 0, 8)
    assert (case / "graph.json").read_bytes() == first
    last = json.loads((case / "audit.jsonl").read_text(encoding="utf-8").splitlines()[-1])
    assert last["result"] == "bez zmian"


# ------------------------------------------------------------------ 4. dwa źródła tego samego incydentu


def test_two_sources_for_one_incident_give_two_edges_and_two_provenance_entries(tmp_path):
    g, _ = import_graph(tmp_path, load("export_two_sources.json"))
    assert [n.id for n in nodes_of(g, T.ORGANIZATION) if n.attrs.get("kind") == "breach"] == [BREACH]
    has = [e for e in by_relation(g, "has_source") if e.src == BREACH]
    assert len(has) == 2 and len({e.dst for e in has}) == 2 and len({e.source for e in has}) == 2
    prov = g.nodes[BREACH].attrs["provenance"]
    assert {p["source_type"] for p in prov} == {"cert_advisory", "hibp_catalog"} and len(prov) == 2
    hibp = next(p for p in prov if p["source_type"] == "hibp_catalog")
    assert hibp["confidence"] == "medium" and hibp["quality"] == "medium"
    assoc = by_relation(g, "associated_with_incident")
    assert len(assoc) == 2 and len({e.source for e in assoc}) == 2
    assert sorted(e.confidence for e in assoc) == [0.6, 0.9]


# ------------------------------------------------------------------ 5. rekord bez źródła


def _drop(data, section, index=0, **changes):
    data = copy.deepcopy(data)
    data[section][index].update(changes)
    return data


@pytest.mark.parametrize(
    "mutate,reason",
    [
        (lambda d: _drop(d, "incidents", source_ids=[]), "brak źródła"),
        (lambda d: _drop(d, "incidents", source_ids=["src_0000000000000000"]), "nieistniejące źródło"),
        (lambda d: _drop(d, "incidents", source_ids=None), "brak źródła"),
    ],
)
def test_record_without_valid_source_is_rejected_with_reason_and_rest_imported(tmp_path, mutate, reason):
    g, _ = import_graph(tmp_path, mutate(load("export_basic.json")))
    assert BREACH not in g.nodes and ORG in g.nodes and "domain:example.test" in g.nodes
    imp = parsed(mutate(load("export_basic.json")))
    assert len(imp.rejected) == 1 and imp.rejected[0].label.startswith("incydent ") and reason in imp.rejected[0].reason


def test_record_without_observation_is_rejected(tmp_path):
    data = load("export_basic.json")
    data["observations"] = [o for o in data["observations"] if o["entity_type"] != "incident"]
    imp = parsed(data)
    assert [r.reason for r in imp.rejected] == ["brak obserwacji (proweniencji) z poprawnego źródła"]


@pytest.mark.parametrize(
    "change,reason",
    [
        ({"url": ""}, "http/https"),
        ({"retrieved_at": ""}, "retrieved_at"),
        ({"retrieved_at": "wczoraj"}, "retrieved_at"),
        ({"source_type": ""}, "typ źródła"),
        ({"source_type": "inny_typ"}, "typ źródła"),
        ({"name": ""}, "bez nazwy"),
        ({"reliability": "super"}, "reliability"),
        ({"content_hash": "abc"}, "content_hash"),
    ],
)
def test_incomplete_source_is_rejected_and_records_based_only_on_it_too(change, reason):
    data = load("export_basic.json")
    cert = next(s for s in data["sources"] if s["source_type"] == "cert_advisory")
    cert.update({"url": "https://cert.pl/komunikat", **change})  # bez słów kluczowych wycieku w adresie
    imp = parsed(data)
    reasons = {r.label.split(" ")[0]: r.reason for r in imp.rejected}
    assert reason in reasons["źródło"] and "odrzuconych źródłach" in reasons["incydent"]
    assert {n.id for n in imp.nodes if n.type is T.ORGANIZATION} == {ORG}  # firma z rejestru zostaje


def test_rejected_record_gives_exit_code_4_and_report_lists_reason(tmp_path, capsys):
    data = _drop(load("export_basic.json"), "incidents", source_ids=[])
    case = make_case(tmp_path)
    assert run_cli(case, write(tmp_path, data)) == 4
    out = capsys.readouterr().out
    assert "ODRZUCONO incydent inc_" in out and "brak źródła" in out and "Węzły:     utworzone 3" in out
    assert "odrzucone 1" in out
    g = case_graph(case)
    assert ORG in g.nodes and BREACH not in g.nodes


# ------------------------------------------------------------------ 6. surowe sekrety

JWT = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ4In0.podpis"
SECRETS = [
    ({"password": "Tajne123!"}, "pole sekretu"),
    ({"api_key": "klucz"}, "pole sekretu"),
    ({"description": f"sesja {JWT}"}, "JWT"),
    ({"description": "Authorization: Bearer abcdefghijklmnopqrstuvwxyz0123456789"}, "Bearer"),
    ({"description": "wpis: jan.nowak@example.test:Haslo123!"}, "e-mail:hasło"),
    ({"description": "-----BEGIN RSA PRIVATE KEY-----"}, "klucz prywatny"),
    ({"description": "$2b$12$abcdefghijklmnopqrstuv"}, "bcrypt"),
    ({"description": "5f4dcc3b5aa765d61d8327deb882cf99"}, "hex"),
]


@pytest.mark.parametrize("change,reason", SECRETS)
def test_record_with_raw_secret_is_rejected_without_echoing_the_secret(tmp_path, capsys, change, reason):
    data = _drop(load("export_basic.json"), "incidents", **change)
    g, _ = import_graph(tmp_path, data)
    assert BREACH not in g.nodes and ORG in g.nodes
    imp = parsed(data)
    assert len(imp.rejected) == 1 and reason in imp.rejected[0].reason
    for secret in (
        "Tajne123!",
        JWT,
        "Haslo123!",
        "abcdefghijklmnopqrstuvwxyz0123456789",
        "5f4dcc3b5aa765d61d8327deb882cf99",
    ):
        assert secret not in imp.rejected[0].reason and secret not in imp.rejected[0].label
    case = make_case(tmp_path)
    assert run_cli(case, write(tmp_path, data)) == 4
    assert not any(s in capsys.readouterr().out for s in ("Tajne123!", "Haslo123!", JWT))
    assert "Tajne123!" not in (case / "graph.json").read_text(encoding="utf-8")


def test_secret_in_name_does_not_leak_through_label(tmp_path):
    data = _drop(load("export_basic.json"), "incidents", name="jan.nowak@example.test:Haslo123!")
    imp = parsed(data)
    assert len(imp.rejected) == 1 and "Haslo123!" not in imp.rejected[0].label
    assert imp.rejected[0].label.startswith("incydent inc_")


def test_label_of_rejected_record_shows_safe_name_only(tmp_path):
    data = _drop(load("export_basic.json"), "incidents", source_ids=[])
    assert parsed(data).rejected[0].label.endswith("(DemoBreach)")


def test_incident_linked_to_person_or_email_is_rejected():
    data = _drop(load("export_basic.json"), "incidents", emails=["a@example.test"])
    assert "osobami" in parsed(data).rejected[0].reason


def test_hash_fields_content_hash_and_evidence_hash_are_allowed():
    data = load("export_basic.json")
    next(s for s in data["sources"] if s["source_type"] == "cert_advisory")["content_hash"] = "a" * 64
    data["observations"][0]["evidence_hash"] = "b" * 64
    imp = parsed(data)
    assert not imp.rejected
    assert next(n for n in imp.nodes if n.attrs.get("content_hash") == "a" * 64)


def test_passwords_data_class_label_is_not_a_secret():
    data = _drop(load("export_basic.json"), "incidents", data_classes=["Email addresses", "Passwords"])
    imp = parsed(data)
    assert not imp.rejected and "Passwords" in next(n for n in imp.nodes if n.id == BREACH).attrs["data_classes"]


# ------------------------------------------------------------------ 7. źródła z sygnałami wycieku


def test_cert_advisory_with_leak_words_in_path_is_accepted_but_telegram_host_is_not():
    imp = parsed(load("export_basic.json"))
    assert not imp.rejected and BREACH in {n.id for n in imp.nodes}  # .../posts/wyciek-stealer-2026/
    data = load("export_basic.json")
    cert = next(s for s in data["sources"] if s["source_type"] == "cert_advisory")
    cert["url"] = "https://t.me/x"
    imp = parsed(data)
    assert BREACH not in {n.id for n in imp.nodes}
    reasons = " ".join(r.reason for r in imp.rejected)
    assert "host t.me" in reasons and "odrzuconych źródłach" in reasons


@pytest.mark.parametrize(
    "stype,url,name,rejected",
    [
        ("cert_advisory", "https://pastebin.com/abc", "Komunikat", True),
        ("cert_advisory", "https://cert.pl/leak-dump/1", "Komunikat", False),
        ("cert_advisory", "https://leak.cert.pl/1", "Komunikat", True),  # słowo w hoście
        ("company_website", "https://www.example.test/combolist", "Strona firmy", True),  # słowo w URL, typ bez wyjątku
        ("company_website", "https://www.example.test/zarzad", "Dump danych", True),  # słowo w nazwie źródła
        ("official_document", "https://dokumenty.example.test/stealer-raport.pdf", "Raport", False),
        ("hibp_catalog", "https://haveibeenpwned.com/api/v3/breach/DemoBreach", "Katalog", False),
    ],
)
def test_source_leak_signals_follow_guards(stype, url, name, rejected):
    data = load("export_basic.json")
    cert = next(s for s in data["sources"] if s["source_type"] == "cert_advisory")
    cert.update({"source_type": stype, "url": url, "name": name})
    imp = parsed(data)
    assert bool(imp.rejected) is rejected
    assert (BREACH in {n.id for n in imp.nodes}) is (not rejected)


# ------------------------------------------------------------------ 8. osoby nigdy nie wchodzą do grafu


def test_people_are_skipped_entirely_and_email_appears_nowhere(tmp_path, capsys):
    store = load("store_basic.json")
    assert store["persons"][0]["public_email"] == EMAIL  # magazyn lokalny ma pełny adres
    case = make_case(tmp_path)
    assert run_cli(case, FX / "store_basic.json") == 0
    assert "Pominięte: osoba – poza zakresem importu: 1" in capsys.readouterr().out
    g = case_graph(case)
    forbidden = {T.PERSON, T.EMAIL, T.USERNAME, T.PHONE}
    assert not [n for n in g.nodes.values() if n.type in forbidden]
    assert not [
        e
        for e in g.edges.values()
        if e.src.split(":")[0] in {t.value for t in forbidden} or e.dst.split(":")[0] in {t.value for t in forbidden}
    ]
    for name in ("graph.json", "audit.jsonl", "graph.graphml", "report.html", "kropki.svg"):
        text = (case / name).read_text(encoding="utf-8")
        assert EMAIL not in text and "jan.kowalski" not in text and "Jan Kowalski" not in text, name
    assert {e.relation for e in g.edges.values()} == {"owns_domain", "associated_with_incident", "has_source"}


def test_scope_assertion_rejects_forbidden_nodes_and_relations():
    imp = org_intel.OrgIntelImported(org_intel.TOOL)
    imp.nodes.append(Node.make(T.PERSON, "Jan Kowalski"))
    with pytest.raises(AssertionError):
        org_intel._assert_scope(imp)
    imp = org_intel.OrgIntelImported(org_intel.TOOL)
    a, b = Node.make(T.DOMAIN, "example.test"), Node.make(T.DOMAIN, "shop.example.test")
    imp.nodes += [a, b]
    imp.edges.append(org_intel.Edge(a.id, b.id, "has_account", "org-intel:x", 0.5, "x"))
    with pytest.raises(AssertionError):
        org_intel._assert_scope(imp)


def test_person_record_garbage_does_not_break_import():
    data = load("export_basic.json")
    data["persons"] = [{"name": "X", "password": "tajne", "public_email": EMAIL}, "nie obiekt"]
    imp = parsed(data)
    assert (
        imp.skipped_people == 1 and not imp.rejected and not any(n.type in org_intel.FORBIDDEN_TYPES for n in imp.nodes)
    )


# ------------------------------------------------------------------ 9. dry-run


def test_dry_run_writes_nothing_and_matches_real_report(tmp_path, capsys):
    case = make_case(tmp_path)
    files_before = sorted(p.name for p in case.iterdir())
    graph_bytes, audit_bytes = (case / "graph.json").read_bytes(), (case / "audit.jsonl").read_bytes()
    assert run_cli(case, FX / "export_subdomain.json", "--dry-run") == 0
    out = capsys.readouterr().out
    assert out.startswith("DRY-RUN: nic nie zapisano\n") and "utworzone 7" in out and "utworzone 8" in out
    assert (case / "graph.json").read_bytes() == graph_bytes and (case / "audit.jsonl").read_bytes() == audit_bytes
    assert sorted(p.name for p in case.iterdir()) == files_before
    assert run_cli(case, FX / "export_subdomain.json", "--dry-run", "--json") == 0
    dry = json.loads(capsys.readouterr().out)
    assert dry["dry_run"] is True and dry["nodes_created"] == 7
    assert run_cli(case, FX / "export_subdomain.json", "--json") == 0
    real = json.loads(capsys.readouterr().out)
    assert real["dry_run"] is False
    assert {k: v for k, v in real.items() if k != "dry_run"} == {k: v for k, v in dry.items() if k != "dry_run"}


def test_dry_run_with_rejections_still_exit_4_and_unchanged_files(tmp_path, capsys):
    case = make_case(tmp_path)
    before = (case / "graph.json").read_bytes(), (case / "audit.jsonl").read_bytes()
    data = _drop(load("export_basic.json"), "incidents", password="x")
    assert run_cli(case, write(tmp_path, data), "--dry-run") == 4
    assert "DRY-RUN: nic nie zapisano" in capsys.readouterr().out
    assert ((case / "graph.json").read_bytes(), (case / "audit.jsonl").read_bytes()) == before


# ------------------------------------------------------------------ 10. eksport grafu zachowuje proweniencję


def test_exports_keep_source_url_time_confidence_and_derivation(tmp_path):
    case = make_case(tmp_path)
    assert run_cli(case, FX / "export_subdomain.json") == 0
    g = case_graph(case)
    inferred = next(e for e in by_relation(g, "associated_with_incident") if e.src == "domain:example.test")
    assert inferred.confidence == 0.6 and "inferred" in inferred.evidence and CERT_URL in inferred.evidence
    assert (
        inferred.timestamp == "2026-10-05T10:10:00Z"
        and inferred.source == "org-intel:cert.pl/posts/2026/10/demo-wyciek-stealer"
    )
    graphml = ET.fromstring((case / "graph.graphml").read_text(encoding="utf-8"))
    names = {k.get("id"): k.get("attr.name") for k in graphml.iter(GRAPHML + "key")}
    edges = []
    for el in graphml.iter(GRAPHML + "edge"):
        edges.append({names[d.get("key")]: d.text for d in el.iter(GRAPHML + "data")})
    row = next(e for e in edges if e["relation"] == "associated_with_incident" and "inferred" in e["evidence"])
    assert row["confidence"] == "0.600" and CERT_URL in row["evidence"] and row["timestamp"] == "2026-10-05T10:10:00Z"
    assert row["source"] == "org-intel:cert.pl/posts/2026/10/demo-wyciek-stealer"
    node_attrs = [
        json.loads(d.text)
        for el in graphml.iter(GRAPHML + "node")
        for d in el.iter(GRAPHML + "data")
        if names[d.get("key")] == "attrs"
    ]
    prov = next(a["provenance"] for a in node_attrs if a.get("kind") == "breach")
    assert prov[0]["source_url_original"] == CERT_URL and prov[0]["retrieved_at"] == "2026-10-05T10:10:00Z"
    assert prov[0]["confidence"] == "high" and prov[0]["derivation"] == "direct"
    html = (case / "report.html").read_text(encoding="utf-8")
    assert CERT_URL in html and "inferred; cert_advisory" in html and "has_source" in html


# ------------------------------------------------------------------ 11. ranking i deduplikacja


def _verified(data, status, at="2026-10-05T11:00:00Z"):
    data = copy.deepcopy(data)
    data["domains"][0].update({"verification_status": status, "verified_at": at if status == "verified" else None})
    return data


def _domain_attrs(case: Path) -> dict:
    return case_graph(case).nodes["domain:example.test"].attrs


def test_verified_domain_is_not_downgraded_by_later_unverified_or_failed_import(tmp_path):
    case = make_case(tmp_path)
    assert run_cli(case, write(tmp_path, _verified(load("export_basic.json"), "verified"), "a.json")) == 0
    assert _domain_attrs(case)["verification_status"] == "verified"
    for status in ("unverified", "failed", "pending"):
        assert run_cli(case, write(tmp_path, _verified(load("export_basic.json"), status), f"{status}.json")) == 0
        attrs = _domain_attrs(case)
        assert attrs["verification_status"] == "verified" and attrs["verified_at"] == "2026-10-05T11:00:00Z"


def test_verification_is_upgraded_in_order_unverified_pending_verified_and_failed_is_lowest(tmp_path):
    case = make_case(tmp_path)
    for status, expect in (
        ("failed", "failed"),
        ("unverified", "unverified"),
        ("pending", "pending"),
        ("unverified", "pending"),
        ("verified", "verified"),
    ):
        assert run_cli(case, write(tmp_path, _verified(load("export_basic.json"), status), "w.json")) == 0
        assert _domain_attrs(case)["verification_status"] == expect, status
    assert _domain_attrs(case)["verified_at"] == "2026-10-05T11:00:00Z"


def test_verified_at_only_comes_with_verified_status():
    imp = parsed(_verified(load("export_basic.json"), "pending"))
    dom = next(n for n in imp.nodes if n.type is T.DOMAIN)
    assert dom.attrs["verification_status"] == "pending" and "verified_at" not in dom.attrs
    data = _verified(load("export_basic.json"), "verified")
    data["domains"][0]["verified_at"] = None  # verified bez daty to rekord niespójny: odrzucenie, nie degradacja
    imp = parsed(data)
    assert not [n for n in imp.nodes if n.type is T.DOMAIN] and "verified_at" in imp.rejected[0].reason


def test_incident_count_is_max_flags_are_or_and_provenance_is_deduplicated(tmp_path):
    case = make_case(tmp_path)
    first = _drop(load("export_basic.json"), "incidents", affected_accounts_count=500, status=[])
    assert run_cli(case, write(tmp_path, first, "1.json")) == 0
    assert "is_verified" not in case_graph(case).nodes[BREACH].attrs
    assert run_cli(case, write(tmp_path, load("export_basic.json"), "2.json")) == 0  # 12345 i verified
    attrs = case_graph(case).nodes[BREACH].attrs
    assert attrs["affected_accounts_count"] == 12345 and attrs["is_verified"] is True
    smaller = _drop(load("export_basic.json"), "incidents", affected_accounts_count=10, status=["sensitive"])
    assert run_cli(case, write(tmp_path, smaller, "3.json")) == 0
    attrs = case_graph(case).nodes[BREACH].attrs
    assert attrs["affected_accounts_count"] == 12345 and attrs["is_verified"] is True and attrs["is_sensitive"] is True
    assert len(attrs["provenance"]) == 1


def test_provenance_keeps_several_sources_after_second_import(tmp_path):
    case = make_case(tmp_path)
    assert run_cli(case, FX / "export_basic.json") == 0
    assert run_cli(case, FX / "export_two_sources.json") == 0
    g = case_graph(case)
    assert {p["source_type"] for p in g.nodes[BREACH].attrs["provenance"]} == {"cert_advisory", "hibp_catalog"}
    assert len([e for e in by_relation(g, "has_source") if e.src == BREACH]) == 2


def _existing_company(name="Inna Nazwa Sp. z o.o.", **attrs) -> Graph:
    g = Graph({"purpose": PURPOSE})
    g.add_node(Node.make(T.ORGANIZATION, name, {"kind": "company", **attrs}, "import:osint-poland:krs.json"), NOW)
    return g


@pytest.mark.parametrize("attrs", [{"krs": "0000123456"}, {"nip": "527-100-12-38"}, {"regon": "360123459"}])
def test_company_with_same_identifier_but_other_name_is_merged_and_old_name_kept(tmp_path, attrs):
    case = make_case(tmp_path, graph=_existing_company(**attrs))
    assert run_cli(case, FX / "export_basic.json") == 0
    g = case_graph(case)
    companies = [n for n in nodes_of(g, T.ORGANIZATION) if n.attrs.get("kind") == "company"]
    assert [n.value for n in companies] == ["Inna Nazwa Sp. z o.o."]
    node = companies[0]
    assert node.attrs["previous_names"] == ["Example Sp. z o.o."] and node.attrs["krs"] == "0000123456"
    assert ORG not in g.nodes
    assert any(e.relation == "owns_domain" and e.src == node.id for e in g.edges.values())


def test_company_with_same_nip_but_conflicting_krs_is_rejected_not_duplicated():
    imp = parsed(load("export_basic.json"), existing=_existing_company(krs="0000999999", nip="5271001238"))
    assert not [n for n in imp.nodes if n.attrs.get("kind") == "company"]
    assert [r.reason for r in imp.rejected if r.label.startswith("organizacja")] == [
        "konflikt identyfikatorów: ten sam NIP co istniejąca organizacja, ale sprzeczny KRS"
    ]


def test_company_krs_beats_nip_and_falls_back_to_name_key():
    g = _existing_company(name="Pierwsza", nip="5271001238")
    g.add_node(Node.make(T.ORGANIZATION, "Druga", {"kind": "company", "krs": "0000123456"}, "x"), NOW)
    node = next(n for n in parsed(load("export_basic.json"), existing=g).nodes if n.attrs.get("kind") == "company")
    assert node.value == "Druga"
    node = next(n for n in parsed(load("export_basic.json")).nodes if n.attrs.get("kind") == "company")
    assert node.id == ORG


def test_breach_node_never_absorbs_a_company_and_company_never_absorbs_a_breach():
    g = Graph()
    g.add_node(
        Node.make(T.ORGANIZATION, "Example Sp. z o.o.", {"kind": "breach", "breach_name": "Example"}, "hibp"), NOW
    )
    imp = parsed(load("export_basic.json"), existing=g)
    assert any("kolizja klucza" in r.reason and r.label.startswith("organizacja") for r in imp.rejected)
    assert ORG not in {n.id for n in imp.nodes}
    g = Graph()
    g.add_node(Node.make(T.ORGANIZATION, "DemoBreach", {"kind": "company", "krs": "0000000001"}, "krs"), NOW)
    imp = parsed(load("export_basic.json"), existing=g)
    assert any("kolizja klucza" in r.reason and r.label.startswith("incydent") for r in imp.rejected)
    data = _drop(load("export_basic.json"), "incidents", name="Example Sp. z o.o.")  # kolizja wewnątrz pliku
    assert any("kolizja klucza" in r.reason for r in parsed(data).rejected)


# ------------------------------------------------------------------ 12. ten sam węzeł wycieku co z hibp-monitor

HIBP_LIST = [
    {
        "Name": "DemoBreach",
        "Title": "DemoBreach",
        "Domain": "example.test",
        "BreachDate": "2026-08-15",
        "PwnCount": 777,
        "DataClasses": ["Email addresses", "Passwords"],
        "IsVerified": True,
    }
]


@pytest.mark.parametrize("hibp_first", [True, False])
def test_incident_merges_with_breach_node_from_hibp_monitor_import(tmp_path, hibp_first):
    g = Graph({"purpose": "test"})
    order = [("hibp.json", HIBP_LIST), ("oi.json", load("export_basic.json"))]
    for name, data in order if hibp_first else reversed(order):
        import_graph(tmp_path, data, graph=g, name=name)
    breaches = [n for n in nodes_of(g, T.ORGANIZATION) if n.attrs.get("kind") == "breach"]
    assert [n.id for n in breaches] == [BREACH]
    attrs = breaches[0].attrs
    assert attrs["breach_name"] == "DemoBreach" and attrs["pwn_count"] == 777 and attrs["breach_date"] == "2026-08-15"
    assert attrs["org_intel_id"].startswith("inc_") and attrs["incident_date"] == "2026-08-15"
    assert {"Email addresses", "Passwords"} <= set(attrs["data_classes"])
    assert any(e.relation == "breached_service" for e in g.edges.values())  # krawędź z hibp zostaje


def test_incident_with_separate_title_uses_title_as_value_like_hibp():
    data = _drop(load("export_basic.json"), "incidents", title="Demo Breach Ltd")
    node = next(n for n in parsed(data).nodes if n.attrs.get("kind") == "breach")
    assert node.value == "Demo Breach Ltd" and node.attrs["breach_name"] == "DemoBreach"


# ------------------------------------------------------------------ rozpoznanie, błędy, limity


def test_csv_is_refused_with_clear_message(tmp_path, capsys):
    case = make_case(tmp_path)
    (tmp_path / "organizations.csv").write_text("id,legal_name\n1,X\n", encoding="utf-8")
    assert run_cli(case, tmp_path / "organizations.csv") == 2
    assert "CSV z org-intel nie jest obsługiwany" in capsys.readouterr().err


def test_input_format_of_org_intel_gets_a_hint_and_garbage_is_refused(tmp_path, capsys):
    case = make_case(tmp_path)
    own = {"sources": [{"key": "s1"}], "organizations": [{"legal_name": "X"}]}
    assert run_cli(case, write(tmp_path, own)) == 2
    assert "org-intel ingest" in capsys.readouterr().err
    assert run_cli(case, write(tmp_path, {"cokolwiek": 1}, "inny.json")) == 2
    (tmp_path / "zepsuty.json").write_text("{nie json", encoding="utf-8")
    assert run_cli(case, tmp_path / "zepsuty.json") == 2
    assert run_cli(case, tmp_path / "nie-ma.json") == 2
    assert [json.loads(x)["event"] for x in (case / "audit.jsonl").read_text(encoding="utf-8").splitlines()] == [
        "start"
    ]


def test_unsupported_schema_version_is_refused(tmp_path, capsys):
    data = load("export_basic.json")
    data["schema_version"] = 2
    case = make_case(tmp_path)
    assert run_cli(case, write(tmp_path, data)) == 2
    assert "wersja schematu" in capsys.readouterr().err
    assert org_intel.kind_of(data) == "unsupported"


def test_oversized_file_is_refused(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(cli, "MAX_FILE_BYTES", 100)
    case = make_case(tmp_path)
    assert run_cli(case, FX / "export_basic.json") == 2
    assert "plik większy niż" in capsys.readouterr().err


def test_tampered_audit_log_blocks_the_import(tmp_path, capsys):
    case = make_case(tmp_path)
    (case / "audit.jsonl").write_text('{"event": "start"}\n', encoding="utf-8")
    assert run_cli(case, FX / "export_basic.json") == 2
    assert nodes_of(case_graph(case), T.ORGANIZATION) == []


def test_polacz_dispatch_recognises_org_intel_before_hibp_and_lists_format(tmp_path):
    assert "org-intel" in importers.FORMATS
    g = Graph({"purpose": "test"})
    reports = import_files(g, [FX / "export_basic.json", FX / "store_basic.json"], NOW)
    assert [r.format for r in reports] == ["org-intel", "org-intel"] and all(r.status == "IMPORTED" for r in reports)
    assert len(nodes_of(g, T.ORGANIZATION)) == 2 and not nodes_of(g, T.PERSON)


def test_run_records_are_a_journal_not_data(tmp_path):
    g, _ = import_graph(tmp_path, load("export_basic.json"), name="a.json")
    n_nodes, n_edges, n_runs = len(g.nodes), len(g.edges), len(g.runs)
    import_graph(tmp_path, load("export_basic.json"), graph=g, name="a.json")
    assert (len(g.nodes), len(g.edges)) == (n_nodes, n_edges) and len(g.runs) == 2 * n_runs


def test_description_html_is_stripped_and_truncated():
    data = _drop(
        load("export_basic.json"), "incidents", description="<b>Opis</b> &amp; <script>x()</script>" + "a" * 3000
    )
    desc = next(n for n in parsed(data).nodes if n.attrs.get("kind") == "breach").attrs["description"]
    assert "<" not in desc and desc.startswith("Opis & x()") and len(desc) <= 2000


def test_inferred_observation_caps_confidence_and_low_stays_low():
    data = load("export_basic.json")
    for o in data["observations"]:
        if o["entity_type"] == "incident":
            o.update({"derivation": "inferred", "confidence": "high"})
    imp = parsed(data)
    edges = [e for e in imp.edges if e.dst == BREACH or e.src == BREACH]
    assert edges and all(e.confidence <= 0.6 and e.evidence.startswith("inferred") for e in edges)
    for o in data["observations"]:
        if o["entity_type"] == "incident":
            o.update({"derivation": "direct", "confidence": "low"})
    assert {e.confidence for e in parsed(data).edges if BREACH in (e.src, e.dst)} == {0.3}


def test_upgrade_of_existing_node_counts_as_update_and_dry_run_does_not_touch_the_case(tmp_path, capsys):
    case = make_case(tmp_path)
    assert run_cli(case, write(tmp_path, _verified(load("export_basic.json"), "unverified"), "a.json")) == 0
    before = (case / "graph.json").read_bytes(), (case / "audit.jsonl").read_bytes()
    upgrade = write(tmp_path, _verified(load("export_basic.json"), "verified"), "b.json")
    capsys.readouterr()
    assert run_cli(case, upgrade, "--dry-run", "--json") == 0
    dry = json.loads(capsys.readouterr().out)
    assert dry["nodes_updated"] == 1 and dry["nodes_unchanged"] == 4
    assert ((case / "graph.json").read_bytes(), (case / "audit.jsonl").read_bytes()) == before
    assert run_cli(case, upgrade, "--json") == 0
    real = json.loads(capsys.readouterr().out)
    assert real["nodes_updated"] == 1 and _domain_attrs(case)["verification_status"] == "verified"
    assert (case / "graph.json").read_bytes() != before[0]


# ------------------------------------------------------------------ oryginalny URL źródła w proweniencji


def test_original_source_url_is_kept_next_to_normalized_one():
    data = load("export_subdomain.json")
    web = next(s for s in data["sources"] if s["source_type"] == "company_website")
    assert web["url"] == "https://www.example.test/zarzad"
    imp = parsed(data)
    shop = next(n for n in imp.nodes if n.id == "domain:shop.example.test")
    prov = shop.attrs["provenance"][0]
    assert prov["source_url_original"] == "https://www.example.test/zarzad"  # tak, jak zapisał org-intel
    assert prov["source_url_normalized"] == "example.test/zarzad"  # bez www.: tylko do deduplikacji
    node = next(n for n in imp.nodes if n.id == "url:example.test/zarzad")
    assert node.attrs["source_url_original"] == "https://www.example.test/zarzad"
    edge = next(e for e in imp.edges if e.src == shop.id and e.relation == "has_source")
    assert "https://www.example.test/zarzad" in edge.evidence and "; example.test/zarzad" not in edge.evidence


def test_provenance_is_deduplicated_by_normalized_url_and_derivation():
    data = load("export_basic.json")
    cert = next(s for s in data["sources"] if s["source_type"] == "cert_advisory")
    twin = {**cert, "id": "src_aaaaaaaaaaaaaaaa", "url": "https://www.cert.pl/posts/2026/10/demo-wyciek-stealer"}
    data["sources"].append(twin)
    data["incidents"][0]["source_ids"].append(twin["id"])
    first = next(o for o in data["observations"] if o["entity_type"] == "incident")
    data["observations"].append({**first, "id": "obs_aaaaaaaaaaaaaaaa", "source_id": twin["id"]})
    node = next(n for n in parsed(data).nodes if n.id == BREACH)
    assert len(node.attrs["provenance"]) == 1


# ------------------------------------------------------------------ kolizja URL źródła z istniejącym węzłem (fail-closed)


def _profile_graph(url: str, **attrs) -> Graph:
    g = Graph({"purpose": PURPOSE})
    prof = g.add_node(Node.make(T.URL, url, {"site": "example", **attrs}, "import:username-engine:x.json"), NOW)
    user = g.add_node(Node.make(T.USERNAME, "jan_k", {}, "seed"), NOW)
    g.add_edge(Edge(user.id, prof.id, "has_account", "import:username-engine:x.json", 0.7, "konto", NOW))
    return g


def _frozen(g: Graph, node_id: str):
    node = g.nodes[node_id]
    return (
        json.dumps(node.to_dict(), sort_keys=True),
        sorted(json.dumps(e.to_dict(), sort_keys=True) for e in g.edges_of(node_id)),
    )


@pytest.mark.parametrize(
    "attrs,shown", [({"kind": "profile"}, "profile"), ({"kind": "gravatar"}, "gravatar"), ({}, "brak kind")]
)
def test_source_url_colliding_with_non_source_node_is_rejected_and_node_untouched(tmp_path, capsys, attrs, shown):
    g = _profile_graph("https://prs.ms.gov.pl/krs/odpis/0000123456", **attrs)
    pid = "url:prs.ms.gov.pl/krs/odpis/0000123456"
    before = _frozen(g, pid)
    case = make_case(tmp_path, graph=g)
    assert run_cli(case, FX / "export_basic.json") == 4
    out = capsys.readouterr().out
    assert f"kolizja: URL źródła istnieje w grafie jako {shown}" in out
    result = case_graph(case)
    assert _frozen(result, pid) == before
    assert not [e for e in result.edges.values() if e.relation == "has_source" and e.dst == pid]
    # firma i domena opierały się wyłącznie na tym źródle (rejestr), więc też odpadły; incydent (CERT) zostaje
    assert ORG not in result.nodes and "domain:example.test" not in result.nodes and BREACH in result.nodes
    assert result.nodes[pid].attrs.get("kind") == attrs.get("kind")


def test_record_with_two_sources_keeps_the_valid_one_when_the_other_collides():
    g = _profile_graph("https://haveibeenpwned.com/api/v3/breach/DemoBreach", kind="profile")
    imp = parsed(load("export_two_sources.json"), existing=g)
    assert [r.label.split(" ")[0] for r in imp.rejected] == ["źródło"] and "kolizja" in imp.rejected[0].reason
    breach = next(n for n in imp.nodes if n.id == BREACH)
    assert [p["source_type"] for p in breach.attrs["provenance"]] == ["cert_advisory"]
    has = [e for e in imp.edges if e.src == BREACH and e.relation == "has_source"]
    assert [e.dst for e in has] == ["url:cert.pl/posts/2026/10/demo-wyciek-stealer"]
    assert not any(e.dst == "url:haveibeenpwned.com/api/v3/breach/DemoBreach" for e in imp.edges)
    assert imp.rejected_edges == 2  # has_source do kolidującego URL i associated_with_incident z tego źródła


def test_existing_source_node_is_not_a_collision(tmp_path):
    g, _ = import_graph(tmp_path, load("export_basic.json"))
    assert not parsed(load("export_basic.json"), existing=g).rejected


def test_has_source_to_non_source_node_in_target_graph_is_refused_by_apply():
    imp = parsed(load("export_basic.json"))  # bez wiedzy o grafie sprawy
    g = _profile_graph("https://prs.ms.gov.pl/krs/odpis/0000123456", kind="profile")
    before = json.dumps(g.to_dict(), sort_keys=True)
    with pytest.raises(AssertionError):
        org_intel.apply(g, imp, "x.json", NOW)
    assert json.dumps(g.to_dict(), sort_keys=True) == before  # nic nie zostało scalone


def test_scope_check_rejects_non_source_url_node_in_import():
    imp = org_intel.OrgIntelImported(org_intel.TOOL)
    prof = Node.make(T.URL, "https://example.test/p", {"kind": "profile"})
    dom = Node.make(T.DOMAIN, "example.test")
    imp.nodes += [prof, dom]
    imp.edges.append(Edge(dom.id, prof.id, "has_source", "org-intel:x", 0.5, "x"))
    with pytest.raises(AssertionError):
        org_intel._assert_scope(imp)


# ------------------------------------------------------------------ licznik odrzuconych krawędzi


def _counts(data):
    imp = parsed(data)
    return len(imp.rejected), imp.rejected_edges, len(imp.nodes), len(imp.edges)


def test_rejected_incident_counts_all_its_dependent_edges_once():
    assert _counts(load("export_subdomain.json")) == (0, 0, 7, 8)
    # has_source(incydent) + associated_with_incident z shop (direct) + z example.test (inferred, domena nadrzędna)
    assert _counts(_drop(load("export_subdomain.json"), "incidents", password="x")) == (1, 3, 5, 5)
    # has_source + jedna krawędź associated_with_incident
    assert _counts(_drop(load("export_basic.json"), "incidents", password="x")) == (1, 2, 3, 3)


def test_rejected_domain_counts_has_source_owns_domain_and_incident_edges():
    data = _drop(load("export_subdomain.json"), "domains", index=1, password="x")
    assert data["domains"][1]["domain"] == "shop.example.test"
    # shop.example.test: has_source + owns_domain + associated_with_incident (direct); example.test zostaje
    assert _counts(data) == (1, 3, 5, 5)


def test_rejected_organization_counts_its_has_source_and_owns_domain_edges():
    # firma odrzucona (2 krawędzie); jej official_domain przestaje uprawniać źródło company_website (druga odrzucona)
    assert _counts(_drop(load("export_basic.json"), "organizations", password="x")) == (2, 2, 4, 3)


def test_rejected_source_counts_edges_of_records_that_survive_on_other_sources():
    data = load("export_two_sources.json")
    next(s for s in data["sources"] if s["source_type"] == "hibp_catalog")["url"] = "https://t.me/x"
    # has_source(incydent, hibp) + associated_with_incident (example.test, hibp)
    assert _counts(data) == (1, 2, 5, 5)


def test_cli_report_shows_rejected_nodes_and_edges(tmp_path, capsys):
    case = make_case(tmp_path)
    data = _drop(load("export_subdomain.json"), "incidents", password="x")
    assert run_cli(case, write(tmp_path, data), "--json") == 4
    report = json.loads(capsys.readouterr().out)
    assert (report["rejected_records"], report["rejected_edges"]) == (1, 3)
    assert (report["nodes_created"], report["edges_created"]) == (5, 5)


# ================================================================== runda 3: utwardzenie importera


def _src(data, stype="cert_advisory"):
    return next(s for s in data["sources"] if s["source_type"] == stype)


def _reasons(imp) -> str:
    return " | ".join(r.reason for r in imp.rejected)


# ------------------------------------------------------------------ --strict


def _unchanged_case(case: Path):
    return (
        (case / "graph.json").read_bytes(),
        (case / "audit.jsonl").read_bytes(),
        sorted(p.name for p in case.iterdir()),
    )


def test_strict_refuses_on_first_rejection_and_writes_nothing(tmp_path, capsys):
    case = make_case(tmp_path)
    before = _unchanged_case(case)
    data = _drop(load("export_basic.json"), "incidents", password="x")
    assert run_cli(case, write(tmp_path, data), "--strict") == 5
    out = capsys.readouterr().out
    assert out.startswith("ODMOWA (--strict): nic nie zapisano") and "ODRZUCONO incydent" in out
    assert _unchanged_case(case) == before  # graph.json i audit.jsonl bajtowo bez zmian
    assert verify_audit(case / "audit.jsonl")[0]


def test_strict_without_rejections_imports_normally(tmp_path, capsys):
    case = make_case(tmp_path)
    assert run_cli(case, FX / "export_basic.json", "--strict") == 0
    assert BREACH in case_graph(case).nodes and "ODMOWA" not in capsys.readouterr().out


def test_strict_treats_unknown_fields_as_rejections_default_mode_only_counts_them(tmp_path, capsys):
    data = _drop(load("export_basic.json"), "incidents", dodatkowe="x")
    imp = parsed(data)
    assert not imp.rejected and imp.unknown_fields == 1 and BREACH in {n.id for n in imp.nodes}
    strict = parsed(data, strict=True)
    assert "nieznane pola rekordu (tryb strict): dodatkowe" in _reasons(strict) and BREACH not in {
        n.id for n in strict.nodes
    }
    case = make_case(tmp_path)
    before = _unchanged_case(case)
    assert run_cli(case, write(tmp_path, data), "--strict") == 5
    assert _unchanged_case(case) == before
    capsys.readouterr()
    assert run_cli(case, write(tmp_path, data), "--json") == 0
    assert json.loads(capsys.readouterr().out)["unknown_fields"] == 1


@pytest.mark.parametrize("where", ["sources", "organizations", "domains", "observations"])
def test_unknown_fields_are_found_in_every_record_type(where):
    data = load("export_subdomain.json")
    data[where][0]["dodatkowe"] = 1
    assert parsed(data).unknown_fields == 1
    strict = parsed(data, strict=True)
    assert strict.rejected and "nieznane pola" in _reasons(strict)


def test_unknown_top_level_keys_are_counted_and_reject_the_file_only_in_strict(tmp_path, capsys):
    data = load("export_basic.json")
    data["cos_nowego"] = {}
    imp = parsed(data)  # domyślnie: liczone, plik przyjęty
    assert not imp.rejected and imp.unknown_fields == 1
    imp = parsed(data, strict=True)  # strict: odmowa całego pliku z nazwą klucza
    assert [r.label for r in imp.rejected] == ["plik"] and "cos_nowego" in imp.rejected[0].reason
    case = make_case(tmp_path)
    before = _unchanged_case(case)
    assert run_cli(case, write(tmp_path, data), "--strict") == cli.EXIT_STRICT
    capsys.readouterr()
    assert _unchanged_case(case) == before


# ------------------------------------------------------------------ niekompletna organizacja i identyfikatory


@pytest.mark.parametrize(
    "change,reason",
    [
        ({"legal_name": ""}, "bez nazwy"),
        ({"legal_name": None}, "bez nazwy"),
        ({"source_ids": []}, "brak źródła"),
        ({"krs": "abc"}, "KRS"),
        ({"nip": "5271001239"}, "NIP"),
        ({"nip": "123"}, "NIP"),
        ({"regon": "360123450"}, "REGON"),
        ({"regon": "12345"}, "REGON"),
        ({"official_domain": "10.0.0.1"}, "adres IP"),
    ],
)
def test_incomplete_or_invalid_organization_is_rejected_not_trimmed(change, reason):
    imp = parsed(_drop(load("export_basic.json"), "organizations", **change))
    org_rej = [r for r in imp.rejected if r.label.startswith("organizacja")]
    assert len(org_rej) == 1 and reason in org_rej[0].reason
    assert ORG not in {n.id for n in imp.nodes} and not imp.warnings[1:]  # nic nie jest wycinane z ostrzeżeniem


# ------------------------------------------------------------------ dane logowania w URL


@pytest.mark.parametrize(
    "bad",
    [
        "https://user:haslo@cert.pl/posts/x",
        "https://user@cert.pl/posts/x",
        "https://cert.pl/posts/x?kontakt=jan@example.test",
    ],
)
def test_url_with_credentials_or_email_is_rejected_in_source_and_evidence_url(bad):
    data = load("export_basic.json")
    _src(data)["url"] = bad
    imp = parsed(data)
    assert BREACH not in {n.id for n in imp.nodes} and "haslo" not in _reasons(imp)
    assert "danymi logowania" in _reasons(imp) or "'@'" in _reasons(imp)
    assert not any("haslo" in json.dumps(n.to_dict()) for n in imp.nodes)
    data = load("export_basic.json")
    next(o for o in data["observations"] if o["entity_type"] == "incident")["evidence_url"] = bad
    imp = parsed(data)
    assert BREACH not in {n.id for n in imp.nodes} and any(r.label.startswith("incydent") for r in imp.rejected)
    assert "haslo" not in _reasons(imp)


# ------------------------------------------------------------------ blokady hostów

BAD_HOSTS = [
    "http://127.0.0.1/x",
    "http://10.1.2.3/x",
    "http://2130706433/",
    "http://0x7f000001/",
    "http://0177.0.0.1/",
    "http://127.1/",
    "http://[::1]/",
    "http://[2001:db8::1]/x",
    "http://localhost/x",
    "http://a.localhost/x",
    "http://srv.local/x",
    "http://db.internal/x",
    "http://abcdefghijklmnop.onion/x",
    "http://x.i2p/x",
    "https://raidforums.com/t",
    "https://breachforums.st/t",
    "https://xss.is/t",
    "https://forum.xss.is/t",
    "https://exploit.in/t",
    "https://nulled.to/t",
    "https://cracked.io/t",
    "https://leakbase.io/t",
    "https://dread.cx/t",
    "https://www.dread.xyz/t",
    "https://my-breachforums-mirror.example.test/t",
]


@pytest.mark.parametrize("url", BAD_HOSTS)
def test_blocked_hosts_are_rejected_for_every_source_type_and_evidence_url(url):
    for stype in ("manual", "passive_dns", "cert_advisory"):
        data = load("export_basic.json")
        _src(data).update({"source_type": stype, "url": url, "name": "Zrodlo"})
        imp = parsed(data)
        assert BREACH not in {n.id for n in imp.nodes}, (stype, url)
        assert any(r.label.startswith("źródło") for r in imp.rejected)
    data = load("export_basic.json")
    next(o for o in data["observations"] if o["entity_type"] == "incident")["evidence_url"] = url
    assert BREACH not in {n.id for n in parsed(data).nodes}


@pytest.mark.parametrize(
    "url", ["https://dreadnought.example.test/x", "https://annulled.example.test/x", "https://notes.example.test/n/1"]
)
def test_host_blocklist_does_not_catch_lookalike_words(url):
    data = load("export_basic.json")
    _src(data).update({"source_type": "manual", "url": url, "name": "Notatka"})
    imp = parsed(data)
    assert not imp.rejected and BREACH in {n.id for n in imp.nodes}


@pytest.mark.parametrize(
    "host,expected",
    [
        ("127.0.0.1", True),
        ("2130706433", True),
        ("0x7f000001", True),
        ("0177.0.0.1", True),
        ("::1", True),
        ("[::1]", True),
        ("fe80::1%25eth0", True),
        ("1.2.3", True),
        ("example.test", False),
        ("cert.pl", False),
        ("a1.example.test", False),
        ("0x.example.test", False),
    ],
)
def test_is_ip_host_covers_every_notation(host, expected):
    assert org_intel.is_ip_host(host) is expected


# ------------------------------------------------------------------ zgodność hosta z typem źródła


def _with_source(stype, url, name="Zrodlo"):
    data = load("export_basic.json")
    _src(data).update({"source_type": stype, "url": url, "name": name})
    return data


@pytest.mark.parametrize(
    "stype,url,category",
    [
        ("hibp_catalog", "https://haveibeenpwned.com/api/v3/breach/DemoBreach", "hibp_catalog"),
        ("hibp_catalog", "https://api.haveibeenpwned.com/api/v3/breach/DemoBreach", "hibp_catalog"),
        ("cert_advisory", "https://cert.pl/posts/2026/10/demo", "cert"),
        ("cert_advisory", "https://www.cert.pl/posts/2026/10/demo", "cert"),
        ("cert_advisory", "https://cert.europa.eu/publications/demo", "cert"),
        ("cert_advisory", "https://nask.pl/aktualnosci/demo", "nask"),
        ("cert_advisory", "https://csirt.gov.pl/cert/demo", "csirt"),
        ("cert_advisory", "https://www.gov.pl/web/baza-wiedzy/demo", "csirt"),
        ("cert_advisory", "https://security.example.test/advisory/demo", "vendor_advisory"),
        ("official_document", "https://www.gov.pl/attachment/demo.pdf", "public_report"),
        ("official_document", "https://eur-lex.europa.eu/demo", "public_report"),
        ("official_document", "https://www.example.test/raport.pdf", "public_report"),
        ("ct_log", "https://crt.sh/?id=12345", "ct_log"),
        ("passive_dns", "https://dns.example.org/lookup/example.test", "passive_dns"),
        ("manual", "https://notes.example.org/n/1", "manual"),
        ("official_registry", "https://ekrs.ms.gov.pl/web/wyszukiwarka-krs/demo", "official_registry"),
        ("official_registry", "https://wyszukiwarkaregon.stat.gov.pl/demo", "official_registry"),
        ("official_registry", "https://biznes.gov.pl/ceidg/firma/demo", "official_registry"),
        ("official_registry", "https://dane.biznes.gov.pl/api/ceidg/v3/firmy", "official_registry"),
        ("company_website", "https://www.example.test/o-nas", "official_company"),
        ("company_website", "https://sklep.example.test/o-nas", "official_company"),
    ],
)
def test_allowed_hosts_per_source_type_and_category_in_provenance(stype, url, category):
    imp = parsed(_with_source(stype, url))
    assert not imp.rejected, _reasons(imp)
    breach = next(n for n in imp.nodes if n.id == BREACH)
    assert breach.attrs["provenance"][0]["source_category"] == category
    assert breach.attrs["provenance"][0]["source_type"] == stype
    target = next(
        n
        for n in imp.nodes
        if n.type is T.URL and n.attrs["kind"] == "source" and n.attrs["source_category"] == category
    )
    assert target.attrs["source_category"] == category


@pytest.mark.parametrize(
    "stype,url",
    [
        ("hibp_catalog", "https://example.test/hibp"),
        ("hibp_catalog", "https://haveibeenpwned.com.evil.test/x"),
        ("hibp_catalog", "https://evil-haveibeenpwned.com/x"),
        ("hibp_catalog", "https://cert.pl/hibp"),
        ("hibp_catalog", "https://www.haveibeenpwned.com/x"),
        ("cert_advisory", "https://blog.example.org/advisory"),
        ("cert_advisory", "https://cert.pl.evil.test/x"),
        ("cert_advisory", "https://notcert.pl/x"),
        ("official_document", "https://example.org/raport.pdf"),
        ("ct_log", "https://example.org/ct"),
        ("official_registry", "https://example.test/krs"),
        ("official_registry", "https://biznes.gov.pl/inne/firma"),
        ("official_registry", "https://www.gov.pl/web/demo"),
        ("company_website", "https://cert.pl/o-nas"),
        ("company_website", "https://example.test.evil.org/o-nas"),
        ("company_website", "https://notexample.test/o-nas"),
    ],
)
def test_host_that_does_not_match_the_source_type_is_rejected_fail_closed(stype, url):
    imp = parsed(_with_source(stype, url))
    assert BREACH not in {n.id for n in imp.nodes}
    assert "nie pasuje do typu źródła" in _reasons(imp)


def test_company_website_needs_an_official_domain_from_the_same_import():
    data = load("export_basic.json")
    data["organizations"][0]["official_domain"] = None
    imp = parsed(_with_source("company_website", "https://www.example.test/o-nas"))
    assert not imp.rejected
    data = _with_source("company_website", "https://www.example.test/o-nas")
    data["organizations"][0]["official_domain"] = "inna-domena.test"
    imp = parsed(data)
    assert BREACH not in {n.id for n in imp.nodes} and "nie pasuje" in _reasons(imp)


def test_allowlists_are_injected_as_a_parameter_never_extended_in_production_constants():
    from dataclasses import replace

    data = _with_source("cert_advisory", "https://cert.example.org/posts/demo")
    assert BREACH not in {n.id for n in parsed(data).nodes}
    rules = replace(
        org_intel.DEFAULT_RULES, advisory=(*org_intel.DEFAULT_RULES.advisory, ("cert", ("cert.example.org",)))
    )
    assert BREACH in {n.id for n in parsed(data, rules=rules).nodes}
    flat = [h for _, hosts in org_intel.DEFAULT_RULES.advisory for h in hosts] + list(org_intel.DEFAULT_RULES.hibp)
    flat += [h for h, _ in org_intel.DEFAULT_RULES.registry] + list(org_intel.DEFAULT_RULES.ct_log)
    flat += list(org_intel.DEFAULT_RULES.public_report)
    assert not any("example" in h for h in flat)


def test_source_type_table_covers_every_org_intel_type_and_has_quality_for_each_category():
    assert set(org_intel.SOURCE_TYPE_TABLE) == set(org_intel._SOURCE_TYPES)
    categories = {c for rule in org_intel.SOURCE_TYPE_TABLE.values() for c in rule.categories}
    assert categories == set(org_intel.CATEGORY_QUALITY)
    assert {
        "official_registry",
        "official_company",
        "cert",
        "csirt",
        "nask",
        "vendor_advisory",
        "public_report",
        "hibp_catalog",
        "ct_log",
        "passive_dns",
        "manual",
    } == categories


@pytest.mark.parametrize(
    "stype,url,quality",
    [
        ("cert_advisory", "https://cert.pl/posts/demo", "high"),
        # host = domena oficjalna z tego samego pliku: niezweryfikowana, więc najwyżej low (nie medium/high)
        ("cert_advisory", "https://security.example.test/a", "low"),
        ("official_document", "https://www.gov.pl/a.pdf", "high"),
        ("official_document", "https://www.example.test/a.pdf", "low"),
        ("hibp_catalog", "https://haveibeenpwned.com/x", "medium"),
        ("ct_log", "https://crt.sh/?id=1", "medium"),
        ("passive_dns", "https://dns.example.org/x", "low"),
        ("manual", "https://notes.example.org/x", "low"),
    ],
)
def test_quality_follows_category_base_capped_by_reliability(stype, url, quality):
    imp = parsed(_with_source(stype, url))
    prov = next(n for n in imp.nodes if n.id == BREACH).attrs["provenance"][0]
    assert prov["quality"] == quality
    data = _with_source(stype, url)
    _src(data, stype)["reliability"] = "low"
    assert next(n for n in parsed(data).nodes if n.id == BREACH).attrs["provenance"][0]["quality"] == "low"


# ------------------------------------------------------------------ maskowanie e-maili


def _mail_data():
    data = load("export_basic.json")
    org = data["organizations"][0]
    org["legal_name"] = "Example Sp. z o.o. (kontakt: biuro@example.test)"
    org["previous_names"] = ["Dawna Nazwa jan.nowak@example.test"]
    inc = data["incidents"][0]
    inc["description"] = "Zgłoszenie od anna@example.test oraz drugi@example.test."
    inc["title"] = "DemoBreach wg jan@example.test"
    _src(data)["name"] = "Komunikat, kontakt cert@example.test"
    _src(data)["license"] = "CC BY 4.0, autor a.b@example.test"
    return data


def test_emails_are_masked_in_every_text_field_and_counted(tmp_path, capsys):
    imp = parsed(_mail_data())
    assert not imp.rejected
    dump = json.dumps([n.to_dict() for n in imp.nodes] + [e.to_dict() for e in imp.edges], ensure_ascii=False)
    # maska całkowita: bez pierwszej litery i bez domeny
    assert "@" not in dump and "***" not in dump and org_intel.EMAIL_MASK in dump
    org = next(n for n in imp.nodes if n.attrs.get("kind") == "company")
    assert org.value == f"Example Sp. z o.o. (kontakt: {org_intel.EMAIL_MASK})"
    assert org.attrs["previous_names"] == [f"Dawna Nazwa {org_intel.EMAIL_MASK}"]
    inc = next(n for n in imp.nodes if n.attrs.get("kind") == "breach")
    assert inc.attrs["description"] == f"Zgłoszenie od {org_intel.EMAIL_MASK} oraz {org_intel.EMAIL_MASK}."
    assert inc.value == f"DemoBreach wg {org_intel.EMAIL_MASK}"
    # pola: legal_name, previous_names, title, description, nazwa źródła, licencja źródła (rejestr bez maili nie liczy się)
    assert imp.masked_fields == 6
    case = make_case(tmp_path)
    report = tmp_path / "raport.json"
    assert run_cli(case, write(tmp_path, _mail_data()), "--report", str(report)) == 0
    capsys.readouterr()
    for name in ("graph.json", "audit.jsonl", "graph.graphml", "report.html", "kropki.svg"):
        text = (case / name).read_text(encoding="utf-8")
        assert not re.search(r"[A-Za-z0-9._-]{2,}@example\.test", text), name
    assert json.loads(report.read_text(encoding="utf-8"))["masked_fields"] == 6
    assert "@" not in report.read_text(encoding="utf-8")


def test_missing_or_false_emails_masked_flag_gives_a_warning_but_masking_is_always_on():
    data = load("export_basic.json")
    assert data["emails_masked"] is True and not parsed(data).warnings
    for value in (False, "tak", None):
        data["emails_masked"] = value
        imp = parsed(data)
        assert any("emails_masked" in w for w in imp.warnings)
    del data["emails_masked"]
    assert any("emails_masked" in w for w in parsed(data).warnings)
    store = parsed(load("store_basic.json"))
    assert any("store.json" in w and "emails_masked" in w for w in store.warnings)


def test_masking_counter_ignores_rejected_records():
    data = _mail_data()
    next(i for i in data["incidents"])["password"] = "x"
    imp = parsed(data)
    assert imp.masked_fields == 4  # legal_name, previous_names, nazwa źródła, licencja: bez 2 pól incydentu
    assert any(r.label.startswith("incydent") for r in imp.rejected)


# ------------------------------------------------------------------ brak derivation / reliability, enumy


@pytest.mark.parametrize(
    "key,value",
    [
        ("derivation", None),
        ("derivation", ""),
        ("derivation", "maybe"),
        ("derivation", "Direct"),
        ("confidence", None),
        ("confidence", "wysoka"),
        ("confidence", "HIGH"),
    ],
)
def test_observation_without_valid_derivation_or_confidence_is_rejected(key, value):
    data = load("export_basic.json")
    obs = next(o for o in data["observations"] if o["entity_type"] == "incident")
    if value is None:
        del obs[key]
    else:
        obs[key] = value
    imp = parsed(data)
    assert BREACH not in {n.id for n in imp.nodes} and key in _reasons(imp)


@pytest.mark.parametrize("value", [None, "", "super", "High"])
def test_source_without_valid_reliability_is_rejected(value):
    data = load("export_basic.json")
    if value is None:
        del _src(data)["reliability"]
    else:
        _src(data)["reliability"] = value
    imp = parsed(data)
    assert "reliability" in _reasons(imp) and BREACH not in {n.id for n in imp.nodes}


def test_domain_without_verification_status_is_rejected():
    data = load("export_basic.json")
    del data["domains"][0]["verification_status"]
    assert "verification_status" in _reasons(parsed(data))


# ------------------------------------------------------------------ duplikaty organizacji


def _second_org(data, **changes):
    org = {**data["organizations"][0], "id": "org_bbbbbbbbbbbbbbbb", **changes}
    data["organizations"].append(org)
    data["observations"].append(
        {
            **next(o for o in data["observations"] if o["entity_type"] == "organization"),
            "id": "obs_bbbbbbbbbbbbbbbb",
            "entity_id": org["id"],
        }
    )
    return data


def test_duplicate_organization_by_krs_inside_one_file_is_one_node_with_previous_name():
    data = _second_org(load("export_basic.json"), legal_name="Example Spolka z ograniczona odpowiedzialnoscia 2")
    data["organizations"][1]["nip"] = None
    imp = parsed(data)
    companies = [n for n in imp.nodes if n.attrs.get("kind") == "company"]
    assert not imp.rejected and [n.value for n in companies] == ["Example Sp. z o.o."]
    assert companies[0].attrs["previous_names"] == ["Example Spolka z ograniczona odpowiedzialnoscia 2"]
    assert companies[0].attrs["nip"] == "5271001238"


def test_duplicate_organization_by_nip_or_regon_inside_one_file_merges_and_fills_missing_ids():
    data = _second_org(load("export_basic.json"), legal_name="Inna Nazwa S.A.", krs=None)
    data["organizations"][0]["regon"] = None
    imp = parsed(data)
    companies = [n for n in imp.nodes if n.attrs.get("kind") == "company"]
    assert len(companies) == 1 and companies[0].attrs["regon"] == "360123459"
    assert companies[0].attrs["previous_names"] == ["Inna Nazwa S.A."]


def test_same_krs_with_conflicting_nip_rejects_the_second_record_with_reason():
    data = _second_org(load("export_basic.json"), legal_name="Zupelnie Inna Firma", nip="1234563218")
    imp = parsed(data)
    assert [r.reason for r in imp.rejected] == [
        "konflikt identyfikatorów: ten sam KRS co istniejąca organizacja, ale sprzeczny NIP"
    ]
    assert [n.value for n in imp.nodes if n.attrs.get("kind") == "company"] == ["Example Sp. z o.o."]


def test_same_krs_with_conflicting_nip_between_imports_is_rejected(tmp_path):
    case = make_case(tmp_path)
    assert run_cli(case, FX / "export_basic.json") == 0
    other = _drop(load("export_basic.json"), "organizations", legal_name="Obca Firma", nip="1234563218")
    assert run_cli(case, write(tmp_path, other)) == 4
    g = case_graph(case)
    assert [n.value for n in nodes_of(g, T.ORGANIZATION) if n.attrs.get("kind") == "company"] == ["Example Sp. z o.o."]


# ------------------------------------------------------------------ daty


@pytest.mark.parametrize(
    "section,field,value",
    [
        ("incidents", "incident_date", "2026-02-30"),
        ("incidents", "incident_date", "2099-01-01"),
        ("incidents", "incident_date", "wczoraj"),
        ("incidents", "incident_date", "1969-05-05"),
        ("incidents", "published_date", "2026-13-01"),
        ("incidents", "published_date", "2026-10-09"),
        ("sources", "retrieved_at", "2026-02-30T10:00:00Z"),
        ("sources", "retrieved_at", "2026-10-07T00:00:00Z"),
        ("sources", "retrieved_at", "nie data"),
        ("observations", "observed_at", "2026-02-30T10:00:00Z"),
        ("observations", "observed_at", "2030-01-01T00:00:00Z"),
        ("observations", "observed_at", ""),
    ],
)
def test_invalid_or_future_dates_reject_the_record(section, field, value):
    data = load("export_basic.json")
    target = (
        _src(data)
        if section == "sources"
        else next(o for o in data["observations"] if o["entity_type"] == "incident")
        if section == "observations"
        else data[section][0]
    )
    target[field] = value
    imp = parsed(data)
    assert imp.rejected and field in _reasons(imp) and BREACH not in {n.id for n in imp.nodes}


def test_dates_within_one_day_of_now_and_empty_optional_dates_are_accepted():
    data = load("export_basic.json")
    data["incidents"][0]["published_date"] = "2026-10-06"  # NOW = 2026-10-05T12:00: mniej niż doba
    data["incidents"][0]["incident_date"] = None
    imp = parsed(data)
    assert not imp.rejected
    attrs = next(n for n in imp.nodes if n.id == BREACH).attrs
    assert attrs["published_date"] == "2026-10-06" and "incident_date" not in attrs


def test_verified_domain_with_invalid_verified_at_is_rejected():
    data = _verified(load("export_basic.json"), "verified", at="2026-02-30T00:00:00Z")
    assert "verified_at" in _reasons(parsed(data))


# ------------------------------------------------------------------ adres IP jako domena


@pytest.mark.parametrize(
    "value",
    [
        "127.0.0.1",
        "10.0.0.1",
        "http://192.168.0.1/x",
        "2130706433",
        "0x7f.0x1",
        "[::1]",
        "user@example.test",
        "https://user:x@example.test",
    ],
)
def test_ip_or_credentials_as_domain_are_rejected(value):
    data = _drop(load("export_subdomain.json"), "domains", index=1, domain=value)
    imp = parsed(data)
    assert any(r.label.startswith("domena") for r in imp.rejected) and "domain:shop.example.test" not in {
        n.id for n in imp.nodes
    }
    data = _drop(load("export_basic.json"), "incidents", affected_domain=value)
    imp = parsed(data)
    assert any(r.label.startswith("incydent") for r in imp.rejected) and BREACH not in {n.id for n in imp.nodes}


# ------------------------------------------------------------------ --report, --format, import_id


def test_report_file_is_written_atomically_without_personal_data_and_matches_json_output(tmp_path, capsys):
    case = make_case(tmp_path)
    report = tmp_path / "raport.json"
    assert run_cli(case, FX / "store_basic.json", "--report", str(report), "--format", "json") == 0
    printed = json.loads(capsys.readouterr().out)
    saved = json.loads(report.read_text(encoding="utf-8"))
    assert saved == printed and saved["skipped_people"] == 1 and saved["import_id"].startswith("imp_")
    text = report.read_text(encoding="utf-8")
    assert EMAIL not in text and "Jan Kowalski" not in text
    assert not [p for p in tmp_path.iterdir() if p.name.startswith(".raport")]  # brak śmieci po zapisie atomowym


def test_report_is_written_for_dry_run_and_for_strict_refusal(tmp_path, capsys):
    case = make_case(tmp_path)
    before = _unchanged_case(case)
    report = tmp_path / "dry.json"
    assert run_cli(case, FX / "export_basic.json", "--dry-run", "--report", str(report)) == 0
    assert json.loads(report.read_text(encoding="utf-8"))["dry_run"] is True
    bad = write(tmp_path, _drop(load("export_basic.json"), "incidents", password="x"))
    refusal = tmp_path / "odmowa.json"
    assert run_cli(case, bad, "--strict", "--report", str(refusal)) == 5
    saved = json.loads(refusal.read_text(encoding="utf-8"))
    assert saved["refused"] is True and saved["strict"] is True and saved["rejected_records"] == 1
    assert _unchanged_case(case) == before


def test_report_path_in_missing_directory_is_a_usage_error_before_anything_happens(tmp_path, capsys):
    case = make_case(tmp_path)
    before = _unchanged_case(case)
    assert run_cli(case, FX / "export_basic.json", "--report", str(tmp_path / "brak" / "r.json")) == 2
    assert run_cli(case, FX / "export_basic.json", "--report", str(tmp_path)) == 2
    assert _unchanged_case(case) == before


def test_format_json_equals_json_alias_and_conflicting_flags_are_a_usage_error(tmp_path, capsys, monkeypatch):
    # stały czas: import_id zależy od chwili importu (sekunda), więc bez tego raporty różniłyby się na granicy sekundy
    monkeypatch.setattr(cli, "utc_now", lambda: NOW)
    case = make_case(tmp_path)
    assert run_cli(case, FX / "export_basic.json", "--dry-run", "--json") == 0
    a = json.loads(capsys.readouterr().out)
    assert run_cli(case, FX / "export_basic.json", "--dry-run", "--format", "json") == 0
    b = json.loads(capsys.readouterr().out)
    assert a == b
    assert run_cli(case, FX / "export_basic.json", "--dry-run", "--format", "text") == 0
    assert capsys.readouterr().out.startswith("DRY-RUN")
    assert run_cli(case, FX / "export_basic.json", "--dry-run", "--json", "--format", "text") == 2
    assert "sprzeczne" in capsys.readouterr().err
    assert run_cli(case, FX / "export_basic.json", "--dry-run", "--json", "--format", "json") == 0


def test_import_id_is_in_report_audit_and_first_provenance_entry_and_does_not_break_idempotence(
    tmp_path, capsys, monkeypatch
):
    clock = iter(f"2026-10-05T13:00:{i:02d}+00:00" for i in range(60))
    monkeypatch.setattr(cli, "utc_now", lambda: next(clock))
    case = make_case(tmp_path)
    assert run_cli(case, FX / "export_subdomain.json", "--json") == 0
    first = json.loads(capsys.readouterr().out)["import_id"]
    g = case_graph(case)
    ids = {p["import_id"] for n in g.nodes.values() for p in n.attrs.get("provenance", [])}
    assert ids == {first}
    graph_bytes = (case / "graph.json").read_bytes()
    assert run_cli(case, FX / "export_subdomain.json", "--json") == 0
    second = json.loads(capsys.readouterr().out)
    assert second["import_id"] != first and second["nodes_updated"] == 0 and second["edges_updated"] == 0
    assert (case / "graph.json").read_bytes() == graph_bytes  # graf bez zmian, wpisy trzymają pierwszy import_id
    events = [json.loads(x) for x in (case / "audit.jsonl").read_text(encoding="utf-8").splitlines()]
    assert {e["import_id"] for e in events if e["event"] == "org_intel_import" and e["phase"] == "przed"} == {
        first,
        second["import_id"],
    }
    assert {e["import_id"] for e in events if e["event"] == "org_intel_import" and e["phase"] == "po"} == {
        first,
        second["import_id"],
    }


def test_import_id_is_stable_within_one_run_and_depends_on_file_and_time():
    a = org_intel.make_import_id("a" * 64, NOW)
    assert a == org_intel.make_import_id("a" * 64, NOW) and a != org_intel.make_import_id("b" * 64, NOW)
    assert a != org_intel.make_import_id("a" * 64, "2026-10-05T12:00:01+00:00") and re.fullmatch(r"imp_[0-9a-f]{12}", a)
    imp = parsed(load("export_basic.json"))
    assert {p["import_id"] for n in imp.nodes for p in n.attrs.get("provenance", [])} == {imp.import_id}


# ================================================================== runda 4: poprawki A-H (przegląd niezależny)

# ------------------------------------------------------------------ A. --report nie może nadpisać pliku sprawy


def _link_dir(target: Path, link: Path) -> bool:
    """Dowiązanie katalogu: symlink, a na Windows bez uprawnień - junction. False = środowisko nie pozwala."""
    try:
        link.symlink_to(target, target_is_directory=True)
        return True
    except (OSError, NotImplementedError):
        pass
    try:
        import _winapi  # tylko Windows

        _winapi.CreateJunction(str(target), str(link))
        return True
    except (ImportError, OSError):
        return False


@pytest.mark.parametrize("dry", [True, False])
@pytest.mark.parametrize("name", ["graph.json", "audit.jsonl", "report.html", "nowy_raport.json"])
def test_report_path_inside_case_is_refused_and_nothing_changes(tmp_path, capsys, name, dry):
    case = make_case(tmp_path)
    before = _unchanged_case(case)
    extra = ["--report", str(case / name)] + (["--dry-run"] if dry else [])
    assert run_cli(case, FX / "export_basic.json", *extra) == 2
    assert "--report" in capsys.readouterr().err
    assert _unchanged_case(case) == before and verify_audit(case / "audit.jsonl")[0]


def test_report_path_with_dotdot_or_relative_path_into_case_is_refused(tmp_path, capsys, monkeypatch):
    case = make_case(tmp_path)
    (tmp_path / "inny").mkdir()
    before = _unchanged_case(case)
    dotdot = str(tmp_path / "inny" / ".." / "sprawa" / "graph.json")
    assert run_cli(case, FX / "export_basic.json", "--dry-run", "--report", dotdot) == 2
    monkeypatch.chdir(case)
    assert run_cli(case, FX / "export_basic.json", "--dry-run", "--report", "graph.json") == 2
    assert run_cli(case, FX / "export_basic.json", "--report", "audit.jsonl") == 2
    capsys.readouterr()
    assert _unchanged_case(case) == before


@pytest.mark.skipif(__import__("sys").platform != "win32", reason="wielkość liter w ścieżkach: tylko Windows")
def test_report_path_differing_only_in_letter_case_is_refused_on_windows(tmp_path, capsys):
    case = make_case(tmp_path)
    before = _unchanged_case(case)
    upper = Path(str(case).upper()) / "GRAPH.JSON"
    assert run_cli(case, FX / "export_basic.json", "--dry-run", "--report", str(upper)) == 2
    assert "--report" in capsys.readouterr().err
    assert _unchanged_case(case) == before


def test_report_path_equal_to_input_is_refused(tmp_path, capsys):
    case = make_case(tmp_path)
    source = write(tmp_path, load("export_basic.json"))
    content = source.read_bytes()
    assert run_cli(case, source, "--dry-run", "--report", str(source)) == 2
    assert "--input" in capsys.readouterr().err and source.read_bytes() == content


def test_report_path_through_symlinked_or_junction_dir_into_case_is_refused(tmp_path, capsys):
    case = make_case(tmp_path)
    link = tmp_path / "skrot"
    if not _link_dir(case, link):
        pytest.skip("środowisko nie pozwala tworzyć dowiązań katalogów")
    before = _unchanged_case(case)
    for dry in (["--dry-run"], []):
        assert run_cli(case, FX / "export_basic.json", *dry, "--report", str(link / "graph.json")) == 2
    capsys.readouterr()
    assert _unchanged_case(case) == before


def test_report_path_as_file_link_to_case_file_is_refused(tmp_path, capsys):
    case = make_case(tmp_path)
    before = _unchanged_case(case)
    makers = (
        ("hard", lambda p: p.hardlink_to(case / "graph.json")),
        ("sym", lambda p: p.symlink_to(case / "audit.jsonl")),
    )
    tried = 0
    for kind, make in makers:
        link = tmp_path / f"{kind}.json"
        try:
            make(link)
        except (OSError, NotImplementedError):
            continue
        tried += 1
        assert run_cli(case, FX / "export_basic.json", "--dry-run", "--report", str(link)) == 2, kind
    if not tried:
        pytest.skip("środowisko nie pozwala tworzyć dowiązań plików")
    capsys.readouterr()
    assert _unchanged_case(case) == before


def test_report_outside_case_is_written(tmp_path, capsys):
    case = make_case(tmp_path)
    report = tmp_path / "raporty" / "r.json"
    report.parent.mkdir()
    assert run_cli(case, FX / "export_basic.json", "--dry-run", "--report", str(report)) == 0
    capsys.readouterr()
    assert json.loads(report.read_text(encoding="utf-8"))["dry_run"] is True


# ------------------------------------------------------------------ B. evidence_url: te same reguły co URL źródła

EVIDENCE_BAD = [
    "https://pastebin.com/abc",
    "https://t.me/kanal/1",
    "https://telegram.me/x",
    "https://dump.example.test/x",
    "https://leaks.example.test/x",
    "https://stealer-logs.example.test/x",
    "https://abcdefghijklmnop.onion/x",
    "https://127.0.0.1/x",
    "https://2130706433/x",
    "https://0x7f000001/x",
    "https://127.1/x",
    "https://[::1]/x",
    "https://10.0.0.5/x",
    "https://192.168.1.10/x",
    "https://localhost/x",
    "https://srv.internal/x",
    "https://raidforums.com/t",
]


@pytest.mark.parametrize("url", EVIDENCE_BAD)
def test_evidence_url_uses_the_same_host_and_leak_rules_as_source_urls(url):
    data = load("export_basic.json")
    next(o for o in data["observations"] if o["entity_type"] == "incident")["evidence_url"] = url
    imp = parsed(data)
    assert BREACH not in {n.id for n in imp.nodes} and "evidence_url" in _reasons(imp)


def test_evidence_url_leak_word_in_path_is_rejected_on_unofficial_host_but_accepted_in_cert_advisory():
    data = load("export_basic.json")  # obserwacja firmy ma źródło rejestru (typ nieopisujący wycieków)
    next(o for o in data["observations"] if o["entity_type"] == "organization")["evidence_url"] = (
        "https://www.example.test/pliki/dump-2026.txt"
    )
    imp = parsed(data)
    assert ORG not in {n.id for n in imp.nodes} and "dump" in _reasons(imp)
    data = load("export_basic.json")  # oficjalny komunikat CERT ze słowem "stealer" w ścieżce: przyjęty
    next(o for o in data["observations"] if o["entity_type"] == "incident")["evidence_url"] = CERT_URL + "-2"
    imp = parsed(data)
    assert not imp.rejected and BREACH in {n.id for n in imp.nodes}


# ------------------------------------------------------------------ C. zakodowane '@' (%40)


@pytest.mark.parametrize(
    "url", [KRS_URL + "%40user", "https://prs.ms.gov.pl/krs/a%40b", "https://prs.ms.gov.pl/x%2540y"]
)
def test_percent_encoded_at_sign_is_rejected_in_source_and_evidence_url(url):
    data = load("export_basic.json")
    _src(data, "official_registry")["url"] = url
    imp = parsed(data)
    assert ORG not in {n.id for n in imp.nodes} and "%40" in _reasons(imp)
    data = load("export_basic.json")
    next(o for o in data["observations"] if o["entity_type"] == "organization")["evidence_url"] = url
    assert ORG not in {n.id for n in parsed(data).nodes}


# ------------------------------------------------------------------ E. domena oficjalna z pliku nie podnosi jakości


def test_official_domain_from_the_same_file_does_not_raise_source_quality():
    data = load("export_basic.json")
    data["organizations"][0]["official_domain"] = "blogspot.com"  # plik może wskazać dowolną "domenę oficjalną"
    _src(data).update({"source_type": "cert_advisory", "url": "https://evil.blogspot.com/advisory", "name": "Blog"})
    imp = parsed(data)
    prov = next(n for n in imp.nodes if n.id == BREACH).attrs["provenance"][0]
    assert prov["quality"] == "low"
    for stype, url in (
        ("company_website", "https://www.example.test/o-nas"),
        ("official_document", "https://www.example.test/raport.pdf"),
    ):
        imp = parsed(_with_source(stype, url))
        assert next(n for n in imp.nodes if n.id == BREACH).attrs["provenance"][0]["quality"] == "low", stype
    imp = parsed(_with_source("cert_advisory", "https://cert.pl/posts/2026/10/x"))  # allowlista: bez zmian
    assert next(n for n in imp.nodes if n.id == BREACH).attrs["provenance"][0]["quality"] == "high"


# ------------------------------------------------------------------ F. tylko HTTPS na porcie 443


@pytest.mark.parametrize(
    "stype,url",
    [
        ("hibp_catalog", "https://haveibeenpwned.com:8443/api/v3/breach/DemoBreach"),
        ("hibp_catalog", "http://haveibeenpwned.com/api/v3/breach/DemoBreach"),
        ("cert_advisory", "http://cert.pl/posts/2026/10/demo"),
        ("cert_advisory", "https://cert.pl:8080/posts/2026/10/demo"),
        ("official_registry", "http://prs.ms.gov.pl/krs/odpis/0000123456"),
        ("manual", "http://notes.example.org/n/1"),
    ],
)
def test_only_https_on_port_443_is_accepted(stype, url):
    imp = parsed(_with_source(stype, url))
    assert "HTTPS na porcie 443" in _reasons(imp)


def test_explicit_port_443_is_accepted():
    imp = parsed(_with_source("cert_advisory", "https://cert.pl:443/posts/2026/10/demo"))
    assert not imp.rejected and BREACH in {n.id for n in imp.nodes}


# ------------------------------------------------------------------ G. rekord metadanych HIBP


def _hibp_data(description: str = "Metadane z publicznego katalogu HIBP.") -> dict:
    data = load("export_basic.json")
    _src(data).update(
        {"source_type": "hibp_catalog", "url": "https://haveibeenpwned.com/api/v3/breaches", "name": "HIBP"}
    )
    next(o for o in data["observations"] if o["entity_type"] == "incident")["evidence_url"] = (
        "https://haveibeenpwned.com/PwnedWebsites#DemoBreach"
    )
    data["incidents"][0].update(
        {"affected_accounts_count": 12345, "data_classes": ["Email addresses", "Passwords"], "description": description}
    )
    return data


def test_hibp_metadata_record_is_imported_as_metadata_only():
    imp = parsed(_hibp_data())
    assert not imp.rejected, _reasons(imp)
    inc = next(n for n in imp.nodes if n.id == BREACH)
    assert inc.attrs["affected_accounts_count"] == 12345
    assert inc.attrs["data_classes"] == ["Email addresses", "Passwords"]  # etykiety klas danych, nie dane
    assert inc.attrs["provenance"][0]["source_category"] == "hibp_catalog"
    assert not ({"emails", "accounts", "passwords", "addresses"} & set(inc.attrs))


def test_hibp_description_with_address_list_is_masked_and_with_credentials_is_rejected():
    imp = parsed(_hibp_data("Przykłady: jan.kowalski@example.test, anna.nowak@example.test, ola@example.test"))
    inc = next(n for n in imp.nodes if n.id == BREACH)
    assert "@" not in inc.attrs["description"] and inc.attrs["description"].count(org_intel.EMAIL_MASK) == 3
    imp = parsed(_hibp_data("Wyciek: jan.kowalski@example.test:Haslo123! oraz anna@example.test:qwerty99"))
    assert BREACH not in {n.id for n in imp.nodes} and "e-mail:hasło" in _reasons(imp)
    imp = parsed(_hibp_data("Hash: 5f4dcc3b5aa765d61d8327deb882cf99"))
    assert BREACH not in {n.id for n in imp.nodes}


# ------------------------------------------------------------------ H. maska całkowita


def test_email_mask_hides_whole_address_including_first_letter_and_domain():
    data = load("export_basic.json")
    data["incidents"][0]["description"] = "kontakt: jan.kowalski@example.test"
    inc = next(n for n in parsed(data).nodes if n.id == BREACH)
    assert inc.attrs["description"] == f"kontakt: {org_intel.EMAIL_MASK}"
    assert "j***" not in inc.attrs["description"] and "example.test" not in inc.attrs["description"]


# ------------------------------------------------------------------ A (runda 5): inne sprawy, istniejące pliki, nazwy


@pytest.mark.parametrize("dry", [True, False])
@pytest.mark.parametrize("name", ["graph.json", "audit.jsonl", "report.html", "nowy_raport.json"])
def test_report_path_into_another_case_is_refused(tmp_path, capsys, name, dry):
    case_a = make_case(tmp_path, "sprawaA")
    case_b = make_case(tmp_path, "sprawaB")
    before_a, before_b = _unchanged_case(case_a), _unchanged_case(case_b)
    extra = ["--report", str(case_b / name)] + (["--dry-run"] if dry else [])
    assert run_cli(case_a, FX / "export_basic.json", *extra) == 2
    assert "--report" in capsys.readouterr().err
    assert _unchanged_case(case_b) == before_b and verify_audit(case_b / "audit.jsonl")[0]
    assert _unchanged_case(case_a) == before_a  # odmowa przed importem: sprawa A też bez zmian


def test_report_path_in_subfolder_of_another_case_is_refused(tmp_path, capsys):
    case_a = make_case(tmp_path, "sprawaA")
    case_b = make_case(tmp_path, "sprawaB")
    (case_b / "dokumenty").mkdir()
    assert run_cli(case_a, FX / "export_basic.json", "--dry-run", "--report", str(case_b / "dokumenty" / "r.json")) == 2
    capsys.readouterr()


def test_existing_file_outside_any_case_is_never_overwritten(tmp_path, capsys):
    case = make_case(tmp_path)
    other = tmp_path / "raporty"
    other.mkdir()
    existing = other / "wazny.json"
    existing.write_text('{"moje": "dane"}', encoding="utf-8")
    for dry in (["--dry-run"], []):
        assert run_cli(case, FX / "export_basic.json", *dry, "--report", str(existing)) == 2
    assert "istnieje" in capsys.readouterr().err
    assert existing.read_text(encoding="utf-8") == '{"moje": "dane"}'
    fresh = other / "nowy.json"
    assert run_cli(case, FX / "export_basic.json", "--dry-run", "--report", str(fresh)) == 0
    capsys.readouterr()
    assert json.loads(fresh.read_text(encoding="utf-8"))["dry_run"] is True
    assert sorted(p.name for p in other.iterdir()) == ["nowy.json", "wazny.json"]  # bez plików tymczasowych


@pytest.mark.parametrize(
    "name", ["GRAPH.JSON", "graph.json.", "graph.json ", "graph.json:x", "Audit.JSONL", "kropki.svg", "maltego.csv"]
)
def test_reserved_case_file_names_are_refused_in_any_folder(tmp_path, capsys, name):
    case = make_case(tmp_path)
    other = tmp_path / "raporty"
    other.mkdir()
    assert run_cli(case, FX / "export_basic.json", "--dry-run", "--report", str(other / name)) == 2
    assert "zastrzeżona" in capsys.readouterr().err
    assert list(other.iterdir()) == []


def _case_bytes(case: Path) -> dict[str, bytes]:
    return {p.name: p.read_bytes() for p in sorted(case.iterdir()) if p.is_file()}


def test_report_refuses_foreign_temp_file_and_leaves_it_untouched(tmp_path, capsys):
    # cudzy plik tymczasowy o nazwie, której użyłby zapis raportu: odmowa (kod 2), plik nie jest usuwany ani zmieniany
    case = make_case(tmp_path)
    out = tmp_path / "out"
    out.mkdir()
    report = out / "raport.json"
    foreign = out / f".{report.name}.{os.getpid()}.tmp"
    foreign.write_bytes(b"CUDZE DANE")
    before = _case_bytes(case)
    assert run_cli(case, FX / "export_basic.json", "--dry-run", "--report", str(report)) == 2
    capsys.readouterr()
    assert foreign.read_bytes() == b"CUDZE DANE"
    assert not report.exists()
    assert _case_bytes(case) == before


def test_report_success_leaves_no_temp_file(tmp_path, capsys):
    case = make_case(tmp_path)
    out = tmp_path / "out"
    out.mkdir()
    report = out / "raport.json"
    assert run_cli(case, FX / "export_basic.json", "--dry-run", "--report", str(report)) == 0
    capsys.readouterr()
    assert json.loads(report.read_text(encoding="utf-8"))["dry_run"] is True
    assert [p.name for p in out.iterdir()] == ["raport.json"]


# ------------------------------------------------------------------ status i registered_address (opcjonalne pola)


def _with_org_fields(**fields) -> dict:
    data = load("export_basic.json")
    data["organizations"][0].update(fields)
    return data


def test_org_status_and_registered_address_pass_strict_and_map_to_node_attrs(tmp_path, capsys):
    data = _with_org_fields(
        status="w_likwidacji", status_raw="W LIKWIDACJI", registered_address="ul. Przykładowa 1, 00-001 Przykładowo"
    )
    imp = parsed(data, strict=True)
    assert not imp.rejected and imp.unknown_fields == 0
    org = next(n for n in imp.nodes if n.id == ORG)
    assert org.attrs["status"] == "w_likwidacji" and org.attrs["status_raw"] == "W LIKWIDACJI"
    assert org.attrs["registered_address"] == "ul. Przykładowa 1, 00-001 Przykładowo"
    case = make_case(tmp_path)
    assert run_cli(case, write(tmp_path, data), "--strict") == 0
    saved = case_graph(case).nodes[ORG]
    assert saved.attrs["status"] == "w_likwidacji" and saved.attrs["registered_address"].startswith("ul. Przyk")
    capsys.readouterr()


def test_org_without_new_fields_has_no_status_attrs():
    org = next(n for n in parsed(load("export_basic.json"), strict=True).nodes if n.id == ORG)
    assert not {"status", "status_raw", "registered_address"} & set(org.attrs)


def test_org_registered_address_masks_emails_like_other_text_fields():
    imp = parsed(_with_org_fields(registered_address=f"ul. Test 1, kontakt {EMAIL}", status_raw=f"opis {EMAIL}"))
    org = next(n for n in imp.nodes if n.id == ORG)
    assert EMAIL not in json.dumps(org.attrs) and "[e-mail ukryty]" in org.attrs["registered_address"]
    assert "[e-mail ukryty]" in org.attrs["status_raw"] and imp.masked_fields == 2


@pytest.mark.parametrize("bad", ["zawieszona ", "ACTIVE", "dowolny tekst", 5, ["aktywna"]])
def test_org_status_outside_the_list_is_rejected(bad):
    imp = parsed(_with_org_fields(status=bad))
    assert ORG not in {n.id for n in imp.nodes} and "niepoprawna wartość pola status" in _reasons(imp)


@pytest.mark.parametrize("key", ["status_raw", "registered_address"])
def test_org_text_fields_must_be_strings(key):
    imp = parsed(_with_org_fields(**{key: {"a": 1}}))
    assert ORG not in {n.id for n in imp.nodes} and f"organizacja: pole {key} musi być tekstem" in _reasons(imp)


def test_org_status_first_value_wins_when_merged_into_existing_graph(tmp_path):
    g, _ = import_graph(tmp_path, _with_org_fields(status="aktywna", status_raw="AKTYWNY"))
    g, _ = import_graph(
        tmp_path, _with_org_fields(status="wykreslona", status_raw="WYKREŚLONY"), graph=g, name="b.json"
    )
    assert g.nodes[ORG].attrs["status"] == "aktywna"


def test_report_temp_collision_is_refused_before_a_real_import_writes_anything(tmp_path, capsys):
    # bez --dry-run: kolizja pliku tymczasowego raportu = kod 2 PRZED importem (sprawa i dziennik bajtowo bez zmian)
    case = make_case(tmp_path)
    out = tmp_path / "out"
    out.mkdir()
    report = out / "raport.json"
    foreign = out / f".{report.name}.{os.getpid()}.tmp"
    foreign.write_bytes(b"CUDZE DANE")
    before = _case_bytes(case)
    assert run_cli(case, FX / "export_basic.json", "--report", str(report)) == 2
    capsys.readouterr()
    assert foreign.read_bytes() == b"CUDZE DANE"
    assert not report.exists()
    assert _case_bytes(case) == before


@pytest.mark.parametrize("masked", ["p***@example.test", "***@example.test", "a*b@sub.example.test"])
def test_partially_masked_email_is_hidden_completely(masked):
    data = load("export_basic.json")
    inc = data["incidents"][0]
    inc["description"] = f"Kontakt: {masked}, reszta opisu."
    imp = parsed(data)
    texts = json.dumps([n.attrs for n in imp.nodes], ensure_ascii=False)
    assert "@" not in texts and "example.test, reszta" not in texts
    assert "[e-mail ukryty]" in texts
