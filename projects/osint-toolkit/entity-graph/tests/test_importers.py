"""Importery wyników narzędzi siostrzanych: formaty (JSON/CSV/tekst), statusy, brak podnoszenia pewności, dane osobowe."""
import json
from pathlib import Path

import pytest

from entity_graph import importers
from entity_graph.importers import import_files, parse_file
from entity_graph.model import Edge, Graph, Node, RunRecord, Status
from entity_graph.normalize import EntityType as T

IMP = Path(__file__).parent / "fixtures" / "import"
FIXT = Path(__file__).parent / "fixtures"
NOW = "2026-10-03T12:00:00+00:00"


def load(name, base=IMP, **kw):
    imp, _ = parse_file(base / name, NOW, **kw)
    return imp


def graph_of(*names, base=IMP, **kw) -> tuple[Graph, list]:
    g = Graph({"purpose": "test importerów"})
    reports = import_files(g, [base / n for n in names], NOW, **kw)
    return g, reports


def types(g, t):
    return [n for n in g.nodes.values() if n.type is t]


def runs(g, prefix):
    return [r for r in g.runs if r.transform == prefix]


# ------------------------------------------------------------------ username-engine

def test_username_engine_json_accounts_keep_status_and_confidence():
    g, reports = graph_of("ue_acme.json")
    assert reports[0].format == "username-engine" and reports[0].status == "IMPORTED"
    user = g.nodes["username:acme_testowa"]
    accounts = {e.dst: e for e in g.edges.values() if e.src == user.id and e.relation == "has_account"}
    assert {k: v.confidence for k, v in accounts.items()} == {
        "url:github.com/acme_testowa": 0.95, "url:x.com/acme_testowa": 0.7, "url:slabe.example/acme_testowa": 0.4}
    gh = g.nodes["url:github.com/acme_testowa"]
    assert gh.attrs["account_status"] == "FOUND" and gh.attrs["account_confidence"] == 0.95
    assert gh.attrs["kind"] == "profile" and gh.attrs["website"] == "https://acme-testowa.example/"
    dump = json.dumps(gh.attrs, ensure_ascii=False)
    assert "nie jest przenoszone" not in dump and "Lublin" not in dump   # minimalizacja: bez treści bio i lokalizacji
    assert gh.attrs["bio_fingerprint"]                                       # tylko odcisk do porównania


def test_username_engine_not_found_and_error_rows_create_no_accounts_but_are_counted():
    g, _ = graph_of("ue_acme.json")
    assert "url:reddit.com/u/acme_testowa" not in g.nodes and "url:b.example/acme_testowa" not in g.nodes
    user = g.nodes["username:acme_testowa"]
    assert user.attrs["scan_counts"] == {"FOUND": 3, "NOT_FOUND": 1, "ERROR": 1}
    assert user.attrs["scan_error_sites"] == ["Blokada"]
    assert [r.status for r in runs(g, "import:username-engine")] == [Status.FOUND]


def test_username_engine_min_confidence_filters_weak_hits():
    g, _ = graph_of("ue_acme.json", min_confidence=0.6)
    assert "url:slabe.example/acme_testowa" not in g.nodes and "url:github.com/acme_testowa" in g.nodes


def test_username_engine_csv_same_result_without_profile_data():
    g, reports = graph_of("ue_acme.csv")
    assert reports[0].format == "username-engine"
    edges = [e for e in g.edges.values() if e.relation == "has_account"]
    assert len(edges) == 1 and edges[0].confidence == 0.95
    assert g.nodes["url:github.com/acme_testowa"].attrs.get("kind") == "profile"
    assert g.nodes["username:acme_testowa"].attrs["scan_counts"]["ERROR"] == 1


def test_username_engine_all_errors_stays_error_never_not_found():
    g, reports = graph_of("ue_all_errors.json")
    assert reports[0].status == "ERROR" and "nie jest dowód braku" in reports[0].reason
    assert [r.status for r in g.runs] == [Status.ERROR]
    assert not types(g, T.URL)


def test_username_engine_errors_mixed_with_not_found_is_unknown_not_not_found():
    g, _ = graph_of("ue_scan_only_errors.json", base=FIXT)   # ERROR + NOT_FOUND bez trafień
    assert [r.status for r in g.runs] == [Status.UNKNOWN]


def test_username_engine_unreadable_confidence_is_error_not_a_hit():
    g, _ = graph_of("ue_bad_confidence.json")
    edges = [e for e in g.edges.values() if e.relation == "has_account"]
    assert [(e.dst, e.confidence) for e in edges] == [("url:c.example/zz", 0.55)]   # tekst i NaN nie stały się 1.0
    assert g.nodes["username:zz"].attrs["scan_counts"]["ERROR"] == 2


def test_username_engine_garbage_variants_do_not_crash(tmp_path):
    for body in ('{"results": {"x": "nie lista"}}', '{"results": {"x": [1, 2, "a"]}}', '{"results": {"": []}}',
                 '{"results": {}}'):
        (tmp_path / "w.json").write_text(body, encoding="utf-8")
        imp, _ = parse_file(tmp_path / "w.json", NOW)
        assert imp.label in ("SKIPPED", "ERROR", "IMPORTED")


# ------------------------------------------------------------------ dns-audit

def test_dns_audit_domain_hosts_and_ips():
    g, reports = graph_of("dns_acme.json")
    assert reports[0].format == "dns-audit"
    assert g.nodes["domain:acme-testowa.example"].attrs["dmarc_policy"] == "reject"
    rels = {(e.relation, e.dst) for e in g.edges.values()}
    assert ("resolves_to", "ip:192.0.2.10") in rels
    assert ("nameserver", "domain:ns1.hosting-test.example") in rels
    assert ("mail_exchanger", "domain:mail.acme-testowa.example") in rels
    assert g.nodes["domain:ns1.hosting-test.example"].attrs["kind"] == "ns_host"
    assert all(e.source == "import:dns-audit:dns_acme.json" for e in g.edges.values())
    assert g.nodes["ip:192.0.2.10"].sources == ["import:dns-audit:dns_acme.json"]


def test_dns_audit_failed_queries_stay_error():
    g, reports = graph_of("dns_audit_failed.json", base=FIXT)
    assert reports[0].status == "ERROR"
    assert [r.status for r in g.runs] == [Status.ERROR] and not g.edges
    assert "domain:example.com" in g.nodes     # domena zostaje w grafie, ale bez żadnego "braku rekordów"


def test_dns_audit_empty_zone_is_not_found_and_bad_summary_is_error(tmp_path):
    g, _ = graph_of("dns_audit_empty.json", base=FIXT)
    assert [r.status for r in g.runs] == [Status.NOT_FOUND]
    (tmp_path / "d.json").write_text('[{"domain": "a.example", "summary": {}}, {"domain": "bad domain!", "summary": {}}]',
                                     encoding="utf-8")
    g2 = Graph()
    import_files(g2, [tmp_path / "d.json"], NOW)
    assert Status.ERROR in {r.status for r in g2.runs}


# ------------------------------------------------------------------ phone-check

def test_phone_json_metadata_only_no_person_links():
    g, reports = graph_of("phone.json")
    assert reports[0].format == "phone-check"
    phone = g.nodes["phone:+48603123456"]
    assert phone.attrs["phone_line_type"] == "komórkowy" and phone.attrs["phone_country_name"] == "Polska"
    assert "phone_carrier_note" in phone.attrs
    assert not g.edges and not types(g, T.PERSON)       # żadnego numer -> osoba


def test_phone_csv_semicolon_with_formula_apostrophe_and_error_row():
    g, reports = graph_of("phone.csv")
    assert reports[0].status == "IMPORTED"
    assert "phone:+48603123456" in g.nodes                       # apostrof z neutralizacji formuł usunięty
    assert g.nodes["phone:+48603123456"].attrs["phone_timezones"] == ["Europe/Warsaw"]
    assert [r.status for r in g.runs] == [Status.FOUND, Status.ERROR]   # niesparsowany numer to ERROR
    assert len(types(g, T.PHONE)) == 1


def test_phone_invalid_number_is_not_found_with_note():
    g, _ = graph_of("phone_invalid.json")
    assert [r.status for r in g.runs] == [Status.NOT_FOUND]
    assert g.nodes["phone:+4812345678"].attrs["phone_valid"] is False


def test_phone_garbage_records_are_errors(tmp_path):
    (tmp_path / "p.json").write_text('[{"input": "x", "parsed": false, "error": "zly"}, {"input": "y", "parsed": true,'
                                     ' "e164": "123"}]', encoding="utf-8")
    g = Graph()
    rep = import_files(g, [tmp_path / "p.json"], NOW)
    assert rep[0].status == "ERROR" and all(r.status is Status.ERROR for r in g.runs) and not g.nodes


# ------------------------------------------------------------------ hibp-monitor

def test_hibp_monitor_domain_and_breach_nodes():
    g, reports = graph_of("hibp_monitor.json")
    assert reports[0].format == "hibp-monitor"
    dom = g.nodes["domain:acme-testowa.example"]
    assert dom.attrs["hibp_breach_total"] == 1 and dom.attrs["hibp_baseline_run"] is True
    breach = g.nodes["organization:test breach a"]
    assert breach.attrs["kind"] == "breach" and breach.attrs["breach_name"] == "TestBreachA"
    assert breach.attrs["pwn_count"] == 1200 and "Passwords" in breach.attrs["data_classes"]
    assert any(e.relation == "breached_service" and e.dst == "domain:serwis-a.example" for e in g.edges.values())


def test_hibp_domain_search_emails_and_breaches_with_full_confidence_as_given():
    g, _ = graph_of("hibp_domain_search.json")
    assert {n.id for n in types(g, T.EMAIL)} == {"email:jan.testowy@acme-testowa.example", "email:biuro@acme-testowa.example"}
    rel = [e for e in g.edges.values() if e.relation == "appears_in_breach"]
    assert len(rel) == 2 and all(e.confidence == 1.0 for e in rel)
    assert g.nodes["domain:acme-testowa.example"].attrs["hibp_total_accounts"] == 2


def test_hibp_catalog_is_skipped_with_reason():
    g, reports = graph_of("hibp_catalog.json")
    assert reports[0].status == "SKIPPED" and "katalog" in reports[0].reason and not g.nodes


def test_hibp_api_breach_list_hostile_title_is_kept_as_data():
    g, _ = graph_of("hibp_breach_list.json")
    assert "organization:adobe" in g.nodes and g.nodes["domain:adobe.com"]
    assert any("<img" in n.value for n in types(g, T.ORGANIZATION))   # dane zostają; escapowanie robi raport HTML


# ------------------------------------------------------------------ exif-map

def test_exif_json_photo_with_gps_as_attribute_only():
    g, reports = graph_of("exif.json")
    assert reports[0].format == "exif-map"
    photo = g.nodes["photo:zdjecia/img_0001.jpg"]
    assert photo.attrs["camera"] == "TestCam X1" and photo.attrs["software"] == "TestSoft 1.0"
    assert photo.attrs["gps"] == {"lat": 52.2297, "lon": 21.0122, "altitude": 110.5, "direction": 90.0}
    assert "gps" not in g.nodes["photo:zdjecia/img_0002.jpg"].attrs
    assert not g.edges and not types(g, T.PERSON) and not types(g, T.DOMAIN)      # brak geokodowania i powiązań
    assert "address" not in json.dumps(photo.attrs)


def test_exif_unreadable_photo_stays_error_without_node():
    g, reports = graph_of("exif.json")
    assert "photo:zdjecia/img_0003.jpg" not in g.nodes
    assert [r.status for r in g.runs].count(Status.ERROR) == 1 and reports[0].errors == 1


def test_exif_csv_equivalent():
    g, reports = graph_of("exif.csv")
    assert reports[0].format == "exif-map"
    assert g.nodes["photo:zdjecia/img_0001.jpg"].attrs["gps"]["lat"] == 52.2297


def test_exif_out_of_range_gps_is_dropped(tmp_path):
    (tmp_path / "e.json").write_text(json.dumps([{"path": "a.jpg", "has_gps": True, "lat": 123.0, "lon": 21.0,
                                                  "camera": "X"}]), encoding="utf-8")
    g = Graph()
    import_files(g, [tmp_path / "e.json"], NOW)
    assert "gps" not in g.nodes["photo:a.jpg"].attrs and "poza zakresem" in g.runs[0].note


# ------------------------------------------------------------------ osint-poland

def test_krs_odpis_organization_website_and_email_but_no_persons():
    g, reports = graph_of("krs_acme.json")
    assert reports[0].format == "osint-poland"
    org = next(n for n in types(g, T.ORGANIZATION))
    assert org.attrs["nip"] == "5260000007" and org.attrs["regon"] == "12345678500000" and org.attrs["krs"] == "0000999001"
    assert org.attrs["address"] == "UL. PRÓBNA 1/2, 20-001 LUBLIN"
    site = next(e for e in g.edges.values() if e.relation == "has_website")
    assert site.dst == "domain:acme-testowa.example" and site.confidence == 0.9 and "KRS" in site.evidence
    assert "email:kontakt@acme-testowa.example" in g.nodes
    assert not types(g, T.PERSON) and "T********" not in json.dumps(g.to_dict())      # anonimizacja zachowana


def test_vat_subject_bank_accounts_normalized_and_representatives_dropped():
    g, _ = graph_of("vat_acme.json")
    org = next(iter(types(g, T.ORGANIZATION)))
    assert org.attrs["bank_accounts"] == ["PL61109010140000071219812874", "PL27114020040000300201355387"]
    assert org.attrs["vat_status"] == "Czynny" and org.attrs["regon"] == "123456785"
    assert "Testowy" not in json.dumps(g.to_dict()) and not types(g, T.PERSON)


def test_vat_not_found_is_not_found_run_without_nodes():
    g, reports = graph_of("vat_notfound.json")
    assert [r.status for r in g.runs] == [Status.NOT_FOUND] and not g.nodes and reports[0].status == "IMPORTED"


def test_snapshot_teczka_org_parcel_and_check_statuses_preserved():
    g, _ = graph_of("teczka_acme.json")
    org = g.nodes["organization:acme testowa spolka akcyjna"]
    assert org.attrs["nip"] == "5260000007" and org.attrs["legal_status"].startswith("Podmiot czynny")
    assert org.attrs["krs"] == "0000999001"                       # z zapytania typu krs
    parcel_edge = next(e for e in g.edges.values() if e.relation == "related_parcel")
    assert parcel_edge.dst == "parcel:141201_1.0001.6509" and parcel_edge.confidence == 0.5
    assert "nie dowód własności" in parcel_edge.evidence
    by = {r.node_id.split("#")[1]: r.status for r in g.runs}
    assert by == {"krs": Status.FOUND, "vat": Status.ERROR, "krs_s": Status.UNKNOWN}   # ERROR zostaje ERROR


def test_uldk_text_parcel_without_owner_and_no_result_file():
    g, _ = graph_of("uldk_parcel.txt")
    parcel = g.nodes["parcel:141201_1.0001.6509"]
    assert parcel.attrs["county"] == "powiat miński" and parcel.attrs["parcel_number"] == "6509"
    assert len(parcel.attrs["extent_wgs84"]) == 4 and not g.edges
    g2, reports = graph_of("uldk_none.txt")
    assert [r.status for r in g2.runs] == [Status.NOT_FOUND] and not g2.nodes and reports[0].format == "osint-poland"


def test_real_osint_poland_fixtures_import(tmp_path):
    base = Path(__file__).parents[2] / "osint-poland" / "tests" / "fixtures"
    if not (base / "krs_0000023302.json").exists():
        pytest.skip("brak osint-poland obok")
    g = Graph()
    reps = import_files(g, [base / "krs_0000023302.json", base / "vat_6920000013.json", base / "uldk_id_z_ukosnikiem.txt"],
                        NOW)
    assert [r.status for r in reps] == ["IMPORTED"] * 3
    orgs = [n for n in types(g, T.ORGANIZATION)]
    assert len(orgs) == 1 and len(orgs[0].attrs["bank_accounts"]) > 100 and orgs[0].attrs["nip"] == "6920000013"
    assert len(orgs[0].sources) == 2
    assert "parcel:146510_8.0502.1/3" in g.nodes


# ------------------------------------------------------------------ entity-graph (własny graf)

def _prior_graph(path: Path) -> Graph:
    g = Graph({"purpose": "poprzednie badanie", "started": "2026-09-01"})
    a = g.add_node(Node.make(T.DOMAIN, "acme-testowa.example", {"x": 1}, "domain_rdap"), NOW)
    b = g.add_node(Node.make(T.IP, "192.0.2.10", {}, "dns_audit"), NOW)
    g.add_edge(Edge(a.id, b.id, "resolves_to", "dns_audit", 0.5, "A", NOW))
    g.runs.append(RunRecord("ip_rdap", b.id, Status.ERROR, NOW, error="timeout"))
    g.save(path)
    return g


def test_entity_graph_json_merge_keeps_runs_status_and_does_not_inflate(tmp_path):
    _prior_graph(tmp_path / "graph.json")
    g = Graph()
    g.add_node(Node.make(T.DOMAIN, "ACME-testowa.example", {"y": 2}, "seed"), NOW)
    g.add_node(Node.make(T.IP, "192.0.2.10", {}, "seed"), NOW)
    g.add_edge(Edge("domain:acme-testowa.example", "ip:192.0.2.10", "resolves_to", "dns_audit", 0.4, "inny dowód", NOW))
    reps = import_files(g, [tmp_path / "graph.json"], NOW)
    assert reps[0].format == "entity-graph" and reps[0].status == "IMPORTED"
    dom = g.nodes["domain:acme-testowa.example"]
    assert dom.attrs == {"y": 2, "x": 1} and "domain_rdap" in dom.sources
    assert "import:entity-graph:graph.json" in dom.sources
    edge = g.edges[("domain:acme-testowa.example", "ip:192.0.2.10", "resolves_to", "dns_audit")]
    assert edge.confidence == 0.5 and "A" in edge.evidence and "inny dowód" in edge.evidence     # max, nie suma
    assert any(r.status is Status.ERROR and r.transform == "ip_rdap" for r in g.runs)
    assert g.meta["merged_graphs"][0]["purpose"] == "poprzednie badanie"


def test_entity_graph_json_invalid_graph_is_error(tmp_path):
    (tmp_path / "g.json").write_text(json.dumps({"schema": 1, "nodes": [{"id": "x"}], "edges": []}), encoding="utf-8")
    g = Graph()
    reps = import_files(g, [tmp_path / "g.json"], NOW)
    assert reps[0].status == "ERROR" and not g.nodes


# ------------------------------------------------------------------ rozpoznawanie, pliki dziwne, katalogi

@pytest.mark.parametrize("name,status,reason", [
    ("empty.json", "SKIPPED", "pusty"), ("broken.json", "ERROR", "uszkodzony JSON"),
    ("unknown.json", "SKIPPED", "nierozpoznany format JSON"), ("notatki.txt", "SKIPPED", "nierozpoznany"),
    ("raport.html", "SKIPPED", "nierozpoznany"), ("obraz.bin", "SKIPPED", "binarny")])
def test_unknown_empty_malformed_and_binary_files_are_reported_never_crash(name, status, reason):
    g, reports = graph_of(name)
    assert reports[0].status == status and reason in reports[0].reason
    assert not g.nodes
    assert g.runs and g.runs[0].status is (Status.ERROR if status == "ERROR" else Status.UNKNOWN)


def test_format_detected_by_content_not_by_name(tmp_path):
    (tmp_path / "wynik.dat").write_text((IMP / "ue_acme.json").read_text(encoding="utf-8"), encoding="utf-8")
    (tmp_path / "dane.txt").write_text((IMP / "phone.json").read_text(encoding="utf-8"), encoding="utf-8")
    (tmp_path / "x.log").write_text((IMP / "uldk_parcel.txt").read_text(encoding="utf-8"), encoding="utf-8")
    g = Graph()
    reps = import_files(g, [tmp_path], NOW)
    assert sorted(r.format for r in reps) == ["osint-poland", "phone-check", "username-engine"]


def test_json_with_non_json_suffix_that_is_not_json_is_skipped_not_error(tmp_path):
    (tmp_path / "audit.jsonl").write_text('{"a": 1}\n{"b": 2}\n', encoding="utf-8")
    reps = import_files(Graph(), [tmp_path / "audit.jsonl"], NOW)
    assert reps[0].status == "SKIPPED"


def test_missing_path_is_error_and_directory_is_expanded_skipping_hidden(tmp_path):
    (tmp_path / ".ukryty").mkdir()
    (tmp_path / ".ukryty" / "x.json").write_text((IMP / "ue_acme.json").read_text(encoding="utf-8"), encoding="utf-8")
    (tmp_path / "sub").mkdir()
    (tmp_path / "sub" / "dns.json").write_text((IMP / "dns_acme.json").read_text(encoding="utf-8"), encoding="utf-8")
    g = Graph()
    reps = import_files(g, [tmp_path, tmp_path / "nie-ma.json"], NOW)
    assert [(r.format, r.status) for r in reps if r.format] == [("dns-audit", "IMPORTED")]
    assert any(r.status == "ERROR" and "nie istnieje" in r.reason for r in reps)
    assert g.meta["imports"] and len(reps) == 2


def test_oversized_file_is_skipped(monkeypatch, tmp_path):
    monkeypatch.setattr(importers, "MAX_FILE_BYTES", 10)
    (tmp_path / "big.json").write_text('{"results": {"a": []}}', encoding="utf-8")
    assert import_files(Graph(), [tmp_path / "big.json"], NOW)[0].status == "SKIPPED"


def test_unexpected_parser_exception_becomes_error_not_crash(monkeypatch):
    def boom(data, ctx):
        raise RuntimeError("niespodzianka")
    monkeypatch.setattr(importers.username_engine, "parse", boom)
    g, reports = graph_of("ue_acme.json")
    assert reports[0].status == "ERROR" and "RuntimeError" in reports[0].reason and g.runs[0].status is Status.ERROR


def test_import_makes_no_network_calls(monkeypatch):
    import socket

    def no_net(*a, **k):
        raise AssertionError("importer nie może łączyć się z siecią")
    monkeypatch.setattr(socket, "socket", no_net)
    monkeypatch.setattr(socket, "create_connection", no_net)
    g = Graph()
    reps = import_files(g, [IMP], NOW)
    assert any(r.status == "IMPORTED" for r in reps) and g.nodes


def test_importing_same_file_twice_does_not_inflate_confidence_or_duplicate():
    g = Graph()
    import_files(g, [IMP / "ue_acme.json"], NOW)
    before = {k: e.confidence for k, e in g.edges.items()}
    import_files(g, [IMP / "ue_acme.json"], NOW)
    assert {k: e.confidence for k, e in g.edges.items()} == before and len(g.nodes) == 4
    assert all(e.confidence <= 0.95 for e in g.edges.values())
