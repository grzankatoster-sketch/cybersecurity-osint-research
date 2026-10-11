"""Pakiet R2 w sprawie: twierdzenia o relacjach, kontekst numeru, kandydaci profili, widok sprawy.
Wyłącznie dane syntetyczne i atrapy podprocesów: zero zapytań do sieci."""
from __future__ import annotations

import json
import re
import subprocess
import xml.etree.ElementTree as ET
from pathlib import Path

import pytest

from conftest import FIXTURES, writes_json_to_flag
from entity_graph import cli, kandydaci, relacje, siblings, sprawa, teczka, telefon
from entity_graph.correlate import correlate
from entity_graph.expand import Scope
from entity_graph.export import render_html, to_graphml
from entity_graph.guardrails import AuditLog, verify_audit
from entity_graph.kropki import render_svg
from entity_graph.model import Edge, Graph, Node
from entity_graph.normalize import EntityType as T

PURPOSE = "due diligence kontrahenta na zlecenie klienta, sprawa 2026/41"
JAN, ANNA, PIOTR = "Jan Kowalski", "Anna Kowalska", "Piotr Nowak"
EVIDENCE = "akt urodzenia z dokumentów klienta wskazuje matkę"
DECISION = "sprawdzono oryginał aktu u klienta, dane zgodne"
SRC = "https://example.org/rejestr/wpis-17"
PHONE_ROW = json.loads((FIXTURES / "phone_check.json").read_text(encoding="utf-8"))[0]


def _case(tmp_path: Path, people=(JAN, ANNA, PIOTR), purpose=PURPOSE) -> Path:
    g = Graph({"purpose": purpose})
    for p in people:
        g.add_node(Node.make(T.PERSON, p, source="seed"))
    case = tmp_path / "sprawa"
    case.mkdir()
    g.save(case / "graph.json")
    AuditLog(case / "audit.jsonl", "ala").start(purpose, [], {})
    (case / "dokumenty").mkdir()
    (case / "dokumenty" / "akt.txt").write_text("treść dokumentu, która nie może trafić do grafu", encoding="utf-8")
    return case


def _events(case: Path) -> list[dict]:
    return [json.loads(x) for x in (case / "audit.jsonl").read_text(encoding="utf-8").splitlines() if x.strip()]


def _relacja(case: Path, *extra: str, typ="rodzic", a=ANNA, b=JAN, zrodlo=SRC, dowod=EVIDENCE) -> int:
    return cli.main(["relacja", str(case), "--person", a, "--typ", typ, "--druga-osoba", b, "--zrodlo", zrodlo,
                     "--dowod", dowod, "--operator", "ala", *extra])


def _graph(case: Path) -> Graph:
    return Graph.load(case / "graph.json")


def _person_edges(g: Graph) -> list[Edge]:
    return [e for e in g.edges.values() if g.nodes[e.src].type is T.PERSON and g.nodes[e.dst].type is T.PERSON]


# --- 1. twierdzenie wymaga celu, źródła i dowodu ---------------------------------------------------------

@pytest.mark.parametrize("zrodlo", ["", "brak", "javascript:alert(1)", "ftp://example.org/x", "dokument:../poza.txt",
                                    "dokument:C:/Windows/win.ini", "dokument:nie-ma.txt", "dokument:graph.json",
                                    "https://user:haslo@example.org/x", "dokument:"])
def test_claim_rejected_without_identifiable_source(tmp_path, zrodlo):
    case = _case(tmp_path)
    (tmp_path / "poza.txt").write_text("x", encoding="utf-8")
    assert _relacja(case, zrodlo=zrodlo) == 2
    assert not relacje.claims(_graph(case))
    assert not [e for e in _events(case) if e["event"] == "relation_claim"]


@pytest.mark.parametrize("dowod", ["", "ok", "tak tak", "   "])
def test_claim_rejected_without_evidence(tmp_path, dowod):
    case = _case(tmp_path)
    assert _relacja(case, dowod=dowod) == 2
    assert not relacje.claims(_graph(case))


def test_claim_rejected_without_case_purpose(tmp_path):
    case = _case(tmp_path)
    (case / "audit.jsonl").write_text("", encoding="utf-8")         # brak celu w dzienniku
    assert _relacja(case) == 2
    g = Graph.load(case / "graph.json")
    a, b = g.nodes[Node.make(T.PERSON, ANNA).id], g.nodes[Node.make(T.PERSON, JAN).id]
    with pytest.raises(ValueError, match="celu"):
        relacje.add_claim(g, a, b, "rodzic", {"kind": "url", "ref": SRC}, EVIDENCE, purpose="")
    with pytest.raises(ValueError, match="źródła"):
        relacje.add_claim(g, a, b, "rodzic", {}, EVIDENCE, PURPOSE)
    with pytest.raises(ValueError):
        relacje.add_claim(g, a, b, "kuzyn", {"kind": "url", "ref": SRC}, EVIDENCE, PURPOSE)
    with pytest.raises(ValueError):
        relacje.add_claim(g, a, a, "rodzic", {"kind": "url", "ref": SRC}, EVIDENCE, PURPOSE)


def test_claim_person_must_exist_or_be_added_explicitly(tmp_path):
    case = _case(tmp_path, people=(JAN,))
    assert _relacja(case) == 2                                      # Anny nie ma w grafie
    assert _relacja(case, "--dodaj") == 0
    g = _graph(case)
    assert g.nodes[Node.make(T.PERSON, ANNA).id].sources == ["operator"]


# --- 2. nowe twierdzenie: oczekuje, pewność 0; dokument jako referencja bez treści ----------------------

def test_new_claim_is_pending_with_zero_confidence_and_audit(tmp_path):
    case = _case(tmp_path)
    assert _relacja(case, "--fragment", "s. 2, rubryka matka") == 0
    assert _relacja(case, typ="rodzenstwo", a=JAN, b=PIOTR, zrodlo="dokument:dokumenty/akt.txt") == 0
    g = _graph(case)
    claims = relacje.claims(g)
    assert [c["status"] for c in claims] == [relacje.PENDING] * 2
    assert all(c["confidence"] == 0.0 and c["purpose"] == PURPOSE and c["created_at"] for c in claims)
    edges = _person_edges(g)
    assert {e.relation for e in edges} == {"claim_parent_of", "claim_sibling"}
    assert all(e.confidence == 0.0 and e.source.startswith("relacje:") for e in edges)
    doc = claims[1]["sources"][0]["source"]
    assert doc["kind"] == "document" and doc["ref"] == "dokumenty/akt.txt" and len(doc["sha256"]) == 64
    raw = (case / "graph.json").read_text(encoding="utf-8") + (case / "audit.jsonl").read_text(encoding="utf-8")
    assert "nie może trafić do grafu" not in raw                    # treść dokumentu nie jest kopiowana
    phases = [(e["event"], e.get("phase")) for e in _events(case) if e["event"] == "relation_claim"]
    assert phases == [("relation_claim", "przed"), ("relation_claim", "po")] * 2
    assert verify_audit(case / "audit.jsonl")[0]


def test_direction_kept_and_symmetric_claims_not_doubled(tmp_path):
    case = _case(tmp_path)
    assert _relacja(case, typ="dziecko", a=JAN, b=ANNA) == 0        # Jan dzieckiem Anny = Anna rodzicem Jana
    assert _relacja(case, typ="rodzic", a=ANNA, b=JAN) == 0         # to samo twierdzenie: bez duplikatu
    assert _relacja(case, typ="partner", a=JAN, b=PIOTR) == 0
    assert _relacja(case, typ="partner", a=PIOTR, b=JAN) == 0       # odwrotna kolejność: ta sama krawędź
    g = _graph(case)
    claims = relacje.claims(g)
    assert len(claims) == 2 and len(_person_edges(g)) == 2
    parent = next(c for c in claims if c["kind"] == "parent_of")
    assert g.nodes[parent["src"]].value == ANNA and g.nodes[parent["dst"]].value == JAN
    assert _relacja(case, typ="inna", a=JAN, b=PIOTR) == 2           # inna bez opisu
    assert _relacja(case, "--opis", "opiekun prawny", typ="inna", a=JAN, b=PIOTR) == 0
    assert relacje.contradictions(_graph(case))                     # partner + inna dla tej samej pary: do wyjaśnienia


# --- 3. to samo nazwisko nie tworzy relacji ------------------------------------------------------------

def test_same_surname_never_creates_relation(tmp_path, make_ctx):
    out = tmp_path / "run"
    ctx = make_ctx()
    assert cli.main(["run", "--purpose", PURPOSE, "--person", JAN, "--person", "Maria Kowalska", "--offline",
                     "--no-evidence", "--out", str(out)], ctx=ctx) == 0
    g = Graph.load(out / "graph.json")
    correlate(g)
    for p in g.nodes_of_type(T.PERSON):
        teczka.propagate(g, p)
    assert not _person_edges(g) and not relacje.claims(g)


# --- 4. decyzje idempotentne, ślad audytowy, odrzucenie usuwa dane pochodne -----------------------------

def test_confirm_reject_and_change_are_idempotent_and_audited(tmp_path):
    case = _case(tmp_path)
    assert _relacja(case) == 0
    cid = relacje.claims(_graph(case))[0]["id"]

    def decide(*extra, dowod=DECISION):
        return cli.main(["relacja-potwierdz", str(case), "--id", cid, "--dowod", dowod, "--operator", "ala", *extra])

    assert decide(dowod=EVIDENCE) == 2                              # potwierdzenie wymaga OSOBNEGO uzasadnienia
    assert decide() == 0
    g = _graph(case)
    assert {(e.relation, e.confidence) for e in _person_edges(g)} == {("confirmed_parent_of", 0.9)}
    before = (case / "graph.json").read_bytes()
    assert decide() == 0                                            # to samo drugi raz: bez zmian
    assert (case / "graph.json").read_bytes() == before
    assert decide("--odrzuc", dowod="oryginał aktu wskazuje inną osobę jako matkę") == 0
    g = _graph(case)
    assert {(e.relation, e.confidence) for e in _person_edges(g)} == {("rejected_parent_of", 0.0)}
    assert decide("--odrzuc", dowod="oryginał aktu wskazuje inną osobę jako matkę") == 0
    assert decide() == 0                                            # zmiana decyzji z powrotem
    g = _graph(case)
    claim = relacje.claims(g)[0]
    assert claim["status"] == relacje.CONFIRMED and len(claim["history"]) == 3
    assert len(_person_edges(g)) == 1
    po = [e["result"] for e in _events(case) if e["event"] == "relation_decision" and e.get("phase") == "po"]
    assert po == ["błąd", "zmieniono", "bez zmian", "zmieniono", "bez zmian", "zmieniono"]
    assert verify_audit(case / "audit.jsonl")[0]
    assert "#7b3fa0" in (case / "kropki.svg").read_text(encoding="utf-8")


def test_audit_failure_blocks_change(tmp_path, monkeypatch):
    case = _case(tmp_path)
    before = (case / "graph.json").read_bytes()

    def broken(self, event, **fields):
        raise OSError("dysk tylko do odczytu")

    monkeypatch.setattr(AuditLog, "write", broken)
    assert _relacja(case) == 2
    assert (case / "graph.json").read_bytes() == before


def test_final_audit_failure_does_not_persist_change(tmp_path, monkeypatch):
    case = _case(tmp_path)
    before = (case / "graph.json").read_bytes()
    original = AuditLog.write
    calls = 0

    def broken_after_action(self, event, **fields):
        nonlocal calls
        calls += 1
        if calls == 2:
            raise OSError("brak miejsca na wpis końcowy")
        return original(self, event, **fields)

    monkeypatch.setattr(AuditLog, "write", broken_after_action)
    assert _relacja(case) == 2
    assert calls == 2
    assert (case / "graph.json").read_bytes() == before


# --- 5. dodanie twierdzenia nie uruchamia niczego -------------------------------------------------------

def test_claim_does_not_start_any_process(tmp_path, monkeypatch):
    case = _case(tmp_path)

    def forbidden(*a, **k):
        raise AssertionError("uruchomiono podproces")

    monkeypatch.setattr(subprocess, "run", forbidden)
    monkeypatch.setattr(subprocess, "Popen", forbidden)
    monkeypatch.setattr(siblings, "default_runner", forbidden)
    assert _relacja(case) == 0
    cid = relacje.claims(_graph(case))[0]["id"]
    assert cli.main(["relacja-potwierdz", str(case), "--id", cid, "--dowod", DECISION]) == 0
    assert not [e for e in _events(case) if e["event"] == "transform"]


# --- 6-8. kontekst numeru ---------------------------------------------------------------------------------

def test_phone_import_twice_does_not_duplicate(tmp_path, make_ctx):
    case = _case(tmp_path)
    plik = str(FIXTURES / "phone_check.json")
    assert cli.main(["telefon", str(case), "--plik", plik]) == 0
    first = _graph(case)
    assert cli.main(["telefon", str(case), "--plik", plik]) == 0
    ctx = make_ctx(handlers={"phone_check": writes_json_to_flag(json.dumps([PHONE_ROW]))})
    assert cli.main(["telefon", str(case), "--numer", "603 123 456"], ctx=ctx) == 0
    g = _graph(case)
    phones = g.nodes_of_type(T.PHONE)
    assert len(phones) == 1 and len(phones[0].attrs[telefon.LOG]) == 1
    assert phones[0].to_dict() == first.nodes_of_type(T.PHONE)[0].to_dict()
    assert [e.get("result") for e in _events(case) if e["event"] == "phone_context" and e.get("phase") == "po"] == \
        ["zmieniono", "bez zmian", "bez zmian"]


FORBIDDEN_OUTPUT = re.compile(r"lokalizacja telefonu|current_location|live_location|latitude|longitude|\bgps\b|"
                              r"pozycja telefonu|znaleziono osob|ustalono rodzin", re.IGNORECASE)


def test_mobile_number_has_plan_country_but_no_city_or_position(tmp_path):
    case = _case(tmp_path)
    row = dict(PHONE_ROW, geo_description="Warszawa")          # opis miasta z biblioteki dla numeru komórkowego
    (case / "pc.json").write_text(json.dumps([row]), encoding="utf-8")
    assert cli.main(["telefon", str(case), "--plik", str(case / "pc.json")]) == 0
    g = _graph(case)
    phone = g.nodes_of_type(T.PHONE)[0]
    assert phone.attrs["phone_plan_region"] == "Polska" and "komórkowy" in phone.attrs["phone_plan_region_note"]
    summary = json.dumps(sprawa.summary(g), ensure_ascii=False)
    outputs = [summary, (case / "report.html").read_text(encoding="utf-8"), (case / "graph.json").read_text(encoding="utf-8"),
               (case / "graph.graphml").read_text(encoding="utf-8"), (case / "kropki.svg").read_text(encoding="utf-8")]
    for text in outputs:
        assert "Warszawa" not in text and not FORBIDDEN_OUTPUT.search(text)
    assert "region planu numeracyjnego" in outputs[1] and "numeracja.uke.gov.pl" in outputs[1]


def test_fixed_line_plan_region_is_not_device_position():
    row = dict(PHONE_ROW, line_type="stacjonarny", line_type_code="FIXED_LINE", geo_description="Kraków")
    attrs = telefon.phone_attrs(row)
    assert attrs["phone_plan_region"] == "Kraków" and "nie jest bieżące miejsce" in attrs["phone_plan_region_note"]


def test_plan_and_manual_carrier_stay_two_observations(tmp_path):
    case = _case(tmp_path)
    assert cli.main(["telefon", str(case), "--plik", str(FIXTURES / "phone_check.json")]) == 0
    manual = ["telefon", str(case), "--numer", "+48603123456", "--operator-aktualny", "Play",
              "--zrodlo", "https://numeracja.uke.gov.pl/", "--data", "2026-10-01"]
    assert cli.main(manual) == 0 and cli.main(manual) == 0          # drugi raz: bez duplikatu
    assert cli.main(["telefon", str(case), "--numer", "+48603123456", "--operator-aktualny", "Play",
                     "--zrodlo", "https://numeracja.uke.gov.pl/", "--data", "2999-01-01"]) == 2
    g = _graph(case)
    phone = g.nodes_of_type(T.PHONE)[0]
    assert phone.attrs["phone_carrier"] == "Plus" and phone.attrs["phone_carrier_manual"] == "Play"
    assert not phone.conflicts()
    assert [x["kind"] for x in phone.attrs[telefon.LOG]] == ["plan", "manual"]
    # inna ręczna weryfikacja z innym wynikiem: konflikt, nie wybór
    assert cli.main(["telefon", str(case), "--numer", "+48603123456", "--operator-aktualny", "Orange",
                     "--zrodlo", "dokument:dokumenty/akt.txt", "--data", "2026-10-02"]) == 0
    phone = _graph(case).nodes_of_type(T.PHONE)[0]
    assert "phone_carrier_manual" not in phone.attrs and phone.attrs["phone_carrier"] == "Plus"
    assert any(c.startswith("phone_carrier_manual") for c in phone.conflicts())
    assert "Konflikt obserwacji" in (case / "report.html").read_text(encoding="utf-8")


def test_plan_results_from_two_sources_conflict(tmp_path):
    g = Graph()
    telefon.attach_plan(g, PHONE_ROW, "2026-10-01T10:00:00+00:00")
    node, changed = telefon.attach_plan(g, dict(PHONE_ROW, carrier="T-Mobile"), "2026-10-02T10:00:00+00:00")
    assert changed and "phone_carrier" not in node.attrs and node.conflicts()
    assert Graph.from_dict(json.loads(json.dumps(g.to_dict()))).nodes[node.id].conflicts() == node.conflicts()


def test_conflicting_phone_validity_is_unknown_in_summary():
    g = Graph()
    telefon.attach_plan(g, PHONE_ROW, "2026-10-01T10:00:00+00:00")
    node, changed = telefon.attach_plan(g, dict(PHONE_ROW, valid=False), "2026-10-02T10:00:00+00:00")
    assert changed and "phone_valid" not in node.attrs
    assert sprawa.summary(g)["phones"][0]["source_status"]["status"] == "UNKNOWN"


def test_old_graph_format_still_loads():
    old = {"schema": 1, "meta": {}, "runs": [], "edges": [], "nodes": [
        {"id": "phone:+48603123456", "type": "phone", "value": "+48603123456", "sources": ["seed"], "first_seen": "",
         "attrs": {"phone_valid": True, "phone_line_type": "komórkowy", "phone_country_name": "Polska",
                   "phone_geo_description": "Polska", "phone_carrier": "Plus"}}]}
    g = Graph.from_dict(old)
    ctx = telefon.context(g.nodes["phone:+48603123456"])
    assert {f["key"]: f["value"] for f in ctx["fields"]}["phone_plan_region"] == "Polska"
    model1 = {**old, "observation_model": 1, "nodes": [{"id": "url:a.example/x", "type": "url", "value": "https://a.example/x",
              "attrs": {}, "sources": ["s1"], "observations": {"website": [{"value": "https://w.example", "sources": ["s1"]}]}}]}
    assert Graph.from_dict(model1).nodes["url:a.example/x"].attrs["website"] == "https://w.example"


# --- 9-11. kandydaci profili --------------------------------------------------------------------------------

def _ue_payload(name: str, rows: list[dict]) -> str:
    return json.dumps({"query": name, "results": {name: rows}})


def _ue_handler(world: dict):
    """Atrapa username-engine: {nazwa: lista wierszy | kod wyjścia}."""
    calls = []

    def handler(cmd):
        name = cmd[-1]
        calls.append(name)
        rows = world.get(name, [])
        if isinstance(rows, int):
            return rows, "", "awaria skanu"
        target = Path(cmd[cmd.index("--results-dir") + 1]) / "scan-test" / "scan.json"
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(_ue_payload(name, rows), encoding="utf-8")
        return 0, "", ""
    handler.calls = calls
    return handler


def _found(url, site, conf=0.9, **profile):
    return {"site": site, "url": url, "status": "FOUND", "confidence": conf, "reason": "tekst profilu",
            "profile": profile}


def _kandydaci(case, ctx, *extra):
    return cli.main(["kandydaci", str(case), "--operator", "ala", *extra], ctx=ctx)


def test_round_keeps_statuses_and_candidates_stay_hypotheses(tmp_path, make_ctx):
    case = _case(tmp_path)
    world = {
        "jan.kowalski": [_found("https://code.example/jan.kowalski", "Code", name=JAN)],
        "jankowalski": [{"site": "R", "url": "https://r.example/jankowalski", "status": "NOT_FOUND", "confidence": 0}],
        "jan_kowalski": [{"site": "B", "url": "https://b.example/x", "status": "ERROR", "confidence": 0, "reason": "429"}],
        "jan-kowalski": 3,
    }
    handler = _ue_handler(world)
    ctx = make_ctx(handlers={"username_engine": handler})
    assert _kandydaci(case, ctx, "--person", JAN, "--max-nazw", "4", "--max-queries", "4", "--max-cost", "20") == 1
    g = _graph(case)
    rnd = kandydaci.rounds(g)[-1]
    assert sorted(q["status"] for q in rnd["queries"]) == ["ERROR", "FOUND", "NOT_FOUND", "UNKNOWN"]
    assert all("interpretation" in q for q in rnd["queries"] if q["status"] in ("ERROR", "UNKNOWN"))
    assert not [e for e in g.edges.values() if e.relation in (teczka.CONFIRMED, "via_confirmed_profile")]
    matches = [e for e in g.edges.values() if e.relation == kandydaci.RELATION]
    assert len(matches) == 1 and matches[0].confidence == 0.0
    person = g.nodes[Node.make(T.PERSON, JAN).id]
    cands = teczka.candidates(g, person)
    assert [c.node.value for c in cands] == ["https://code.example/jan.kowalski"] and cands[0].decision == ""
    summary = sprawa.summary(g)
    cand = summary["candidates"][0]
    assert cand["decision"] == "wymaga potwierdzenia" and cand["confidence"] == 0.9
    assert cand["source_status"].startswith("FOUND")
    username = g.nodes[Node.make(T.USERNAME, "jan.kowalski").id]
    assert any(link["engine"] == "Facebook" for link in username.attrs["manual_review_links"])
    po = [e for e in _events(case) if e["event"] == "profile_round"]
    assert [e["phase"] for e in po] == ["przed", "po"]


def test_name_or_username_match_alone_is_not_confirmation(tmp_path, make_ctx):
    case = _case(tmp_path)
    handler = _ue_handler({"jan.kowalski": [_found("https://code.example/jan.kowalski", "Code", name=JAN)]})
    ctx = make_ctx(handlers={"username_engine": handler})
    assert _kandydaci(case, ctx, "--person", JAN, "--nazwy", "jan.kowalski") == 0
    g = _graph(case)
    row = kandydaci.rounds(g)[-1]["candidates"][0]
    assert row["decision"] == "przeglad" and row["copy_only"]       # sama zgodna nazwa: tylko do przeglądu
    assert not kandydaci.rounds(g)[-1]["proposals"]
    assert not teczka.dossier(g, g.nodes[Node.make(T.PERSON, JAN).id])["confirmed"]
    assert cli.main(["potwierdz", str(case), "--person", JAN, "--profil", "https://code.example/jan.kowalski",
                     "--dowod", "ok"]) == 2                          # bez dowodu nie ma potwierdzenia
    assert len(handler.calls) == 1


def test_further_round_needs_explicit_action_and_respects_limits(tmp_path, make_ctx):
    case = _case(tmp_path)
    g = _graph(case)
    person = g.nodes[Node.make(T.PERSON, JAN).id]
    anchor = g.add_node(Node.make(T.URL, "https://code.example/jan", {"kind": "profile", "site": "Code",
                                                                       "links": ["https://hub.example/jkow"]}, "seed"))
    u = g.add_node(Node.make(T.USERNAME, "jan", source="seed"))
    g.add_edge(Edge(u.id, anchor.id, "has_account", "username_scan", 0.9, "trafienie"))
    teczka.decide(g, person, anchor, teczka.CONFIRMED, "zdjęcie i firma zgodne z KRS spółki")
    g.save(case / "graph.json")
    world = {"jan.kowalski": [_found("https://hub.example/jkow", "Hub", name=JAN, links=["https://code.example/jan",
                                                                                         "https://other.example/jk7"])]}
    handler = _ue_handler(world)
    ctx = make_ctx(handlers={"username_engine": handler})
    # limit zapytań: 3 nazwy, 1 zapytanie
    assert _kandydaci(case, ctx, "--person", JAN, "--nazwy", "jankowalski,jan.kowalski,jan_kowalski",
                      "--max-queries", "1") == 0
    rnd = kandydaci.rounds(_graph(case))[-1]
    assert len(rnd["queries"]) == 1 and len(rnd["skipped"]) == 2 and "limit zapytań" in rnd["skipped"][0]["why"]
    assert rnd["candidates"][0]["decision"] == "rozwin"
    assert [p["identifier"] for p in rnd["proposals"]] == ["jk7"]
    assert handler.calls == ["jan.kowalski"]                          # propozycja NIE została uruchomiona
    # limit kosztu: zapytanie kosztuje 5
    assert _kandydaci(case, ctx, "--username", "jk7", "--max-cost", "4") == 0
    assert handler.calls == ["jan.kowalski"] and "limit kosztu" in kandydaci.rounds(_graph(case))[-1]["stop_reason"]
    # jawna kolejna runda z propozycji
    assert _kandydaci(case, ctx, "--username", "jk7") == 0
    assert handler.calls == ["jan.kowalski", "jk7"]
    # limit rund sprawy
    assert _kandydaci(case, ctx, "--username", "jk7", "--max-rounds", "3") == 2
    assert _kandydaci(case, ctx, "--username", "nieznana") == 2      # spoza sprawy i propozycji
    for bad in (["--max-queries", "11"], ["--max-cost", "51"], ["--max-seconds", "1801"], ["--max-nazw", "13"]):
        assert _kandydaci(case, ctx, "--username", "jk7", "--max-rounds", "9", *bad) == 2
    assert handler.calls == ["jan.kowalski", "jk7"]


def test_round_time_limit(tmp_path, make_ctx):
    g = Graph()
    person = g.add_node(Node.make(T.PERSON, JAN))
    names = kandydaci.plan_names(g, person, None, 2)
    ticks = iter([0.0, 0.0, 5.0, 5.0, 5.0, 5.0])
    handler = _ue_handler({})
    ctx = make_ctx(handlers={"username_engine": handler})
    audit = AuditLog(tmp_path / "a.jsonl", "t")
    scope = Scope(adapters=("username_scan",), max_rounds=1, max_queries=5, max_seconds=1.0, max_cost=50)
    rep = kandydaci.run_round(g, person, names, ctx, audit, scope, clock=lambda: next(ticks))
    assert len(handler.calls) == 1 and "limit czasu" in rep["stop_reason"]
    with pytest.raises(ValueError):
        kandydaci.run_round(g, person, names, ctx, audit, Scope(auto_continue=True, max_rounds=2))


# --- 13. wrogie dane w raporcie, GraphML i SVG ------------------------------------------------------------

def test_hostile_text_is_escaped_in_all_exports(tmp_path):
    evil = '<script>alert(1)</script> Kowalski'
    case = _case(tmp_path, people=(evil, ANNA))
    url = 'https://example.org/?q="><script>alert(2)</script>'
    assert _relacja(case, a=evil, b=ANNA, typ="rodzic", zrodlo=url,
                    dowod='dowód "><img src=x onerror=alert(3)> z rejestru') == 0
    html = (case / "report.html").read_text(encoding="utf-8")
    assert "<script>" not in html and "<img src=x" not in html and "&lt;script&gt;" in html
    root = ET.fromstring((case / "graph.graphml").read_text(encoding="utf-8").encode("utf-8"))
    assert not [el for el in root.iter() if el.tag.endswith("script") or el.tag.endswith("img")]
    svg = (case / "kropki.svg").read_text(encoding="utf-8")
    ET.fromstring(svg.encode("utf-8"))
    assert "<script" not in svg and "<img" not in svg
    summary = json.dumps(sprawa.summary(_graph(case)), ensure_ascii=False)
    assert "alert(3)" in summary                                     # dane są w JSON; panel wstawia je jako tekst


# --- 14. kod produkcyjny bez niedozwolonych mechanizmów ---------------------------------------------------

FORBIDDEN_CODE = re.compile(r"current_location|live_location|latitude|longitude|\bgps\b|imsi|\bhlr\b|roaming|"
                            r"sim.?swap|caller.?id|truecaller|callapp|sync\.me|captcha|webdriver|selenium|playwright|"
                            r"login|password|hidden|employ|hiring|job.?fit|risk.?score|character|recommend|"
                            r"owner|send_?sms|tracking.?link", re.IGNORECASE)


def code_tokens(path: Path) -> str:
    """Identyfikatory i stałe tekstowe kodu (bez docstringów, które jawnie opisują, czego narzędzie NIE robi)."""
    import ast
    tree = ast.parse(path.read_text(encoding="utf-8"))
    docs = {id(n.body[0].value) for n in ast.walk(tree)
            if isinstance(n, (ast.Module, ast.FunctionDef, ast.ClassDef)) and n.body
            and isinstance(n.body[0], ast.Expr) and isinstance(n.body[0].value, ast.Constant)}
    out = []
    for n in ast.walk(tree):
        if isinstance(n, ast.Name):
            out.append(n.id)
        elif isinstance(n, ast.Attribute):
            out.append(n.attr)
        elif isinstance(n, (ast.FunctionDef, ast.arg)):
            out.append(getattr(n, "name", None) or n.arg)
        elif isinstance(n, ast.Constant) and isinstance(n.value, str) and id(n) not in docs:
            out.append(n.value)
    return "\n".join(out)


def test_new_modules_have_no_forbidden_mechanisms():
    src = Path(__file__).resolve().parents[1] / "src" / "entity_graph"
    for name in ("relacje.py", "telefon.py", "kandydaci.py", "sprawa.py", "transforms/phone.py"):
        hit = FORBIDDEN_CODE.search(code_tokens(src / name))
        assert hit is None, (name, hit)
