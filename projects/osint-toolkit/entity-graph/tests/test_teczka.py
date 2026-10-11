import json

import pytest

from entity_graph import cli, teczka
from entity_graph.guardrails import AuditLog, verify_audit
from entity_graph.model import Edge, Graph, Node
from entity_graph.normalize import EntityType as T

PROFILE = {"kind": "profile"}


def _graph() -> tuple[Graph, dict]:
    g = Graph({"purpose": "due diligence kandydata na wspólnika, zlecenie 2026/7"})
    n = {
        "person": g.add_node(Node.make(T.PERSON, "Jan Kowalski")),
        "u1": g.add_node(Node.make(T.USERNAME, "jan.kowalski", {"candidate": True})),
        "u2": g.add_node(Node.make(T.USERNAME, "jkowalski", {"candidate": True})),
        "a": g.add_node(Node.make(T.URL, "https://github.com/jan.kowalski", {**PROFILE, "site": "GitHub"})),
        "b": g.add_node(Node.make(T.URL, "https://gitlab.com/jkow", {**PROFILE, "site": "GitLab"})),
        "c": g.add_node(Node.make(T.URL, "https://x.com/jkowalski", {**PROFILE, "site": "X"})),
        "dom": g.add_node(Node.make(T.DOMAIN, "kowalski-dev.pl")),
        "mail": g.add_node(Node.make(T.EMAIL, "jan@kowalski-dev.pl")),
    }
    for u in ("u1", "u2"):
        g.add_edge(Edge(n["person"].id, n[u].id, "candidate_username", "person_candidates", 0.0, "wzorzec"))
    g.add_edge(Edge(n["u1"].id, n["a"].id, "has_account", "username_scan", 0.8, "trafienie"))
    g.add_edge(Edge(n["u2"].id, n["c"].id, "has_account", "username_scan", 0.6, "trafienie"))
    g.add_edge(Edge(n["a"].id, n["dom"].id, "links_to_domain", "links", 0.6, "strona w profilu"))
    g.add_edge(Edge(n["a"].id, n["mail"].id, "avatar_matches_email", "correlate", 0.85, "gravatar"))
    g.add_edge(Edge(n["a"].id, n["b"].id, "same_person", "correlate", 0.7, "wzajemny link"))
    g.add_edge(Edge(n["b"].id, n["mail"].id, "uses_email", "x", 0.9, "x"))
    return g, n


EVIDENCE = "zdjęcie i firma zgodne z KRS spółki"


def test_candidates_from_person_usernames_sorted_by_confidence():
    g, n = _graph()
    ids = [c.node.id for c in teczka.candidates(g, n["person"])]
    assert ids == [n["a"].id, n["c"].id]   # profil B nie jest kandydatem, dopóki A niepotwierdzony


def test_confirm_links_profile_data_to_person_but_not_other_profiles():
    g, n = _graph()
    teczka.decide(g, n["person"], n["a"], teczka.CONFIRMED, EVIDENCE)
    created = teczka.propagate(g, n["person"])
    linked = {e.dst: e for e in created}
    assert set(linked) == {n["u1"].id, n["dom"].id, n["mail"].id}
    assert all(e.confidence <= 0.9 for e in created)
    assert linked[n["dom"].id].confidence == 0.6
    assert n["b"].id not in linked                      # inny profil: tylko kandydat
    cands = {c.node.id: c for c in teczka.candidates(g, n["person"])}
    assert cands[n["b"].id].decision == "" and "ta sama osoba" in cands[n["b"].id].reasons[0]
    assert cands[n["a"].id].decision == teczka.CONFIRMED


def test_reject_after_confirm_removes_linked_data_and_propagate_is_idempotent():
    g, n = _graph()
    teczka.decide(g, n["person"], n["a"], teczka.CONFIRMED, EVIDENCE)
    first = teczka.propagate(g, n["person"])
    assert len(teczka.propagate(g, n["person"])) == len(first)
    teczka.decide(g, n["person"], n["a"], teczka.REJECTED, "inna osoba, inne miasto i zdjęcie")
    assert teczka.propagate(g, n["person"]) == []
    d = teczka.dossier(g, n["person"])
    assert not d["confirmed"] and len(d["rejected"]) == 1 and not d["data"]


@pytest.mark.parametrize("bad", ["", "tak", "   ", "ok ok"])
def test_evidence_required(bad):
    g, n = _graph()
    with pytest.raises(ValueError):
        teczka.decide(g, n["person"], n["a"], teczka.CONFIRMED, bad)


def test_non_profile_cannot_be_confirmed():
    g, n = _graph()
    with pytest.raises(ValueError):
        teczka.decide(g, n["person"], n["dom"], teczka.CONFIRMED, EVIDENCE)


def _case(tmp_path):
    g, n = _graph()
    g.save(tmp_path / "graph.json")
    AuditLog(tmp_path / "audit.jsonl", "ala").start(g.meta["purpose"], [], {})
    return n


def test_cli_przeglad_interactive(tmp_path, monkeypatch, capsys):
    n = _case(tmp_path)
    # A: tak (najpierw za krótki dowód); C (0.6): nie; B (pojawia się po potwierdzeniu A): pomiń
    answers = iter(["t", "tak", EVIDENCE, "n", "inne zdjęcie, inne miasto", "p"])
    monkeypatch.setattr(cli, "ASK", lambda prompt: next(answers))
    assert cli.main(["przeglad", str(tmp_path), "--person", "Jan Kowalski"]) == 0
    out = capsys.readouterr().out
    assert "dowód jest wymagany" in out and "Zapisano" in out
    g = Graph.load(tmp_path / "graph.json")
    d = teczka.dossier(g, g.nodes[n["person"].id])
    assert [x.id for x, _ in d["confirmed"]] == [n["a"].id]
    assert [x.id for x, _ in d["rejected"]] == [n["c"].id]
    assert {x.id for x, _ in d["data"]} == {n["u1"].id, n["dom"].id, n["mail"].id}
    ok, _ = verify_audit(tmp_path / "audit.jsonl")
    events = [json.loads(x)["event"] for x in (tmp_path / "audit.jsonl").read_text(encoding="utf-8").splitlines()]
    assert ok and events.count("decision") == 2 and "teczka" in events
    assert "Teczka osoby" in (tmp_path / "report.html").read_text(encoding="utf-8")
    assert "#1b9e45" in (tmp_path / "kropki.svg").read_text(encoding="utf-8")


def test_cli_potwierdz_manual_profile_and_guards(tmp_path, capsys):
    _case(tmp_path)
    args = ["potwierdz", str(tmp_path), "--person", "Jan Kowalski", "--profil", "https://linkedin.com/in/jan-k",
            "--dowod", EVIDENCE]
    assert cli.main(args) == 2                         # profilu nie ma w grafie
    assert cli.main(args + ["--dodaj"]) == 0
    assert cli.main(["potwierdz", str(tmp_path), "--person", "Anna Nowak", "--profil", "https://x.com/jkowalski",
                     "--dowod", EVIDENCE]) == 2         # osoby nie ma w grafie
    (tmp_path / "audit.jsonl").write_text("", encoding="utf-8")
    assert cli.main(args) == 2                         # bez dziennika audytu nie ma decyzji


def test_profile_website_and_links_become_person_domains_and_vanish_after_reject():
    g, n = _graph()
    n["a"].attrs.update(website="https://kowalski-dev.pl", links=["https://blog-kowalskiego.example/o-mnie",
                                                                  "https://gitlab.com/jkow"])
    teczka.decide(g, n["person"], n["a"], teczka.CONFIRMED, EVIDENCE)
    created = {e.dst: e for e in teczka.propagate(g, n["person"])}
    blog = Node.make(T.DOMAIN, "blog-kowalskiego.example").id
    assert created[blog].confidence == 0.5 and "link w profilu" in created[blog].evidence
    assert created[n["dom"].id].confidence == 0.6        # istniejąca domena: wyższa z dwóch dróg
    assert not any("gitlab" in d for d in created)        # platforma to nie własna domena
    teczka.decide(g, n["person"], n["a"], teczka.REJECTED, "inna osoba, inne miasto i zdjęcie")
    teczka.propagate(g, n["person"])
    assert blog not in g.nodes                            # dodana tylko przez teczkę: usunięta
    assert n["dom"].id in g.nodes                         # znana z innego źródła: zostaje
