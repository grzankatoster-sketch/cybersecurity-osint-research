"""Testy mapowania Finding -> rekord run sprawy entity-graph.

Kontrakt (klucze rekordu, wartości statusów) jest zahardkodowany wg
entity-graph/src/entity_graph/model.py (RunRecord.to_dict, Status) — tak, by
test wychwycił rozjazd, gdyby któraś strona się zmieniła. Nie importujemy
entity-graph.
"""
import asyncio

from osint_connectors import (
    Context,
    Finding,
    InputKind,
    SourceKind,
    Status,
    Subject,
    run,
    subject_ref,
)
from osint_connectors.integration import (
    ENTITY_GRAPH_RUN_KEYS,
    finding_to_run,
    findings_to_runs,
)

# Odwzorowanie kontraktu entity-graph (model.py). Gdy się rozjedzie — test padnie.
EG_RUN_KEYS = ("transform", "node", "status", "timestamp", "note", "error", "stats")
EG_STATUS_VALUES = {"FOUND", "NOT_FOUND", "UNKNOWN", "ERROR"}


def test_status_names_bridge_to_entity_graph_values():
    # Nasze wartości są lowercase, ale .name daje wartości enuma entity-graph.
    assert {s.name for s in Status} == EG_STATUS_VALUES


def test_run_has_exact_entity_graph_keys():
    assert ENTITY_GRAPH_RUN_KEYS == EG_RUN_KEYS
    f = Finding("gravatar_public", SourceKind.PASSIVE, Status.FOUND, 0.95, "refhash",
                evidence="publiczny profil Gravatara istnieje", extra={"public_profile_url": "https://x"})
    r = finding_to_run(f, "email:jan@example.com")
    assert tuple(r.keys()) == EG_RUN_KEYS
    assert r["status"] == "FOUND"
    assert r["transform"] == "gravatar_public"
    assert r["node"] == "email:jan@example.com"
    assert r["error"] == ""  # FOUND nie ma błędu
    assert r["stats"]["source"] == "passive"
    assert r["stats"]["confidence"] == 0.95
    assert r["stats"]["subject_ref"] == "refhash"
    assert r["stats"]["extra.public_profile_url"] == "https://x"


def test_error_kind_goes_to_error_field():
    f = Finding("c", SourceKind.OFFICIAL_API, Status.ERROR, 0.0, "ref", error_kind="transport")
    r = finding_to_run(f, "email:x@y.z")
    assert r["status"] == "ERROR" and r["error"] == "transport"
    u = Finding("c", SourceKind.OFFICIAL_API, Status.UNKNOWN, 0.0, "ref", error_kind="rate_limited")
    assert finding_to_run(u, "email:x@y.z")["error"] == "rate_limited"


def test_node_id_required():
    f = Finding("c", SourceKind.PASSIVE, Status.NOT_FOUND, 0.9, "ref")
    try:
        finding_to_run(f, "   ")
    except ValueError:
        pass
    else:
        raise AssertionError("pusty node_id powinien dać ValueError")


def test_no_raw_subject_in_run_record():
    subj = Subject(InputKind.EMAIL, "target@example.com")
    ctx = Context(salt="sol", dataset={"known_refs": set()})
    import osint_connectors.connectors.passive_local  # noqa: F401
    from osint_connectors import registry
    findings = asyncio.run(run([registry.get("passive_local_dataset")], subj, ctx))
    runs = findings_to_runs(findings, "email:target@example.com")
    # node_id celowo zawiera e-mail (to dane wołającego), ale stats nie powielają surowej wartości,
    # a subject_ref jest zahaszowany.
    for r in runs:
        assert r["stats"]["subject_ref"] == subject_ref(subj, "sol")
        assert "@" not in r["stats"]["subject_ref"]


def test_findings_to_runs_sorted():
    f1 = Finding("zeta", SourceKind.PASSIVE, Status.NOT_FOUND, 0.9, "ref")
    f2 = Finding("alpha", SourceKind.PASSIVE, Status.FOUND, 1.0, "ref")
    runs = findings_to_runs([f1, f2], "email:a@b.c")
    assert [r["transform"] for r in runs] == ["alpha", "zeta"]
