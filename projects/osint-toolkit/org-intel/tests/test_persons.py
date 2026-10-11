from __future__ import annotations

from org_intel.guards import NO_EMAIL_NOTE
from org_intel.models import EntityType, SourceType
from org_intel.parsers import parse_data


def person(**kw):
    base = {"name": "Jan Kowalski", "role": "Prezes Zarządu", "organization": "0000123456", "sources": ["s2"]}
    base.update(kw)
    return base


def run(own_doc, **kw):
    own_doc["persons"] = [person(**kw)]
    return parse_data(own_doc)


def test_osoba_ze_zrodla_official_registry(own_doc):
    r = run(own_doc, sources=["s1"])
    assert not r.rejections
    p = r.persons[0]
    assert p.organization_id == r.organizations[0].id
    assert p.role == "Prezes Zarządu"
    obs = [o for o in r.observations if o.entity_type is EntityType.PERSON]
    assert obs and obs[0].source_id == p.source_ids[0]


def test_email_przyjety_first_party_z_domena_organizacji(own_doc):
    r = run(own_doc, public_email="Jan.Kowalski@Example.test")
    assert r.persons[0].public_email == "jan.kowalski@example.test"
    assert not r.warnings


def test_email_przyjety_dla_subdomeny_organizacji(own_doc):
    r = run(own_doc, public_email="jan@poczta.example.test")
    assert r.persons[0].public_email == "jan@poczta.example.test"


def test_email_obca_domena_bez_cytatu_odrzucony_osoba_zapisana(own_doc):
    r = run(own_doc, public_email="jan.kowalski@gmail.test")
    assert not r.rejections
    assert r.persons[0].public_email is None
    notes = [o.notes for o in r.observations if o.entity_type is EntityType.PERSON]
    assert notes and all(n == NO_EMAIL_NOTE for n in notes)
    assert any(NO_EMAIL_NOTE in w.reason for w in r.warnings)


def test_email_obca_domena_ale_cytat_dowodu_przyjety(own_doc):
    r = run(
        own_doc, public_email="jan.kowalski@gmail.test", evidence_quote="Kontakt do prezesa: jan.kowalski@gmail.test"
    )
    assert r.persons[0].public_email == "jan.kowalski@gmail.test"


def test_email_ze_zrodla_manual_odrzucony_osoba_zostaje(own_doc):
    # osoba potwierdzona w rejestrze, ale e-mail pochodzi z notatki recznej
    r = run(own_doc, sources=["s1", "s4"], public_email="jan.kowalski@example.test", email_source="s4")
    assert not r.rejections
    assert r.persons[0].public_email is None
    assert any(NO_EMAIL_NOTE == o.notes for o in r.observations if o.entity_type is EntityType.PERSON)
    # zrodlo manual nie wchodzi do proweniencji osoby
    manual_id = next(s.id for s in r.sources if s.source_type is SourceType.MANUAL)
    assert manual_id not in r.persons[0].source_ids


def test_osoba_tylko_ze_zrodla_manual_odrzucona(own_doc):
    r = run(own_doc, sources=["s4"], public_email="jan.kowalski@example.test")
    assert not r.persons and "official_registry" in r.rejections[0].reason


def test_osoba_ze_zrodla_hibp_lub_cert_odrzucona(own_doc):
    own_doc["sources"].append(
        {
            "key": "h",
            "name": "Katalog HIBP",
            "url": "https://haveibeenpwned.com/api/v3/breaches",
            "source_type": "hibp_catalog",
            "license": "CC BY 4.0",
            "retrieved_at": "2026-10-05T10:00:00Z",
        }
    )
    for key in ("h", "s3"):
        r = run(own_doc, sources=[key])
        assert not r.persons, key
        assert "official_registry" in r.rejections[0].reason


def test_niepoprawny_format_emaila_nie_odrzuca_osoby(own_doc):
    r = run(own_doc, public_email="to-nie-email")
    assert r.persons and r.persons[0].public_email is None
    assert "niepoprawny format" in r.warnings[0].reason


def test_nieznana_organizacja_odrzuca_osobe(own_doc):
    r = run(own_doc, organization="Nieistniejąca Sp. z o.o.")
    assert not r.persons and "nieznana organizacja" in r.rejections[0].reason


def test_organizacja_po_nip_regon_i_nazwie(own_doc):
    for ref in ("5271001238", "360123459", "EXAMPLE spółka z ograniczoną odpowiedzialnością", "Example"):
        r = run(own_doc, organization=ref)
        assert r.persons, ref


def test_cytat_dowodu_nie_jest_zapisywany_tylko_hash(own_doc):
    r = run(own_doc, evidence_quote="Prezes: Jan Kowalski")
    obs = next(o for o in r.observations if o.entity_type is EntityType.PERSON)
    assert obs.evidence_hash and len(obs.evidence_hash) == 64
    assert "Prezes: Jan" not in str([o.to_dict() for o in r.observations])
