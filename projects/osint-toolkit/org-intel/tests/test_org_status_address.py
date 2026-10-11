"""Opcjonalne pola organizacji: status (znormalizowany + status_raw) i registered_address (tylko osoby prawne)."""

from __future__ import annotations

import io
import json

import pytest
from conftest import KRS, NIP, REGON

from org_intel.cli import EXIT_OK, main
from org_intel.export import build_json
from org_intel.models import Organization
from org_intel.normalize import ORG_STATUSES, normalize_org_status
from org_intel.parsers import parse_data
from org_intel.store import Store

ADDRESS = "ul. Przykładowa 1/2, 00-001 Przykładowo"


def doc(**org_fields):
    org = {"legal_name": "Example Sp. z o.o.", "krs": KRS, "nip": NIP, "regon": REGON, "sources": ["s1"]}
    org.update(org_fields)
    return {
        "sources": [
            {
                "key": "s1",
                "name": "Odpis z KRS",
                "url": "https://api-krs.ms.gov.pl/api/krs/OdpisAktualny/0000123456?rejestr=P&format=json",
                "source_type": "official_registry",
                "license": "dane publiczne",
                "retrieved_at": "2026-10-05T10:00:00Z",
                "reliability": "high",
            },
            {
                "key": "m1",
                "name": "Notatka",
                "url": "https://notatki.example.test/1",
                "source_type": "manual",
                "license": "",
                "retrieved_at": "2026-10-05T10:00:00Z",
            },
        ],
        "organizations": [org],
    }


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("AKTYWNY", "aktywna"),
        ("Aktywna", "aktywna"),
        ("ZAWIESZONY", "zawieszona"),
        ("WYKREŚLONY", "wykreslona"),
        ("wykreślona z powodu likwidacji", "wykreslona"),
        ("W LIKWIDACJI", "w_likwidacji"),
        ("w upadłości", "w_upadlosci"),
        ("postępowanie restrukturyzacyjne", "w_restrukturyzacji"),
        ("OCZEKUJE_NA_ROZPOCZECIE_DZIALALNOSCI", "inny"),
        ("nieaktywna", "inny"),
        ("coś zupełnie innego", "inny"),
        ("", None),
        ("   ", None),
        (None, None),
        (5, None),
    ],
)
def test_normalize_org_status(raw, expected):
    assert normalize_org_status(raw) == expected


def test_normalize_org_status_idempotent_on_list():
    for status in ORG_STATUSES:
        assert normalize_org_status(status) == status


def test_status_i_adres_osoby_prawnej_przyjete():
    r = parse_data(doc(status="W LIKWIDACJI", registered_address=ADDRESS))
    assert not r.rejections
    org = r.organizations[0]
    assert (org.status, org.status_raw, org.registered_address) == ("w_likwidacji", "W LIKWIDACJI", ADDRESS)


def test_status_raw_podany_osobno():
    org = parse_data(doc(status="wykreslona", status_raw="WYKREŚLONY Z REJESTRU")).organizations[0]
    assert (org.status, org.status_raw) == ("wykreslona", "WYKREŚLONY Z REJESTRU")


def test_brak_pol_to_none():
    org = parse_data(doc()).organizations[0]
    assert (org.status, org.status_raw, org.registered_address) == (None, None, None)


def test_adres_bez_krs_i_bez_legal_entity_odrzucony():
    r = parse_data(doc(krs=None, registered_address=ADDRESS))
    assert not r.organizations
    assert "registered_address" in r.rejections[0].reason


def test_adres_z_legal_entity_true_bez_krs_przyjety():
    r = parse_data(doc(krs=None, legal_entity=True, registered_address=ADDRESS))
    assert not r.rejections
    assert r.organizations[0].registered_address == ADDRESS


def test_adres_z_legal_entity_false_odrzucony_nawet_z_krs():
    r = parse_data(doc(legal_entity=False, registered_address=ADDRESS))
    assert not r.organizations and r.rejections


def test_adres_legal_entity_nie_bool_odrzucony():
    r = parse_data(doc(legal_entity="tak", registered_address=ADDRESS))
    assert not r.organizations and "legal_entity" in r.rejections[0].reason


def test_adres_wymaga_zrodla_official_registry():
    r = parse_data(doc(registered_address=ADDRESS, sources=["m1"]))
    assert not r.organizations
    assert "official_registry" in r.rejections[0].reason


def test_status_bez_adresu_dla_osoby_fizycznej_ok():
    r = parse_data(doc(krs=None, status="AKTYWNY"))
    assert not r.rejections
    org = r.organizations[0]
    assert org.status == "aktywna" and org.registered_address is None


def test_merge_pierwsza_wartosc_wygrywa_z_ostrzezeniem():
    first = Organization(id="org_x", legal_name="Example", krs=KRS, status="aktywna", status_raw="AKTYWNY")
    other = Organization(
        id="org_x", legal_name="Example", krs=KRS, status="wykreslona", status_raw="WYKREŚLONY", registered_address="A"
    )
    warnings = first.merge(other)
    assert (first.status, first.status_raw, first.registered_address) == ("aktywna", "AKTYWNY", "A")
    assert any("konflikt status" in w for w in warnings)
    third = Organization(id="org_x", legal_name="Example", krs=KRS, registered_address="B")
    assert any("konflikt registered_address" in w for w in first.merge(third))
    assert first.registered_address == "A"


def test_merge_uzupelnia_puste_pola_razem_ze_status_raw():
    first = Organization(id="org_x", legal_name="Example", krs=KRS)
    first.merge(Organization(id="org_x", legal_name="Example", krs=KRS, status="zawieszona", status_raw="ZAWIESZONY"))
    assert (first.status, first.status_raw) == ("zawieszona", "ZAWIESZONY")


def test_store_roundtrip_eksport_i_stary_magazyn(tmp_path):
    store = Store(tmp_path / "store.json")
    store.apply(parse_data(doc(status="ZAWIESZONY", registered_address=ADDRESS)))
    store.save()
    loaded = Store.load(tmp_path / "store.json")
    org = next(iter(loaded.organizations.values()))
    assert (org.status, org.registered_address) == ("zawieszona", ADDRESS)
    exported = build_json(loaded)["organizations"][0]
    assert exported["status"] == "zawieszona" and exported["status_raw"] == "ZAWIESZONY"
    assert exported["registered_address"] == ADDRESS
    # magazyn sprzed zmiany (bez nowych pol) nadal sie wczytuje
    data = json.loads((tmp_path / "store.json").read_text(encoding="utf-8"))
    for key in ("status", "status_raw", "registered_address"):
        del data["organizations"][0][key]
    (tmp_path / "old.json").write_text(json.dumps(data), encoding="utf-8")
    old = next(iter(Store.load(tmp_path / "old.json").organizations.values()))
    assert (old.status, old.status_raw, old.registered_address) == (None, None, None)


def test_ponowny_import_idempotentny_i_bez_ostrzezen(tmp_path):
    store = Store(tmp_path / "store.json")
    store.apply(parse_data(doc(status="AKTYWNY", registered_address=ADDRESS)))
    before = json.dumps(store.to_dict(), sort_keys=True)
    again = parse_data(doc(status="AKTYWNY", registered_address=ADDRESS), known_orgs=list(store.organizations.values()))
    summary = store.apply(again)
    assert json.dumps(store.to_dict(), sort_keys=True) == before
    assert not summary.warnings


def test_search_company_pokazuje_status_i_adres(tmp_path):
    path = tmp_path / "in.json"
    path.write_text(json.dumps(doc(status="W LIKWIDACJI", registered_address=ADDRESS)), encoding="utf-8")
    store = tmp_path / "store.json"
    assert main(["ingest", str(path), "--store", str(store)], out=io.StringIO()) == EXIT_OK
    out = io.StringIO()
    assert main(["search-company", KRS, "--store", str(store)], out=out) == EXIT_OK
    text = out.getvalue()
    assert "status: w_likwidacji (rejestr: W LIKWIDACJI)" in text
    assert f"adres siedziby: {ADDRESS}" in text
    out = io.StringIO()
    assert main(["search-company", KRS, "--json", "--store", str(store)], out=out) == EXIT_OK
    organization = json.loads(out.getvalue())["results"][0]["organization"]
    assert organization["status"] == "w_likwidacji" and organization["registered_address"] == ADDRESS
