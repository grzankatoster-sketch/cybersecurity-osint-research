from __future__ import annotations

import json
import os

import pytest
from conftest import KRS

import org_intel.store as store_mod
from org_intel.correlate import company_view, incidents_for_domain, search_company
from org_intel.models import (
    Confidence,
    Derivation,
    EntityType,
    IncidentStatus,
    Source,
    SourceType,
    make_id,
)
from org_intel.parsers import parse_data
from org_intel.quality import observation_confidence, source_quality
from org_intel.store import ProvenanceError, Store, StoreError


def src(stype, reliability=Confidence.HIGH, url="https://x.example.test/a"):
    return Source("src_1", "n", url, stype, "", "2026-10-05T10:00:00Z", reliability)


# --- jakosc ----------------------------------------------------------------------


def test_jakosc_bazowa_z_typu_zrodla():
    assert source_quality(src(SourceType.OFFICIAL_REGISTRY)) is Confidence.HIGH
    assert source_quality(src(SourceType.COMPANY_WEBSITE)) is Confidence.HIGH
    assert source_quality(src(SourceType.CERT_ADVISORY)) is Confidence.HIGH
    assert source_quality(src(SourceType.HIBP_CATALOG)) is Confidence.MEDIUM
    assert source_quality(src(SourceType.MANUAL)) is Confidence.LOW
    assert source_quality(src(SourceType.OFFICIAL_DOCUMENT)) is Confidence.MEDIUM
    assert source_quality(src(SourceType.OFFICIAL_DOCUMENT, url="https://www.gov.pl/doc.pdf")) is Confidence.HIGH


def test_reliability_uzytkownika_obniza_ale_nie_podnosi():
    assert source_quality(src(SourceType.OFFICIAL_REGISTRY, Confidence.LOW)) is Confidence.LOW
    assert source_quality(src(SourceType.MANUAL, Confidence.HIGH)) is Confidence.LOW


def test_pewnosc_obserwacji_to_minimum_ze_zadeklarowana():
    s = src(SourceType.OFFICIAL_REGISTRY)
    assert observation_confidence(s, Confidence.MEDIUM) is Confidence.MEDIUM
    assert observation_confidence(s, None) is Confidence.HIGH


def test_fabricated_i_spam_list_daja_low():
    cert = src(SourceType.CERT_ADVISORY)
    assert observation_confidence(cert, None, [IncidentStatus.VERIFIED]) is Confidence.HIGH
    assert observation_confidence(cert, None, [IncidentStatus.FABRICATED]) is Confidence.LOW
    assert observation_confidence(cert, None, [IncidentStatus.VERIFIED, IncidentStatus.SPAM_LIST]) is Confidence.LOW


def test_katalog_hibp_zweryfikowany_medium_niezweryfikowany_low():
    hibp = src(SourceType.HIBP_CATALOG, Confidence.MEDIUM)
    assert observation_confidence(hibp, None, [IncidentStatus.VERIFIED]) is Confidence.MEDIUM
    assert observation_confidence(hibp, None, []) is Confidence.LOW


def test_fabricated_w_katalogu_hibp_przeklada_sie_na_obserwacje(ingest, hibp_api):
    store, _ = ingest(hibp_api)
    inc = {i.name: i for i in store.incidents.values()}
    conf = {n: store.observations_for(EntityType.INCIDENT, i.id)[0].confidence for n, i in inc.items()}
    assert conf == {"DemoBreach": Confidence.MEDIUM, "FakeList": Confidence.LOW, "StealerDemo": Confidence.MEDIUM}


# --- magazyn -------------------------------------------------------------------------


def test_kazda_encja_ma_obserwacje_z_pelna_proweniencja(loaded):
    for etype, bucket in (
        (EntityType.ORGANIZATION, loaded.organizations),
        (EntityType.DOMAIN, loaded.domains),
        (EntityType.PERSON, loaded.persons),
        (EntityType.INCIDENT, loaded.incidents),
    ):
        for ent in bucket.values():
            obs = loaded.observations_for(etype, ent.id)
            assert obs, f"{etype} {ent.id} bez obserwacji"
            for o in obs:
                assert o.evidence_url and o.observed_at and o.source_id in loaded.sources
                assert loaded.sources[o.source_id].source_type in SourceType
                assert o.confidence in Confidence and o.derivation in Derivation


def test_apply_odmawia_encji_bez_obserwacji(own_doc, tmp_path):
    r = parse_data(own_doc)
    r.observations = [o for o in r.observations if o.entity_type is not EntityType.INCIDENT]
    with pytest.raises(ProvenanceError):
        Store(tmp_path / "s.json").apply(r)


def test_deduplikacja_zrodel_po_znormalizowanym_url(own_doc, ingest):
    store, _ = ingest(own_doc)
    n_sources = len(store.sources)
    first = store.sources[make_id("source", "ekrs.example.test/odpis/0000123456")]
    again = json.loads(json.dumps(own_doc))
    again["sources"][0]["url"] = "http://EKRS.example.test/odpis/0000123456/?utm_campaign=z#inne"
    again["sources"][0]["retrieved_at"] = "2026-11-01T09:00:00Z"
    ingest(again, store)
    assert len(store.sources) == n_sources
    assert store.sources[first.id].retrieved_at == "2026-10-05T10:00:00Z"  # zostaje pierwsze
    org = next(iter(store.organizations.values()))
    dates = {o.observed_at for o in store.observations_for(EntityType.ORGANIZATION, org.id)}
    assert dates == {"2026-10-05T10:00:00Z", "2026-11-01T09:00:00Z"}  # nowe pobranie = nowa obserwacja


def test_reimport_tego_samego_pliku_jest_idempotentny(own_doc, ingest):
    store, _ = ingest(own_doc)
    before = json.dumps(store.to_dict(), sort_keys=True)
    ingest(own_doc, store)
    assert json.dumps(store.to_dict(), sort_keys=True) == before


def test_scalanie_organizacji_po_identyfikatorze_i_poprzednie_nazwy(own_doc, ingest):
    store, _ = ingest(own_doc)
    other = {
        "sources": [own_doc["sources"][0]],
        "organizations": [{"legal_name": "Stary Example S.A.", "krs": "123456", "sources": ["s1"]}],
    }
    store, _ = ingest(other, store)
    assert len(store.organizations) == 1
    org = next(iter(store.organizations.values()))
    assert org.legal_name == "Example Sp. z o.o."
    assert "Stary Example S.A." in org.previous_names
    assert org.nip and org.regon


def test_scalanie_po_nazwie_gdy_brak_identyfikatora(own_doc, ingest):
    store, _ = ingest(own_doc)
    other = {
        "sources": [own_doc["sources"][0]],
        "organizations": [{"legal_name": "EXAMPLE spółka z ograniczoną odpowiedzialnością", "sources": ["s1"]}],
    }
    store, _ = ingest(other, store)
    assert len(store.organizations) == 1


def test_rozne_krs_to_rozne_organizacje(own_doc, ingest):
    store, _ = ingest(own_doc)
    other = {
        "sources": [own_doc["sources"][0]],
        "organizations": [{"legal_name": "Example Sp. z o.o.", "krs": "0000999991", "sources": ["s1"]}],
    }
    store, _ = ingest(other, store)
    assert len(store.organizations) == 2


def test_status_weryfikacji_nie_cofany_przez_reimport(own_doc, ingest):
    from org_intel.models import VerificationStatus

    store, _ = ingest(own_doc)
    dom = store.find_domain("example.test")
    dom.verification_status = VerificationStatus.VERIFIED
    ingest(own_doc, store)
    assert store.find_domain("example.test").verification_status is VerificationStatus.VERIFIED


def test_zapis_i_odczyt_magazynu(loaded):
    loaded.save()
    again = Store.load(loaded.path)
    assert again.to_dict() == loaded.to_dict()
    assert json.loads(loaded.path.read_text(encoding="utf-8"))["schema_version"] == 1


def test_wersja_schematu_i_uszkodzony_plik(tmp_path):
    p = tmp_path / "s.json"
    p.write_text(json.dumps({"schema_version": 99}), encoding="utf-8")
    with pytest.raises(StoreError, match="wersj"):
        Store.load(p)
    p.write_text("{nie json", encoding="utf-8")
    with pytest.raises(StoreError):
        Store.load(p)


def test_zapis_atomowy_blad_zachowuje_stary_plik(loaded, monkeypatch):
    loaded.save()
    original = loaded.path.read_text(encoding="utf-8")
    loaded.verifications["x"] = {"a": 1}

    def boom(*a, **k):
        raise OSError("symulowana awaria")

    monkeypatch.setattr(os, "replace", boom)
    with pytest.raises(OSError):
        loaded.save()
    assert loaded.path.read_text(encoding="utf-8") == original
    assert not list(loaded.path.parent.glob("*.tmp"))


def test_audit_mode_zapisuje_raw_tylko_gdy_wlaczony(own_doc, tmp_path):
    off = Store(tmp_path / "a" / "s.json")
    off.apply(parse_data(own_doc))
    assert not (tmp_path / "a" / "raw").exists()
    on = Store(tmp_path / "b" / "s.json", audit_mode=True)
    summary = on.apply(parse_data(own_doc))
    raw = list((tmp_path / "b" / "raw").glob("ingest-*.json"))
    assert len(raw) == 1 and summary.raw_file
    kinds = {r["kind"] for r in json.loads(raw[0].read_text(encoding="utf-8"))["records"]}
    assert kinds == {"organization", "domain", "person", "incident"}


def test_audit_mode_nie_zapisuje_odrzuconych_sekretow(own_doc, tmp_path):
    own_doc["incidents"][0]["password"] = "tajne"
    st = Store(tmp_path / "s.json", audit_mode=True)
    st.apply(parse_data(own_doc))
    text = "".join(p.read_text(encoding="utf-8") for p in (tmp_path / "raw").glob("*.json"))
    assert "tajne" not in text


def test_magazyn_nie_zawiera_cytatow_dowodu(loaded):
    loaded.save()
    assert "Prezes Zarządu: Jan Kowalski, jan" not in loaded.path.read_text(encoding="utf-8")


# --- korelacje --------------------------------------------------------------------------


def test_firma_do_domeny(loaded):
    org = next(iter(loaded.organizations.values()))
    view = company_view(loaded, org)
    doms = {d.entity.domain: d for d in view.domains}
    assert set(doms) == {"example.test", "shop.example.test"}
    assert doms["example.test"].derivation is Derivation.DIRECT
    for d in view.domains:
        assert d.observations and d.source_ids


def test_domena_inferred_ze_zrodla_nie_first_party(own_doc, ingest):
    own_doc["domains"][0]["sources"] = ["s3"]  # cert_advisory, nie first-party
    store, _ = ingest(own_doc)
    view = company_view(store, next(iter(store.organizations.values())))
    shop = next(d for d in view.domains if d.entity.domain == "shop.example.test")
    assert shop.derivation is Derivation.INFERRED


def test_domena_po_nazwie_inferred(own_doc, ingest):
    own_doc["organizations"][0].pop("official_domain")
    own_doc["domains"] = [{"domain": "example.test", "sources": ["s3"]}]  # bez organization
    store, _ = ingest(own_doc)
    view = company_view(store, next(iter(store.organizations.values())))
    assert [(d.entity.domain, d.derivation) for d in view.domains] == [("example.test", Derivation.INFERRED)]


def test_domena_do_incydentu_i_subdomena_jako_inferred(loaded, hibp_api, ingest):
    ingest(hibp_api, loaded)  # DemoBreach na shop.example.test
    on_root = {l.entity.name: l for l in incidents_for_domain(loaded, "example.test")}
    assert on_root["CertIncident"].derivation is Derivation.DIRECT
    assert on_root["DemoBreach"].derivation is Derivation.INFERRED  # subdomena -> domena glowna
    assert "subdomenie" in on_root["DemoBreach"].via
    on_shop = {l.entity.name: l for l in incidents_for_domain(loaded, "shop.example.test")}
    assert set(on_shop) == {"DemoBreach"} and on_shop["DemoBreach"].derivation is Derivation.DIRECT
    assert incidents_for_domain(loaded, "inna.test") == []


def test_incydent_organizacji_przez_domene_ma_proweniencje(own_doc, hibp_api, ingest):
    own_doc["domains"] = []  # tylko example.test jako official_domain
    store, _ = ingest(own_doc)
    ingest(hibp_api, store)
    view = company_view(store, next(iter(store.organizations.values())))
    inc = {l.entity.name: l for l in view.incidents}
    assert inc["DemoBreach"].derivation is Derivation.INFERRED
    assert inc["DemoBreach"].observations and inc["DemoBreach"].source_ids
    assert {s.source_type for s in view.sources} >= {SourceType.HIBP_CATALOG, SourceType.OFFICIAL_REGISTRY}


def test_firma_do_osoby(loaded):
    view = company_view(loaded, next(iter(loaded.organizations.values())))
    assert [p.entity.name for p in view.persons] == ["Jan Kowalski"]
    assert view.persons[0].derivation is Derivation.DIRECT
    assert view.persons[0].observations


def test_brak_relacji_osoba_incydent_i_email_osoba(loaded, hibp_api, ingest):
    ingest(hibp_api, loaded)
    d = json.dumps(loaded.to_dict())
    for inc in loaded.incidents.values():
        assert not any(k in inc.to_dict() for k in ("person_id", "persons", "email", "emails"))
    for p in loaded.persons.values():
        assert not any(k in p.to_dict() for k in ("incident_id", "incidents"))
    assert "relations" not in d


def test_search_company_wszystkie_sposoby(loaded):
    for q in (
        "Example",
        "example sp. z o.o.",
        "EXAMPLE spółka z ograniczoną odpowiedzialnością",
        KRS,
        "123456",
        "527-100-12-38",
        "360123459",
    ):
        assert len(search_company(loaded, q)) == 1, q
    assert search_company(loaded, "Nieistniejaca") == []
    with pytest.raises(ValueError):
        search_company(loaded, "  ")


def test_search_company_poprzednie_nazwy(loaded):
    org = next(iter(loaded.organizations.values()))
    org.previous_names.append("Dawna Nazwa S.A.")
    assert len(search_company(loaded, "dawna nazwa")) == 1
    assert len(search_company(loaded, "dawna zupelnie inna")) == 0


def test_search_company_zawiera_proweniencje_w_kazdym_elemencie(loaded):
    (view,) = search_company(loaded, "Example")
    d = view.to_dict()
    assert d["organization"]["id"] and d["observations"] and d["sources"]
    for section in ("domains", "persons", "incidents"):
        for item in d[section]:
            assert item["source_ids"] and item["observations"] and item["derivation"] in ("direct", "inferred")


def test_store_module_ma_domyslna_sciezke():
    assert str(store_mod.DEFAULT_STORE).replace("\\", "/") == "org-intel-data/store.json"
