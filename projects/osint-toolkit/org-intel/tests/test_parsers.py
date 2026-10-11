from __future__ import annotations

import copy
import json

import pytest
from conftest import KRS, NIP, REGON, load_fixture

from org_intel.models import Confidence, Derivation, EntityType, IncidentStatus, SourceType
from org_intel.parsers import (
    HIBP_CATALOG_URL,
    HIBP_LICENSE,
    ParseError,
    clean_description,
    detect_format,
    parse_data,
    parse_file,
    parse_text,
)


def reasons(result):
    return [r.reason for r in result.rejections]


def test_wlasny_format_parsowanie(own_doc):
    r = parse_data(own_doc)
    assert r.format == "own"
    assert not r.rejections
    assert [o.legal_name for o in r.organizations] == ["Example Sp. z o.o."]
    org = r.organizations[0]
    assert (org.krs, org.nip, org.regon) == (KRS, NIP, REGON)
    assert org.official_domain == "example.test"
    assert {d.domain for d in r.domains} == {"example.test", "shop.example.test"}
    assert [p.name for p in r.persons] == ["Jan Kowalski"]
    assert r.persons[0].public_email == "jan.kowalski@example.test"
    assert [i.name for i in r.incidents] == ["CertIncident"]
    assert r.incidents[0].status == [IncidentStatus.VERIFIED]
    # zrodlo s1: utm i fragment usuniete w adresie zrodla
    s1 = next(s for s in r.sources if s.source_type is SourceType.OFFICIAL_REGISTRY)
    assert s1.url == "https://ekrs.example.test/odpis/0000123456"


def test_hibp_api_format(hibp_api):
    r = parse_data(hibp_api)
    assert r.format == "hibp_api"
    assert [i.name for i in r.incidents] == ["DemoBreach", "FakeList", "StealerDemo"]
    demo = r.incidents[0]
    assert demo.affected_domain == "shop.example.test"
    assert demo.affected_accounts_count == 12345
    assert demo.incident_date == "2026-08-15"
    assert demo.published_date == "2026-09-01T10:00:00Z"
    assert demo.status == [IncidentStatus.VERIFIED]
    assert "<" not in demo.description and "&amp;" not in demo.description
    assert demo.description == "Syntetyczny incydent & test. Szczegóły"
    assert [s.source_type for s in r.sources] == [SourceType.HIBP_CATALOG]
    src = r.sources[0]
    assert src.url == HIBP_CATALOG_URL and src.license == HIBP_LICENSE
    stealer = r.incidents[2]
    assert IncidentStatus.STEALER_LOG in stealer.status and IncidentStatus.MALWARE in stealer.status
    assert stealer.affected_domain is None


def test_hibp_monitor_format(hibp_monitor):
    r = parse_data(hibp_monitor)
    assert r.format == "hibp_monitor"
    assert [i.name for i in r.incidents] == ["DemoBreach", "FakeList"]
    assert r.incidents[1].status == [IncidentStatus.SPAM_LIST]
    assert r.incidents[1].description == "Lista zmyślona."
    assert r.sources[0].source_type is SourceType.HIBP_CATALOG


def test_oba_warianty_hibp_daja_ten_sam_incydent(hibp_api, hibp_monitor):
    a = parse_data(hibp_api).incidents[0]
    b = parse_data(hibp_monitor).incidents[0]
    assert a.id == b.id and a.to_dict() == b.to_dict() | {"description": a.description}


def test_dataclasses_passwords_nie_odrzucane(hibp_api):
    r = parse_data(hibp_api)
    assert not r.rejections
    assert "Passwords" in r.incidents[0].data_classes


def test_opis_html_i_limit():
    assert clean_description("<p>A &lt;b&gt; <b>x</b></p>") == "A <b> x"
    long = clean_description("x" * 5000)
    assert len(long) == 2000


def test_detect_format_i_bledy(tmp_path):
    with pytest.raises(ParseError):
        detect_format({"cos": 1})
    with pytest.raises(ParseError):
        detect_format([])
    with pytest.raises(ParseError):
        detect_format("tekst")
    with pytest.raises(ParseError, match="JSON"):
        parse_text("{niepoprawny")
    f = tmp_path / "x.json"
    f.write_text("{", encoding="utf-8")
    with pytest.raises(ParseError, match="JSON"):
        parse_file(f)
    with pytest.raises(ParseError, match="nie można|Nie można"):
        parse_file(tmp_path / "brak.json")
    with pytest.raises(ParseError, match="listą"):
        parse_data({"sources": {}})


def test_limit_rozmiaru_pliku(tmp_path, monkeypatch):
    from org_intel import parsers

    f = tmp_path / "duzy.json"
    f.write_text("{}" + " " * 200, encoding="utf-8")
    monkeypatch.setattr(parsers, "MAX_FILE_BYTES", 100)
    with pytest.raises(ParseError, match="limit"):
        parsers.parse_file(f)


def test_odrzucony_rekord_nie_przerywa_importu(own_doc):
    own_doc["organizations"].insert(0, {"legal_name": "Bez Zrodla Sp. z o.o.", "sources": []})
    own_doc["incidents"].append({"name": "Zly", "sources": ["s1"], "affected_domain": "!!!"})
    r = parse_data(own_doc)
    assert [o.legal_name for o in r.organizations] == ["Example Sp. z o.o."]
    assert len(r.rejections) == 2
    assert r.rejections[0].label.startswith("organizations[0]")
    assert any("brak źródła" in x for x in reasons(r))
    assert [i.name for i in r.incidents] == ["CertIncident"]


def test_rekord_bez_zrodla_odrzucony(own_doc):
    del own_doc["incidents"][0]["sources"]
    r = parse_data(own_doc)
    assert not r.incidents
    assert reasons(r) == ["brak źródła"]


def test_nieznany_klucz_zrodla_odrzuca_rekord(own_doc):
    own_doc["incidents"][0]["sources"] = ["s3", "literowka"]
    r = parse_data(own_doc)
    assert not r.incidents and "literowka" in reasons(r)[0]


@pytest.mark.parametrize(
    "patch",
    [
        {"name": "Pastebin dump firmy"},
        {"url": "https://t.me/kanal_z_baza"},
        {"url": "https://example.test/leaked/baza"},
        {"name": "Telegram: baza klientów"},
        {"source_type": "stealer_logs"},
        {"url": "https://breachforums.example.test/thread/1"},
        {"name": "combolist 2026"},
        {"source_type": "leak"},
    ],
)
def test_zrodlo_dump_telegram_odrzucone(own_doc, patch):
    own_doc["sources"].append({**own_doc["sources"][3], "key": "bad", **patch})
    own_doc["incidents"][0]["sources"] = ["bad"]
    r = parse_data(own_doc)
    assert any(x.label.startswith("sources[4]") for x in r.rejections)
    assert not r.incidents  # rekord opierajacy sie na odrzuconym zrodle tez odpada
    assert any("odrzucone" in x for x in reasons(r))
    assert all(s.id for s in r.sources)


def test_komunikat_cert_o_wycieku_dozwolony(own_doc):
    # komunikaty CERT opisuja wycieki z natury: slowa w sciezce/nazwie nie odrzucaja zrodla
    own_doc["sources"][2].update(
        name="CERT: wyciek stealer 2026", url="https://cert.example.test/posts/wyciek-stealer-2026/"
    )
    r = parse_data(own_doc)
    assert r.incidents and not any(x.label.startswith("sources[2]") for x in r.rejections)


@pytest.mark.parametrize(
    "url", ["https://t.me/kanal_z_baza", "https://pastebin.com/abc", "https://leaks.example.test/a"]
)
def test_komunikat_cert_na_hoscie_z_wyciekami_odrzucony(own_doc, url):
    own_doc["sources"][2]["url"] = url
    r = parse_data(own_doc)
    assert any(x.label.startswith("sources[2]") for x in r.rejections) and not r.incidents


def test_nieznany_typ_zrodla_i_brak_url_lub_daty(own_doc):
    base = own_doc["sources"][0]
    for patch, text in [
        ({"source_type": "hacker_forum"}, "nieznany typ"),
        ({"url": "ftp://x.test/a"}, "url"),
        ({"url": ""}, "url"),
        ({"retrieved_at": "wczoraj"}, "ISO 8601"),
        ({"retrieved_at": None}, "ISO 8601"),
    ]:
        doc = {"sources": [{**base, "key": "z", **patch}]}
        r = parse_data(doc)
        assert text in r.rejections[0].reason, (patch, r.rejections)


def test_hibp_catalog_jest_dozwolony_typ(own_doc):
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
    own_doc["incidents"].append({"name": "X", "affected_domain": "x.test", "sources": ["h"], "status": ["stealer_log"]})
    r = parse_data(own_doc)
    assert not r.rejections
    assert r.incidents[-1].status == [IncidentStatus.STEALER_LOG]


@pytest.mark.parametrize(
    "record, fragment",
    [
        ({"password": "abc"}, "password"),
        ({"password_hash": "x"}, "password_hash"),
        ({"api_key": "k"}, "api_key"),
        ({"access_token": "t"}, "access_token"),
        ({"notes": "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.sig"}, "JWT"),
        ({"description": "hash $2b$12$abcdefghijklmnopqrstuuABCDEFGHIJKLMNOPQRSTUVWXYZ01234"}, "bcrypt"),
        ({"description": "jan@example.test:Haslo123!"}, "e-mail:hasło"),
        ({"description": "-----BEGIN RSA PRIVATE KEY-----\nabc"}, "klucz prywatny"),
        ({"description": "5f4dcc3b5aa765d61d8327deb882cf99"}, "hex"),
        ({"data_classes": ["Passwords", "x" * 3, "e99a18c428cb38d5f260853678922e03abd8332d"]}, "hex"),
        ({"nested": {"deep": [{"secret": "x"}]}}, "secret"),
    ],
)
def test_sekrety_w_rekordzie_odrzucane(own_doc, record, fragment):
    own_doc["incidents"][0].update(record)
    r = parse_data(own_doc)
    assert not r.incidents
    assert fragment in reasons(r)[0], reasons(r)


def test_sekrety_w_kazdym_rodzaju_rekordu(own_doc):
    own_doc["organizations"][0]["password"] = "x"
    own_doc["domains"][0]["token"] = "x"
    own_doc["persons"][0]["notes"] = "a@b.test:haslo1"
    r = parse_data(own_doc)
    assert not r.organizations and not r.persons
    assert {x.label.split("[")[0] for x in r.rejections} == {"organizations", "domains", "persons"}


def test_hashe_dowodu_dozwolone(own_doc):
    h = "a" * 64
    own_doc["sources"][0]["content_hash"] = h
    own_doc["incidents"][0]["evidence_hash"] = h
    r = parse_data(own_doc)
    assert not r.rejections
    assert r.sources[0].content_hash == h or any(s.content_hash == h for s in r.sources)


def test_hex_w_url_nie_jest_sekretem(own_doc):
    own_doc["incidents"][0]["evidence_url"] = "https://cert.example.test/k/5f4dcc3b5aa765d61d8327deb882cf99"
    assert not parse_data(own_doc).rejections


def test_katalog_hibp_z_sekretem_odrzuca_tylko_ten_rekord(hibp_api):
    hibp_api[1]["Description"] = "dump: 5f4dcc3b5aa765d61d8327deb882cf99"
    r = parse_data(hibp_api)
    assert [i.name for i in r.incidents] == ["DemoBreach", "StealerDemo"]
    assert len(r.rejections) == 1


def test_incydent_bez_relacji_do_osob(own_doc):
    own_doc["incidents"][0]["persons"] = ["Jan Kowalski"]
    r = parse_data(own_doc)
    assert not r.incidents and "osobami" in reasons(r)[0]
    own_doc["incidents"][0].pop("persons")
    own_doc["persons"][0]["incidents"] = ["CertIncident"]
    r = parse_data(own_doc)
    assert not r.persons and "incydentem" in reasons(r)[0]


def test_niepoprawne_identyfikatory_odrzucone(own_doc):
    own_doc["organizations"][0]["nip"] = "5271001239"
    r = parse_data(own_doc)
    assert not r.organizations and "NIP" in reasons(r)[0]


def test_znany_organization_z_magazynu_jest_uzywany_do_osob(own_doc, ingest):
    store, _ = ingest(own_doc)
    persons_only = {
        "sources": [own_doc["sources"][1]],
        "persons": [
            {"name": "Anna Nowak", "role": "Wiceprezes", "organization": "Example sp. z o.o.", "sources": ["s2"]}
        ],
    }
    persons_only["sources"][0] = {**persons_only["sources"][0], "key": "s2"}
    r = parse_data(copy.deepcopy(persons_only), known_orgs=list(store.organizations.values()))
    assert not r.rejections
    assert r.persons[0].organization_id == next(iter(store.organizations))


def test_obserwacje_maja_pelna_proweniencje(own_doc):
    r = parse_data(own_doc)
    kinds = {(o.entity_type, o.entity_id) for o in r.observations}
    for ent_type, ents in (
        (EntityType.ORGANIZATION, r.organizations),
        (EntityType.DOMAIN, r.domains),
        (EntityType.PERSON, r.persons),
        (EntityType.INCIDENT, r.incidents),
    ):
        for e in ents:
            assert (ent_type, e.id) in kinds
    for o in r.observations:
        assert o.evidence_url.startswith("https://")
        assert o.observed_at.endswith("Z")
        assert isinstance(o.confidence, Confidence) and isinstance(o.derivation, Derivation)
        assert o.source_id in {s.id for s in r.sources}


def test_plik_json_przez_parse_file(tmp_path):
    f = tmp_path / "w.json"
    f.write_text(json.dumps(load_fixture("hibp_api.json")), encoding="utf-8")
    assert len(parse_file(f).incidents) == 3
