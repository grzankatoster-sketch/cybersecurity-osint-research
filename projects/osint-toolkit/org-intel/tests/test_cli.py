from __future__ import annotations

import csv
import io
import json
import shutil
from pathlib import Path

import pytest
from conftest import FIXTURES, FakeClient, FakeResolver, ForbiddenClient

from org_intel.cli import EXIT_NETWORK, EXIT_OK, EXIT_PARTIAL, EXIT_USAGE, main
from org_intel.http import Response
from org_intel.models import VerificationStatus
from org_intel.store import Store


def run(*argv, **kw):
    out = io.StringIO()
    code = main([str(a) for a in argv], out=out, **kw)
    return code, out.getvalue()


@pytest.fixture
def store_path(tmp_path) -> Path:
    return tmp_path / "data" / "store.json"


@pytest.fixture
def ingested(store_path):
    code, text = run("ingest", FIXTURES / "own_format.json", "--store", store_path)
    assert code == EXIT_OK, text
    return store_path


def test_ingest_raport_i_magazyn(store_path):
    code, text = run("ingest", FIXTURES / "own_format.json", "--store", store_path)
    assert code == EXIT_OK
    assert "Zaakceptowano: 5 encji" in text and "odrzucono: 0" in text
    store = Store.load(store_path)
    assert len(store.organizations) == 1 and len(store.domains) == 2 and len(store.persons) == 1


def test_ingest_czesciowe_odrzucenie_daje_kod_4(tmp_path, store_path):
    doc = json.loads((FIXTURES / "own_format.json").read_text(encoding="utf-8"))
    doc["incidents"].append({"name": "Bez zrodla"})
    doc["incidents"].append({"name": "Haslo", "password": "x", "sources": ["s3"]})
    f = tmp_path / "in.json"
    f.write_text(json.dumps(doc), encoding="utf-8")
    code, text = run("ingest", f, "--store", store_path)
    assert code == EXIT_PARTIAL
    assert "ODRZUCONO incidents[1] Bez zrodla: brak źródła" in text
    assert "password" in text
    assert len(Store.load(store_path).incidents) == 1  # reszta zapisana


def test_ingest_zly_plik_kod_2(tmp_path, store_path):
    f = tmp_path / "zly.json"
    f.write_text("{nie json", encoding="utf-8")
    assert run("ingest", f, "--store", store_path)[0] == EXIT_USAGE
    assert run("ingest", tmp_path / "brak.json", "--store", store_path)[0] == EXIT_USAGE


def test_ingest_katalog_hibp_oba_formaty(store_path):
    assert run("ingest", FIXTURES / "hibp_api.json", "--store", store_path)[0] == EXIT_OK
    assert run("ingest", FIXTURES / "hibp_monitor.json", "--store", store_path)[0] == EXIT_OK
    assert len(Store.load(store_path).incidents) == 3  # te same nazwy -> deduplikacja


def test_audit_mode_flaga(tmp_path, store_path):
    run("ingest", FIXTURES / "own_format.json", "--store", store_path)
    assert not (store_path.parent / "raw").exists()
    code, text = run("ingest", FIXTURES / "own_format.json", "--store", store_path, "--audit-mode")
    assert code == EXIT_OK and "Tryb audytowy" in text
    assert list((store_path.parent / "raw").glob("ingest-*.json"))


def test_search_company_tekst_i_json(ingested):
    code, text = run("search-company", "example", "--store", ingested)
    assert code == EXIT_OK
    assert "Example Sp. z o.o." in text and "example.test" in text and "źródła:" in text
    assert "https://ekrs.example.test/odpis/0000123456" in text
    code, text = run("search-company", "0000123456", "--store", ingested, "--json")
    data = json.loads(text)
    assert data["results"][0]["organization"]["nip"] == "5271001238"
    code, text = run("search-company", "nie ma takiej", "--store", ingested)
    assert code == EXIT_OK and "Brak wyników" in text


def test_incidents_domena(ingested):
    run("ingest", FIXTURES / "hibp_api.json", "--store", ingested)
    code, text = run("incidents", "--domain", "https://www.example.test", "--store", ingested, "--json")
    names = {i["entity"]["name"]: i["derivation"] for i in json.loads(text)["incidents"]}
    assert names == {"CertIncident": "direct", "DemoBreach": "inferred"}
    code, text = run("incidents", "--domain", "zly domen", "--store", ingested)
    assert code == EXIT_USAGE
    code, text = run("incidents", "--domain", "brak.test", "--store", ingested)
    assert code == EXIT_OK and "Brak incydentów" in text


def test_export_json_i_csv(ingested, tmp_path):
    code, _ = run("export", "--format", "json", "--out", tmp_path / "e" / "all.json", "--store", ingested)
    assert code == EXIT_OK
    data = json.loads((tmp_path / "e" / "all.json").read_text(encoding="utf-8"))
    assert data["persons"][0]["public_email"] == "j***@example.test"
    code, _ = run("export", "--format", "csv", "--out", tmp_path / "csv", "--store", ingested, "--include-emails")
    assert code == EXIT_OK
    rows = list(csv.DictReader((tmp_path / "csv" / "persons.csv").open(encoding="utf-8-sig", newline="")))
    assert rows[0]["public_email"] == "jan.kowalski@example.test"


def test_verify_domain_wydanie_tokenu_offline(ingested):
    client = ForbiddenClient()
    code, text = run("verify-domain", "example.test", "--store", ingested, client=client)
    assert code == EXIT_OK and "org-intel-verification=" in text
    token = text.split("org-intel-verification=")[1].split()[0]
    store = Store.load(ingested)
    assert store.find_domain("example.test").verification_status is VerificationStatus.PENDING
    assert token not in ingested.read_text(encoding="utf-8")
    assert client.calls == 0


def test_verify_domain_check_bez_online_kod_2_zero_ruchu(ingested):
    resolver = FakeResolver()
    client = ForbiddenClient()
    code, _ = run("verify-domain", "example.test", "--check", "--store", ingested, resolver=resolver, client=client)
    assert code == EXIT_USAGE and resolver.calls == [] and client.calls == 0


def test_verify_domain_check_online(ingested):
    _, text = run("verify-domain", "example.test", "--store", ingested)
    record = "org-intel-verification=" + text.split("org-intel-verification=")[1].split()[0]
    code, text = run(
        "verify-domain", "example.test", "--check", "--online", "--store", ingested, resolver=FakeResolver([record])
    )
    assert code == EXIT_OK and "zweryfikowana" in text
    assert Store.load(ingested).find_domain("example.test").verification_status is VerificationStatus.VERIFIED
    run("verify-domain", "example.test", "--store", ingested)  # nowy token
    code, text = run(
        "verify-domain",
        "example.test",
        "--check",
        "--online",
        "--store",
        ingested,
        resolver=FakeResolver(["v=spf1 -all"]),
    )
    assert code == EXIT_OK and "nieudana" in text
    assert Store.load(ingested).find_domain("example.test").verification_status is VerificationStatus.FAILED


def test_verify_domain_nieznana_domena_kod_2(ingested):
    assert run("verify-domain", "nieznana.test", "--store", ingested)[0] == EXIT_USAGE


def test_fetch_hibp_bez_online_kod_2_zero_wywolan(store_path):
    client = ForbiddenClient()
    code, _ = run("fetch-hibp-catalog", "--user-agent", "x", "--store", store_path, client=client)
    assert code == EXIT_USAGE and client.calls == 0
    assert not store_path.exists()


def test_fetch_hibp_wymaga_user_agent(store_path):
    client = ForbiddenClient()
    assert run("fetch-hibp-catalog", "--online", "--store", store_path, client=client)[0] == EXIT_USAGE
    assert client.calls == 0


def test_fetch_hibp_online_zapis_przez_parser(store_path):
    body = (FIXTURES / "hibp_api.json").read_text(encoding="utf-8")
    client = FakeClient(Response(200, body))
    code, text = run(
        "fetch-hibp-catalog", "--online", "--user-agent", "firma org-intel/0.1", "--store", store_path, client=client
    )
    assert code == EXIT_OK and "pobrano z HIBP" in text
    assert len(client.calls) == 1
    store = Store.load(store_path)
    assert len(store.incidents) == 3
    assert (store_path.parent / "cache" / "hibp-breaches.json").exists()
    code, text = run(
        "fetch-hibp-catalog", "--online", "--user-agent", "firma org-intel/0.1", "--store", store_path, client=client
    )
    assert code == EXIT_OK and "cache" in text and len(client.calls) == 1


def test_fetch_hibp_blad_sieci_kod_3(store_path):
    client = FakeClient(Response(500, ""))
    code, _ = run("fetch-hibp-catalog", "--online", "--user-agent", "ua", "--store", store_path, client=client)
    assert code == EXIT_NETWORK


def test_blad_skladni_kod_2():
    with pytest.raises(SystemExit) as e:
        main(["export", "--format", "xml"], out=io.StringIO())
    assert e.value.code == 2
    with pytest.raises(SystemExit) as e:
        main([], out=io.StringIO())
    assert e.value.code == 2


def test_end_to_end(tmp_path):
    store = tmp_path / "e2e" / "store.json"
    shutil.copy(FIXTURES / "own_format.json", tmp_path / "own.json")
    assert run("ingest", tmp_path / "own.json", "--store", store)[0] == EXIT_OK
    assert run("ingest", FIXTURES / "hibp_api.json", "--store", store)[0] == EXIT_OK
    _, text = run("search-company", "Example Sp. z o.o.", "--store", store, "--json")
    view = json.loads(text)["results"][0]
    assert {d["entity"]["domain"] for d in view["domains"]} == {"example.test", "shop.example.test"}
    assert {i["entity"]["name"] for i in view["incidents"]} == {"CertIncident", "DemoBreach"}
    assert [p["entity"]["name"] for p in view["persons"]] == ["Jan Kowalski"]
    assert run("export", "--format", "json", "--out", tmp_path / "x.json", "--store", store)[0] == EXIT_OK
    exported = json.loads((tmp_path / "x.json").read_text(encoding="utf-8"))
    assert exported["attribution"] and len(exported["observations"]) == 8
