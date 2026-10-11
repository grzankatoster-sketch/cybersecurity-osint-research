from __future__ import annotations

import csv
import io
import json
import logging

from org_intel.export import HIBP_ATTRIBUTION, export_csv, export_json, sanitize_cell
from org_intel.logging_redact import get_logger, mask_email, redact


def test_eksport_json_z_atrybucja_hibp(loaded, hibp_api, ingest, tmp_path):
    ingest(hibp_api, loaded)
    path = export_json(loaded, tmp_path / "out" / "all.json")
    data = json.loads(path.read_text(encoding="utf-8"))
    assert data["attribution"][0]["license"] == "CC BY 4.0"
    assert data["attribution"][0]["source"] == HIBP_ATTRIBUTION["source"]
    assert {s["source_type"] for s in data["sources"]} >= {"hibp_catalog", "official_registry"}
    assert len(data["incidents"]) == 4 and data["observations"]
    assert "verifications" not in data


def test_eksport_json_bez_atrybucji_bez_zrodel_hibp(loaded, tmp_path):
    data = json.loads(export_json(loaded, tmp_path / "a.json").read_text(encoding="utf-8"))
    assert "attribution" not in data


def test_eksport_maskuje_emaile_domyslnie(loaded, tmp_path):
    masked = export_json(loaded, tmp_path / "m.json").read_text(encoding="utf-8")
    assert "jan.kowalski@example.test" not in masked and "j***@example.test" in masked
    full = export_json(loaded, tmp_path / "f.json", include_emails=True).read_text(encoding="utf-8")
    assert "jan.kowalski@example.test" in full


def test_eksport_csv_pliki_i_maskowanie(loaded, tmp_path):
    files = export_csv(loaded, tmp_path / "csv")
    names = {f.name for f in files}
    assert {
        "sources.csv",
        "organizations.csv",
        "domains.csv",
        "persons.csv",
        "incidents.csv",
        "observations.csv",
    } <= names
    rows = list(csv.DictReader((tmp_path / "csv" / "persons.csv").open(encoding="utf-8-sig", newline="")))
    assert rows[0]["public_email"] == "j***@example.test"
    full = export_csv(loaded, tmp_path / "csv2", include_emails=True)
    rows = list(csv.DictReader((tmp_path / "csv2" / "persons.csv").open(encoding="utf-8-sig", newline="")))
    assert rows[0]["public_email"] == "jan.kowalski@example.test" and full


def test_csv_listy_laczone_srednikiem(loaded, tmp_path):
    export_csv(loaded, tmp_path / "c")
    rows = list(csv.DictReader((tmp_path / "c" / "incidents.csv").open(encoding="utf-8-sig", newline="")))
    assert rows[0]["status"] == "verified"
    orgs = list(csv.DictReader((tmp_path / "c" / "organizations.csv").open(encoding="utf-8-sig", newline="")))
    assert orgs[0]["source_ids"].count(";") == 0  # jedno zrodlo


def test_csv_injection(own_doc, ingest, tmp_path):
    own_doc["incidents"][0]["name"] = '=HYPERLINK("http://x.test")'
    own_doc["incidents"][0]["description"] = "@SUM(A1)"
    own_doc["incidents"][0]["data_classes"] = ["+cmd", "-1+1", "ok"]
    store, _ = ingest(own_doc)
    export_csv(store, tmp_path / "c")
    rows = list(csv.DictReader((tmp_path / "c" / "incidents.csv").open(encoding="utf-8-sig", newline="")))
    assert rows[0]["name"].startswith("'=")
    assert rows[0]["description"] == "'@SUM(A1)"
    assert rows[0]["data_classes"] == "'+cmd;-1+1;ok"


def test_sanitize_cell():
    for bad in ("=1+1", "+1", "-1", "@x", "\tx", "\rx"):
        assert sanitize_cell(bad) == "'" + bad
    assert sanitize_cell("zwykły") == "zwykły"
    assert sanitize_cell(5) == 5


def test_csv_pusty_magazyn_ma_naglowki(tmp_path):
    from org_intel.store import Store

    export_csv(Store(tmp_path / "s.json"), tmp_path / "e")
    assert (tmp_path / "e" / "persons.csv").read_text(encoding="utf-8-sig").startswith("id,name,role")


# --- logowanie ------------------------------------------------------------------------------


def test_mask_email():
    assert mask_email("jan.kowalski@example.test") == "j***@example.test"


def test_redact_wzorce():
    jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjMifQ.c2lnbmF0dXJl"
    text = redact(
        f"mail jan.kowalski@example.test jwt {jwt} Authorization: Bearer abc.def-123 hibp-api-key: 0123abcd "
        'password=Tajne123 token=xyz api_key="a b" hex 5f4dcc3b5aa765d61d8327deb882cf99 '
        "txt org-intel-verification=TOKEN_ABC"
    )
    for leaked in ("jan.kowalski", jwt, "abc.def-123", "0123abcd", "Tajne123", "xyz", "5f4dcc3b", "TOKEN_ABC"):
        assert leaked not in text, leaked
    assert "j***@example.test" in text


def test_logger_redaguje_email_i_token():
    stream = io.StringIO()
    handler = logging.StreamHandler(stream)  # celowo BEZ filtra: filtr siedzi na loggerze
    logger = get_logger("org_intel.test_redakcja")
    logger.setLevel(logging.INFO)
    logger.addHandler(handler)
    try:
        logger.info("kontakt %s, token=%s", "jan.kowalski@example.test", "sekret123")
        logger.info("Authorization: Bearer abcdef.ghijkl")
    finally:
        logger.removeHandler(handler)
    out = stream.getvalue()
    assert "jan.kowalski" not in out and "sekret123" not in out and "abcdef.ghijkl" not in out
    assert "j***@example.test" in out and "token=[REDACTED]" in out


def test_get_logger_idempotentny():
    a = get_logger("org_intel.idem")
    b = get_logger("org_intel.idem")
    assert a is b and len(a.filters) == 1
