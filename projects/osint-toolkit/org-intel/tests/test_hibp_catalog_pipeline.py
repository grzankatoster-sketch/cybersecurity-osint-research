"""Sciezka: publiczny katalog metadanych HIBP -> org-intel (incydenty, zrodlo hibp_catalog). Bez sieci, dane syntetyczne.

Pokrywa: dozwolone pola, odrzucanie pol kont/e-mail/sekretow, maskowanie e-maili w opisie, minimalizacje cache,
proweniencje (url, retrieved_at, content_hash, ETag), idempotencje, tryb audytowy, brak klucza API i zakazanych
endpointow. Cache TTL, 429 i Retry-After testuje test_verify_hibp.py.
"""

from __future__ import annotations

import ast
import contextlib
import hashlib
import importlib
import io
import json
import logging
import socket
import sys
from datetime import UTC, datetime
from pathlib import Path
from types import SimpleNamespace

import pytest
from conftest import FakeClient, ForbiddenClient

from org_intel import guards
from org_intel.cli import EXIT_NETWORK, EXIT_OK, EXIT_PARTIAL, EXIT_USAGE, main
from org_intel.hibp_catalog import (
    CACHE_FILE,
    CATALOG_FIELDS,
    CATALOG_URL,
    ConfigError,
    HibpCatalogClient,
    minimize_catalog,
)
from org_intel.http import Response
from org_intel.logging_redact import get_logger, mask_emails
from org_intel.models import IncidentStatus, SourceType
from org_intel.parsers import CatalogMeta, clean_description, parse_data, parse_hibp_catalog
from org_intel.store import Store

SRC = Path(__file__).resolve().parents[1] / "src" / "org_intel"
MONITOR_SRC = Path(__file__).resolve().parents[2] / "hibp-monitor" / "src"
UA = "test-firma org-intel/0.1 (kontakt@example.test)"
API_KEY = "fake-hibp-key-0123456789"  # atrapa; slowo "fake" oznacza ja dla bramki sekretow  gitleaks:allow
EMAIL = "jan.kowalski@example.test"
NOW = datetime(2026, 10, 5, 12, 0, 0, tzinfo=UTC)
FORBIDDEN_ENDPOINTS = ("breachedaccount", "pasteaccount", "stealerlogs", "breacheddomain")


@pytest.fixture(autouse=True)
def no_network(monkeypatch):
    def blocked(*args, **kwargs):
        raise AssertionError("socket zablokowany: test nie moze dotykac sieci")

    monkeypatch.setattr(socket.socket, "connect", blocked)
    monkeypatch.setattr(socket.socket, "connect_ex", blocked)
    monkeypatch.setattr(socket, "create_connection", blocked)
    monkeypatch.setattr(socket, "getaddrinfo", blocked)


@pytest.fixture(autouse=True)
def no_sleep(monkeypatch):
    """Odstep miedzy zapytaniami i Retry-After nie maja czekac naprawde (domyslny sleep konektora)."""
    monkeypatch.setitem(HibpCatalogClient.__init__.__kwdefaults__, "sleep", lambda seconds: None)


def catalog() -> list[dict]:
    """Syntetyczny katalog w formacie API (PascalCase): 5 rekordow poprawnych + 2 z polami kont."""
    common = {"Description": "Opis.", "DataClasses": ["Email addresses"], "IsSubscriptionFree": False}
    return [
        {
            **common,
            "Name": "VerifiedCo",
            "Title": "Verified Co",
            "Domain": "verified.example.test",
            "BreachDate": "2026-05-01",
            "AddedDate": "2026-05-03T10:00:00Z",
            "ModifiedDate": "2026-05-04T10:00:00Z",
            "PwnCount": 1200,
            "IsVerified": True,
            "LogoPath": "https://logos.example.test/verified.png",
            "Attribution": "nie kopiujemy",
        },
        {
            **common,
            "Name": "FakeList",
            "Domain": "fake.example.test",
            "PwnCount": 10,
            "IsFabricated": True,
            "IsSpamList": True,
        },
        {**common, "Name": "SensitiveDemo", "PwnCount": 5, "IsVerified": True, "IsSensitive": True},
        {**common, "Name": "OldRetired", "PwnCount": 7, "IsVerified": True, "IsRetired": True},
        {
            **common,
            "Name": "StealerMeta",
            "PwnCount": 99,
            "DataClasses": ["Passwords", "Auth tokens"],
            "IsVerified": True,
            "IsMalware": True,
            "IsStealerLog": True,
        },
        {
            **common,
            "Name": "HtmlMailDemo",
            "Title": f"Demo ({EMAIL})",
            "Domain": "html.example.test",
            "PwnCount": 3,
            "IsVerified": "false",  # tekst "false" nie jest prawda
            "Description": f'<p>Kontakt: <a href="mailto:{EMAIL}">{EMAIL}</a></p><b>Opis</b> &amp; reszta.',
        },
        {**common, "Name": "WithEmails", "PwnCount": 2, "Emails": [EMAIL], "IsVerified": True},
        {**common, "Name": "WithAccounts", "PwnCount": 2, "Accounts": [{"email": EMAIL}], "IsVerified": True},
    ]


def body_of(items) -> str:
    return json.dumps(items)


def run(*argv, **kw):
    out = io.StringIO()
    code = main([str(a) for a in argv], out=out, now=NOW, **kw)
    return code, out.getvalue()


def fetch_args(store_path, *extra):
    return ["fetch-hibp-catalog", "--online", "--user-agent", UA, "--store", store_path, *extra]


@pytest.fixture
def store_path(tmp_path) -> Path:
    return tmp_path / "data" / "store.json"


def statuses(store: Store, name: str) -> set[str]:
    inc = next(i for i in store.incidents.values() if i.name == name)
    return {s.value for s in inc.status}


# --- testy statyczne: zakazane endpointy, brak klucza API ---------------------------------------------


def _code_strings(path: Path) -> list[str]:
    tree = ast.parse(path.read_text(encoding="utf-8"))
    docstrings = set()
    for node in ast.walk(tree):
        if isinstance(node, (ast.Module, ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)) and node.body:
            first = node.body[0]
            if isinstance(first, ast.Expr) and isinstance(first.value, ast.Constant):
                docstrings.add(id(first.value))
    return [
        n.value
        for n in ast.walk(tree)
        if isinstance(n, ast.Constant) and isinstance(n.value, str) and id(n) not in docstrings
    ]


def test_zaden_modul_org_intel_nie_zawiera_zakazanych_endpointow():
    for path in sorted(SRC.glob("*.py")):
        for text in _code_strings(path):
            assert not any(word in text.lower() for word in FORBIDDEN_ENDPOINTS), (path.name, text[:60])


def test_konektor_ma_jeden_adres_i_zero_odwolan_do_klucza_api():
    strings = _code_strings(SRC / "hibp_catalog.py")
    urls = [s for s in strings if s.startswith(("http://", "https://")) or "/api/" in s]
    assert urls == [CATALOG_URL] == ["https://haveibeenpwned.com/api/v3/breaches"]
    tree = ast.parse((SRC / "hibp_catalog.py").read_text(encoding="utf-8"))
    names = {n.attr for n in ast.walk(tree) if isinstance(n, ast.Attribute)} | {
        n.id for n in ast.walk(tree) if isinstance(n, ast.Name)
    }
    assert not names & {"environ", "getenv"}
    for path in (SRC / "hibp_catalog.py", SRC / "parsers.py", SRC / "cli.py", SRC / "store.py"):
        assert not any("api-key" in s.lower() or "api_key" in s.lower() for s in _code_strings(path)), path.name


@pytest.mark.parametrize("flag", ["--api-key", "--hibp-api-key", "--key"])
def test_cli_nie_przyjmuje_klucza_api(flag, store_path):
    with pytest.raises(SystemExit) as err:
        main(["fetch-hibp-catalog", "--online", "--user-agent", UA, flag, API_KEY, "--store", str(store_path)])
    assert err.value.code == 2


def test_klucz_api_ze_srodowiska_nigdy_nie_trafia_do_zapytania(store_path, monkeypatch):
    monkeypatch.setenv("HIBP_API_KEY", API_KEY)
    client = FakeClient(Response(200, body_of(catalog())))
    code, text = run(*fetch_args(store_path), client=client)
    assert code == EXIT_PARTIAL
    assert [url for url, _ in client.calls] == [CATALOG_URL]
    headers = client.calls[0][1]
    assert set(headers) == {"User-Agent", "Accept"}
    assert API_KEY not in json.dumps(headers) and API_KEY not in text
    stored = store_path.read_text(encoding="utf-8") + (store_path.parent / "cache" / CACHE_FILE).read_text(
        encoding="utf-8"
    )
    assert API_KEY not in stored


def test_user_agent_bez_znakow_sterujacych(tmp_path):
    for bad in ("firma\r\nhibp-api-key: x", "firma\x00", "x" * 201):
        with pytest.raises(ConfigError):
            HibpCatalogClient(bad, tmp_path)


# --- tryb online: zero wywolan bez --online -----------------------------------------------------------


def test_online_wymagane_kod_2_zero_wywolan_i_zero_plikow(store_path):
    client = ForbiddenClient()
    code, _ = run("fetch-hibp-catalog", "--user-agent", UA, "--store", store_path, client=client)
    assert code == EXIT_USAGE and client.calls == 0
    assert not store_path.exists() and not (store_path.parent / "cache").exists()


# --- parser: dozwolone pola, pola kont, e-maile ---------------------------------------------------------


def test_parser_flagi_jakosci_i_pola_poza_lista():
    r = parse_hibp_catalog(catalog(), now=NOW)
    by = {i.name: i for i in r.incidents}
    assert {s.value for s in by["VerifiedCo"].status} == {"verified"}
    assert {s.value for s in by["FakeList"].status} == {"fabricated", "spam_list"}
    assert {s.value for s in by["SensitiveDemo"].status} == {"verified", "sensitive"}
    assert {s.value for s in by["OldRetired"].status} == {"verified", "retired"}
    assert {s.value for s in by["StealerMeta"].status} == {"verified", "malware", "stealer_log"}
    assert by["HtmlMailDemo"].status == []  # "false" jako tekst != prawda
    assert (
        by["VerifiedCo"].affected_accounts_count == 1200 and by["VerifiedCo"].affected_domain == "verified.example.test"
    )
    assert by["VerifiedCo"].incident_date == "2026-05-01" and by["VerifiedCo"].published_date == "2026-05-03T10:00:00Z"
    dumped = json.dumps([i.to_dict() for i in r.incidents] + [o.to_dict() for o in r.observations])
    assert "LogoPath" not in dumped and "logos.example.test" not in dumped and "Attribution" not in dumped
    mod_notes = [o.notes for o in r.observations if "2026-05-04" in o.notes]
    assert mod_notes and mod_notes[0].startswith("zmodyfikowano w katalogu")


@pytest.mark.parametrize(
    "extra",
    [{"Emails": ["a@b.test"]}, {"Accounts": []}, {"EmailAddresses": "x"}, {"Passwords": ["x"]}, {"api_key": "x"}],
)
def test_rekord_z_polami_kont_lub_sekretow_jest_odrzucany_reszta_zostaje(extra):
    data = catalog()[:2] + [{"Name": "Bad", "PwnCount": 1, **extra}]
    r = parse_hibp_catalog(data, now=NOW)
    assert [i.name for i in r.incidents] == ["VerifiedCo", "FakeList"]
    assert len(r.rejections) == 1 and r.rejections[0].label.endswith("Bad")
    assert guards.catalog_forbidden_key(next(iter(extra))) is not None


def test_dozwolone_klucze_katalogu_nie_sa_zakazane():
    for key in list(CATALOG_FIELDS) + list(CATALOG_FIELDS.values()) + ["LogoPath", "Attribution", "IsSubscriptionFree"]:
        assert guards.catalog_forbidden_key(key) is None, key


def test_email_w_opisie_i_tytule_jest_maskowany_a_html_usuniety():
    r = parse_hibp_catalog(catalog(), now=NOW)
    inc = next(i for i in r.incidents if i.name == "HtmlMailDemo")
    assert EMAIL not in inc.description and EMAIL not in inc.title
    assert "j***@example.test" in inc.description and "j***@example.test" in inc.title
    assert "<" not in inc.description and "&amp;" not in inc.description
    assert inc.description == "Kontakt: j***@example.test Opis & reszta."


def test_opis_maks_2000_i_maskowanie_przed_obcieciem():
    long = clean_description("<p>" + ("x " * 3000) + EMAIL + "</p>")
    assert len(long) <= 2000 and EMAIL not in long
    assert mask_emails(f"a {EMAIL} b") == "a j***@example.test b"


def test_nazwa_incydentu_z_emailem_odrzucona():
    r = parse_hibp_catalog([{"Name": EMAIL, "PwnCount": 1}, {"Name": "Ok"}], now=NOW)
    assert [i.name for i in r.incidents] == ["Ok"] and len(r.rejections) == 1


def test_dziwny_etag_nie_wywraca_zrodla_zostaje_hash():
    sha = hashlib.sha256(b"x").hexdigest()
    r = parse_hibp_catalog(catalog()[:1], now=NOW, meta=CatalogMeta(sha, "online", etag="x@example.test:hunter22"))
    src = r.sources[0]
    assert src.content_hash == sha and "ETag" not in src.notes and src.source_type is SourceType.HIBP_CATALOG


def test_minimize_catalog_zostawia_tylko_dozwolone_pola():
    kept, rejected = minimize_catalog(catalog() + ["nie obiekt"])
    assert len(kept) == 6 and len(rejected) == 3
    allowed = set(CATALOG_FIELDS)
    assert all(set(rec) <= allowed for rec in kept)
    assert EMAIL not in json.dumps(kept)
    assert {r["label"] for r in rejected} == {"WithEmails", "WithAccounts", "breaches[8]"}


# --- oba formaty wejscia ----------------------------------------------------------------------------------


@pytest.fixture
def monitor_main():
    """Prawdziwy kod hibp-monitor (bez sieci: atrapa klienta); pomijany, gdy pakietu nie ma obok."""
    if not MONITOR_SRC.exists():
        pytest.skip("brak hibp-monitor/src obok org-intel")
    sys.path.insert(0, str(MONITOR_SRC))
    try:
        yield importlib.import_module("hibp_monitor.cli").main
    finally:
        sys.path.remove(str(MONITOR_SRC))
        for name in [m for m in sys.modules if m == "hibp_monitor" or m.startswith("hibp_monitor.")]:
            del sys.modules[name]


class MonitorClient:
    def __init__(self, text):
        self.text, self.calls = text, []

    def get(self, url, headers=None):
        self.calls.append((url, dict(headers or {})))
        return SimpleNamespace(status=200, text=self.text, headers={})


def test_oba_formaty_daja_te_same_incydenty(monitor_main, tmp_path):
    good = [rec for rec in catalog() if "Emails" not in rec and "Accounts" not in rec]
    client = MonitorClient(body_of(good))
    buf = io.StringIO()
    assert monitor_main(["breaches", "--catalog", "--json", "--limit", "0"], client=client, out=buf) == 0
    assert client.calls[0][0] == CATALOG_URL and "hibp-api-key" not in {k.lower() for k in client.calls[0][1]}
    monitor_json = json.loads(buf.getvalue())
    assert monitor_json["total"] == len(good) == len(monitor_json["breaches"])

    api = parse_data(good, now=NOW)
    mon = parse_data(monitor_json, now=NOW)
    assert (api.format, mon.format) == ("hibp_api", "hibp_monitor")
    assert not api.rejections and not mon.rejections

    def key(i):
        return (i.name, i.title, i.affected_domain, i.incident_date, i.published_date, i.affected_accounts_count,
                tuple(i.data_classes), tuple(s.value for s in i.status), i.description)  # fmt: skip

    assert sorted(map(key, api.incidents)) == sorted(map(key, mon.incidents))
    flags = {i.name: {s.value for s in i.status} for i in mon.incidents}
    assert flags["FakeList"] == {"fabricated", "spam_list"} and "stealer_log" in flags["StealerMeta"]
    assert EMAIL not in json.dumps([i.to_dict() for i in mon.incidents])

    # ingest z pliku wygenerowanego przez hibp-monitor: ten sam wynik w magazynie co z surowego API
    f = tmp_path / "monitor.json"
    f.write_text(buf.getvalue(), encoding="utf-8")
    code, _ = run("ingest", f, "--store", tmp_path / "s.json")
    assert code == EXIT_OK
    assert statuses(Store.load(tmp_path / "s.json"), "StealerMeta") == {"verified", "malware", "stealer_log"}


# --- magazyn, proweniencja, idempotencja ---------------------------------------------------------------------


def test_fetch_zapisuje_tylko_metadane_i_proweniencje(store_path):
    body = body_of(catalog())
    headers = {"ETag": 'W/"0a1b2c3d4e5f60718293a4b5c6d7e8f9"', "Last-Modified": "Mon, 05 Oct 2026 10:00:00 GMT"}
    client = FakeClient(Response(200, body, headers))
    code, text = run(*fetch_args(store_path), client=client)
    assert code == EXIT_PARTIAL  # 2 rekordy z polami kont odrzucone, reszta zapisana
    assert "ODRZUCONO WithEmails" in text and "ODRZUCONO WithAccounts" in text
    assert [h["User-Agent"] for _, h in client.calls] == [UA]

    store = Store.load(store_path)
    assert sorted(i.name for i in store.incidents.values()) == [
        "FakeList", "HtmlMailDemo", "OldRetired", "SensitiveDemo", "StealerMeta", "VerifiedCo"
    ]  # fmt: skip
    (src,) = store.sources.values()
    sha = hashlib.sha256(body.encode("utf-8")).hexdigest()
    assert src.source_type is SourceType.HIBP_CATALOG and src.url == CATALOG_URL
    assert src.content_hash == sha
    wrapper_time = json.loads((store_path.parent / "cache" / CACHE_FILE).read_text(encoding="utf-8"))["fetched_at"]
    assert src.retrieved_at == datetime.fromtimestamp(wrapper_time, UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
    assert (
        "Pochodzenie: online" in src.notes
        and "ETag: W/" in src.notes
        and "Last-Modified: Mon, 05 Oct 2026" in src.notes
    )
    assert "bez danych kont" in src.notes
    assert all(o.evidence_hash == sha and o.source_id == src.id for o in store.observations.values())
    assert all(
        o.evidence_url.startswith("https://haveibeenpwned.com/PwnedWebsites#") for o in store.observations.values()
    )

    on_disk = store_path.read_text(encoding="utf-8")
    cache_text = (store_path.parent / "cache" / CACHE_FILE).read_text(encoding="utf-8")
    for blob in (on_disk, cache_text):
        assert EMAIL not in blob and "logos.example.test" not in blob
        assert "Attribution" not in blob
    assert "Emails" not in on_disk and "Accounts" not in on_disk
    assert "LogoPath" not in cache_text  # w magazynie tylko w notatce zrodla ("bez LogoPath")
    wrapper = json.loads(cache_text)
    assert "Emails" not in wrapper["body"] and "Accounts" not in wrapper["body"]  # tylko w powodach odrzucen
    assert wrapper["minimized"] is True and wrapper["content_hash"] == sha
    assert {r["label"] for r in wrapper["rejected"]} == {"WithEmails", "WithAccounts"}
    assert not (store_path.parent / "raw").exists()  # surowe rekordy tylko po jawnym --audit-mode


def test_fetch_idempotentny_drugi_raz_z_cache_ten_sam_magazyn(store_path):
    client = FakeClient(Response(200, body_of(catalog()), {"ETag": '"v1"'}))
    run(*fetch_args(store_path), client=client)
    first = store_path.read_bytes()
    code, text = run(*fetch_args(store_path), client=client)
    assert code == EXIT_PARTIAL and "cache" in text and len(client.calls) == 1
    assert store_path.read_bytes() == first


def test_ingest_pliku_idempotentny_i_z_hashem_pliku(store_path, tmp_path):
    f = tmp_path / "katalog.json"
    f.write_text(body_of(catalog()), encoding="utf-8")
    run("ingest", f, "--store", store_path)
    first = store_path.read_bytes()
    code, _ = run("ingest", f, "--store", store_path)
    assert code == EXIT_PARTIAL and store_path.read_bytes() == first
    (src,) = Store.load(store_path).sources.values()
    assert src.content_hash == hashlib.sha256(f.read_bytes()).hexdigest() and "plik lokalny" in src.notes
    assert str(tmp_path) not in store_path.read_text(encoding="utf-8")  # zadnej sciezki pliku w magazynie


def test_wszystkie_rekordy_odrzucone_nie_zostawia_incydentow(store_path):
    client = FakeClient(Response(200, body_of([{"Name": "X", "Emails": [EMAIL]}])))
    code, _ = run(*fetch_args(store_path), client=client)
    assert code == EXIT_USAGE
    assert not store_path.exists() or not Store.load(store_path).incidents


def test_stary_cache_z_surowym_cialem_jest_ignorowany(tmp_path):
    cache = tmp_path / "cache"
    cache.mkdir()
    raw = body_of(catalog())
    (cache / CACHE_FILE).write_text(
        json.dumps({"fetched_at": 1_000_000.0, "url": CATALOG_URL, "body": raw}), encoding="utf-8"
    )
    client = FakeClient(Response(200, body_of(catalog()[:1])))
    conn = HibpCatalogClient(UA, cache, client=client, clock=lambda: 1_000_100.0, sleep=lambda s: None)
    out = conn.fetch()
    assert not out.from_cache and len(client.calls) == 1
    assert EMAIL not in (cache / CACHE_FILE).read_text(encoding="utf-8")


def test_blad_sieci_kod_3_nic_nie_zapisane(store_path):
    code, _ = run(*fetch_args(store_path), client=FakeClient(Response(500, "")))
    assert code == EXIT_NETWORK and not store_path.exists()


# --- tryb audytowy ------------------------------------------------------------------------------------------


def _raw_blob(store_path: Path) -> str:
    files = list((store_path.parent / "raw").glob("*.json"))
    assert len(files) == 1
    return files[0].read_text(encoding="utf-8")


@pytest.mark.parametrize("via", ["ingest", "fetch"])
def test_audit_mode_zapisuje_tylko_dozwolone_pola(via, store_path, tmp_path):
    if via == "ingest":
        f = tmp_path / "k.json"
        f.write_text(body_of(catalog()), encoding="utf-8")
        run("ingest", f, "--store", store_path, "--audit-mode")
    else:
        run(*fetch_args(store_path, "--audit-mode"), client=FakeClient(Response(200, body_of(catalog()))))
    blob = _raw_blob(store_path)
    records = [r["record"] for r in json.loads(blob)["records"]]
    assert len(records) == 6
    assert all(set(rec) <= set(CATALOG_FIELDS) for rec in records)
    for forbidden in ("LogoPath", "Emails", "Accounts", EMAIL, "Attribution"):
        assert forbidden not in blob


@pytest.mark.parametrize("via", ["ingest", "fetch"])
def test_bez_audit_mode_nie_ma_katalogu_raw(via, store_path, tmp_path):
    if via == "ingest":
        f = tmp_path / "k.json"
        f.write_text(body_of(catalog()), encoding="utf-8")
        run("ingest", f, "--store", store_path)
    else:
        run(*fetch_args(store_path), client=FakeClient(Response(200, body_of(catalog()))))
    assert not (store_path.parent / "raw").exists()


# --- logi bez sekretow --------------------------------------------------------------------------------------------


def test_logi_nie_zawieraja_klucza_ani_e_maili(store_path, caplog, monkeypatch):
    monkeypatch.setenv("HIBP_API_KEY", API_KEY)
    caplog.set_level(logging.DEBUG)
    run(*fetch_args(store_path), client=FakeClient(Response(429, "", {"Retry-After": "0"})))
    run(
        *fetch_args(store_path),
        client=FakeClient([Response(429, "", {"Retry-After": "0"}), Response(200, body_of(catalog()))]),
    )
    run(*fetch_args(store_path), client=FakeClient(Response(200, body_of(catalog()))))  # cache
    assert caplog.records
    for blob in (caplog.text, "".join(r.getMessage() for r in caplog.records)):
        assert API_KEY not in blob and EMAIL not in blob and "kontakt@example.test" not in blob


def test_logger_redaguje_klucz_i_email(caplog):
    caplog.set_level(logging.INFO)
    log = get_logger("org_intel.hibp_catalog")
    log.info("naglowki: hibp-api-key: %s, kontakt %s", API_KEY, EMAIL)
    text = caplog.text
    assert API_KEY not in text and EMAIL not in text and "[REDACTED]" in text and "j***@example.test" in text


def test_stdout_i_stderr_cli_bez_klucza(store_path, capsys, monkeypatch):
    monkeypatch.setenv("HIBP_API_KEY", API_KEY)
    with contextlib.redirect_stdout(io.StringIO()):
        main([str(a) for a in fetch_args(store_path)], client=FakeClient(Response(500, "")))
    cap = capsys.readouterr()
    assert API_KEY not in cap.out + cap.err and "kontakt@example.test" not in cap.out + cap.err


def test_status_enum_zawiera_flagi_katalogu():
    assert {s.value for s in IncidentStatus} == {
        "verified", "fabricated", "spam_list", "sensitive", "retired", "malware", "stealer_log"
    }  # fmt: skip
