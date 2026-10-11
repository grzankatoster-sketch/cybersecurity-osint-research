"""Granica katalog (bez klucza) / platne API (klucz z env + zweryfikowana domena) oraz kontrakt dla org-intel.

Bez sieci (socket zablokowany), dane syntetyczne.
"""

from __future__ import annotations

import ast
import json
import socket
from pathlib import Path

import pytest
from conftest import FakeClient

from hibp_monitor.breaches import Breach, strip_html
from hibp_monitor.cli import main
from hibp_monitor.domain_search import ENV_KEY
from hibp_monitor.http import KEY_HOST, HibpError, HttpClient, Response, check_key_target

SRC = Path(__file__).resolve().parents[1] / "src" / "hibp_monitor"
CATALOG = "https://haveibeenpwned.com/api/v3/breaches"
SECRET = "fake-klucz-testowy-456"  # atrapa; slowo "fake" oznacza ja dla bramki sekretow  gitleaks:allow


@pytest.fixture(autouse=True)
def no_network(monkeypatch):
    def blocked(*args, **kwargs):
        raise AssertionError("socket zablokowany: test nie moze dotykac sieci")

    for name in ("connect", "connect_ex"):
        monkeypatch.setattr(socket.socket, name, blocked)
    monkeypatch.setattr(socket, "create_connection", blocked)
    monkeypatch.setattr(socket, "getaddrinfo", blocked)


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


# --- zakazane endpointy: breacheddomain tylko w domain_search.py (za kluczem) ----------------------------


def test_breacheddomain_tylko_w_domain_search_a_reszta_zakazanych_nigdzie():
    for path in sorted(SRC.glob("*.py")):
        blob = "\n".join(_code_strings(path)).lower()
        for word in ("breachedaccount", "pasteaccount", "stealerlogs"):
            assert word not in blob, (path.name, word)
        assert ("breacheddomain" in blob) == (path.name == "domain_search.py"), path.name


def test_modul_nie_loguje_nic():
    """Brak modulu logging: klucz API nie ma jak trafic do logow (komunikaty tylko przez print z safe_text)."""
    for path in sorted(SRC.glob("*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        imported = {a.name for n in ast.walk(tree) if isinstance(n, ast.Import) for a in n.names}
        imported |= {n.module for n in ast.walk(tree) if isinstance(n, ast.ImportFrom) and n.module}
        assert "logging" not in imported, path.name


def test_klucz_tylko_ze_zmiennej_srodowiskowej_nie_z_argumentow_cli():
    for flag in ("--api-key", "--key", "--hibp-api-key"):
        with pytest.raises(SystemExit) as err:
            main(["domain-search", "example.com", flag, SECRET], client=FakeClient(), environ={ENV_KEY: SECRET})
        assert err.value.code == 2


# --- katalog i monitor domen: bez klucza, nawet gdy jest w srodowisku ---------------------------------------


def test_katalog_i_monitor_nie_wysylaja_klucza_nawet_z_env(monkeypatch, tmp_path, capsys):
    monkeypatch.setenv(ENV_KEY, SECRET)
    c = FakeClient(default=Response(200, "[]"))
    assert main(["breaches", "--catalog", "--json"], client=c) == 0
    assert main(["breaches", "--domain", "example.com", "--state", str(tmp_path / "s.json")], client=c) == 0
    assert [u for u, _ in c.calls] == [CATALOG, CATALOG + "?domain=example.com"]
    for _, headers in c.calls:
        assert {k.lower() for k in headers} == {"accept"}
    cap = capsys.readouterr()
    assert SECRET not in cap.out + cap.err


def test_katalog_przez_httpclient_wysyla_tylko_user_agent_i_accept(monkeypatch):
    monkeypatch.setenv(ENV_KEY, SECRET)
    seen = []

    def transport(url, headers, timeout):
        seen.append((url, headers))
        return Response(200, "[]")

    from hibp_monitor.breaches import fetch_catalog

    fetch_catalog(HttpClient("ua/1", transport=transport))
    assert seen[0][0] == CATALOG and set(seen[0][1]) == {"User-Agent", "Accept"}


# --- platne API: klucz tylko do haveibeenpwned.com po https:443 --------------------------------------------


@pytest.mark.parametrize(
    "url, fragment",
    [
        ("http://haveibeenpwned.com/api/v3/breacheddomain/example.com", "https"),
        ("https://evil.test/api/v3/breacheddomain/example.com", "evil.test"),
        ("https://haveibeenpwned.com.evil.test/x", "haveibeenpwned.com.evil.test"),
        ("https://user:pw@haveibeenpwned.com/x", "logowania"),
        ("https://haveibeenpwned.com:8443/x", "8443"),
    ],
)
def test_klucz_nie_moze_trafic_pod_obcy_adres(url, fragment):
    with pytest.raises(HibpError) as err:
        check_key_target(url)
    assert fragment in str(err.value) and SECRET not in str(err.value)
    calls = []
    client = HttpClient("ua/1", transport=lambda u, h, t: calls.append(u) or Response(200, "{}"))
    with pytest.raises(HibpError):
        client.get(url, {"hibp-api-key": SECRET})
    assert calls == []  # zadnego zapytania z kluczem


def test_klucz_dozwolony_tylko_dla_hosta_hibp():
    check_key_target(f"https://{KEY_HOST}/api/v3/breacheddomain/example.com")
    check_key_target(f"https://{KEY_HOST}:443/api/v3/breacheddomain/example.com")


@pytest.mark.parametrize("status", [200, 401, 403, 404, 500])
@pytest.mark.parametrize("extra", [[], ["--json"], ["--show-addresses"]])
def test_klucz_nie_wycieka_do_wyjscia_cli(status, extra, capsys):
    body = json.dumps({"alice": ["Adobe"]}) if status == 200 else ""
    c = FakeClient({"https://haveibeenpwned.com/api/v3/breacheddomain/": Response(status, body)})
    main(["domain-search", "example.com", *extra], client=c, environ={ENV_KEY: SECRET})
    cap = capsys.readouterr()
    assert SECRET not in cap.out + cap.err
    assert c.calls[0][1]["hibp-api-key"] == SECRET  # klucz poszedl tylko w naglowku


def test_domain_search_bez_klucza_zero_ruchu_nawet_z_pustym_kluczem(capsys):
    c = FakeClient()
    for env in ({}, {ENV_KEY: ""}, {ENV_KEY: "   "}):
        assert main(["domain-search", "example.com"], client=c, environ=env) == 2
    assert c.calls == []


# --- kontrakt dla org-intel: `breaches --catalog --json` --------------------------------------------------

API = [
    {
        "Name": "FakeList",
        "Title": "Fake <b>List</b>",
        "Domain": "fake.example.test",
        "BreachDate": "2026-07-01",
        "AddedDate": "2026-07-02T08:00:00Z",
        "ModifiedDate": "2026-07-03T08:00:00Z",
        "PwnCount": 9,
        "DataClasses": ["Email addresses"],
        "Description": "<p>Zmyslona.</p><p>Lista.</p>",
        "LogoPath": "x.png",
        "IsVerified": False,
        "IsFabricated": True,
        "IsSpamList": True,
        "IsMalware": "false",
        "IsStealerLog": "true",
    },
]


def test_katalog_json_niesie_wszystkie_flagi_jakosci_i_opis_bez_html(capsys):
    c = FakeClient({CATALOG: Response(200, json.dumps(API))})
    assert main(["breaches", "--catalog", "--json", "--limit", "0"], client=c) == 0
    (rec,) = json.loads(capsys.readouterr().out)["breaches"]
    assert rec["is_fabricated"] is True and rec["is_spam_list"] is True and rec["is_verified"] is False
    assert rec["is_malware"] is False  # tekst "false" nie jest prawda
    assert rec["is_stealer_log"] is True
    assert rec["modified_date"] == "2026-07-03T08:00:00Z"
    assert rec["description"] == "Zmyslona. Lista."
    assert "LogoPath" not in rec and "logo_path" not in rec  # pola spoza listy nie sa przekazywane


def test_strip_html_nie_skleja_slow_na_granicy_blokow():
    assert strip_html("<p>a@b.test</p><p>c</p>") == "a@b.test c"
    assert strip_html("Lista <b>zmyslona</b>.") == "Lista zmyslona."
    assert Breach.from_api({"Name": "X", "IsVerified": "false"}).is_verified is False
