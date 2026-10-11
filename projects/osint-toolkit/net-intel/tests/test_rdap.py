import copy
import json
from datetime import date, datetime, timezone

import pytest

from conftest import FakeFetch, FetchError, Response, fixture_text, ok, rdap_fetch
from net_intel.cli import main
from net_intel.models import Severity
from net_intel.rdap import Bootstrap, RdapError, evaluate, lookup, parse_rdap

TODAY = date(2026, 10, 3)
BASE = json.loads(fixture_text("rdap_domain.json"))
PRIVATE = ["Jan Prywatny Kowalski", "Prywatna Firma", "jan.kowalski", "anna.tech", "Anna Techniczna", "600100200",
           "ul. Tajna", "abuse@registrar", "registrar-private", "Abuse Desk", "5550100"]


def variant(expires: str | None = None, status: list[str] | None = None, **extra) -> dict:
    d = copy.deepcopy(BASE)
    if expires is not None:
        for ev in d["events"]:
            if ev["eventAction"] == "expiration":
                ev["eventDate"] = expires
    if status is not None:
        d["status"] = status
    d.update(extra)
    return d


def sev(findings, area):
    return [f.severity for f in findings if f.area == area]


def test_parse_fixture():
    r = parse_rdap(BASE, "example.org", TODAY, "rdap.example-pir.test")
    assert r.registrar == "Example Registrar, Inc." and r.registrar_iana_id == "9999"
    assert r.created.startswith("1995-08-14") and r.updated.startswith("2026-08-14") and r.expires.startswith("2027-08-13")
    assert r.nameservers == ["a.iana-servers.net", "b.iana-servers.net"]
    assert r.dnssec_signed is True and "client transfer prohibited" in r.status
    assert r.days_to_expiry == (datetime(2027, 8, 13, 4, tzinfo=timezone.utc) - datetime(2026, 10, 3, tzinfo=timezone.utc)).days


@pytest.mark.parametrize("expires,expected_sev", [
    ("2026-10-02T00:00:00Z", Severity.FAIL),    # wygasła wczoraj
    ("2025-01-01T00:00:00Z", Severity.FAIL),
    ("2026-10-03T12:00:00Z", Severity.FAIL),    # dziś
    ("2026-10-09T23:00:00Z", Severity.FAIL),    # 6 dni
    ("2026-10-10T00:00:00Z", Severity.WARN),    # dokładnie 7 dni
    ("2026-10-20T00:00:00Z", Severity.WARN),    # 17 dni
    ("2026-11-01T23:00:00Z", Severity.WARN),    # 29 dni
    ("2026-11-02T00:00:00Z", Severity.OK),      # dokładnie 30 dni
    ("2027-08-13T04:00:00Z", Severity.OK),
])
def test_expiry_thresholds(expires, expected_sev):
    r = parse_rdap(variant(expires=expires), "example.org", TODAY)
    assert sev(evaluate(r), "WAŻNOŚĆ") == [expected_sev]


def test_expired_title_mentions_days():
    r = parse_rdap(variant(expires="2026-09-23T00:00:00Z"), "example.org", TODAY)
    title = [f for f in evaluate(r) if f.area == "WAŻNOŚĆ"][0].title
    assert "wygasła" in title and r.days_to_expiry == -10


def test_today_accepts_datetime():
    r = parse_rdap(variant(expires="2026-10-10T00:00:00Z"), "example.org", datetime(2026, 10, 3, 12, tzinfo=timezone.utc))
    assert r.days_to_expiry == 6


def test_missing_expiry_is_info():
    d = variant()
    d["events"] = [e for e in d["events"] if e["eventAction"] != "expiration"]
    assert sev(evaluate(parse_rdap(d, "example.org", TODAY)), "WAŻNOŚĆ") == [Severity.INFO]


@pytest.mark.parametrize("hold", ["clientHold", "serverHold"])
def test_hold_status_warns(hold):
    r = parse_rdap(variant(status=["client transfer prohibited", hold]), "example.org", TODAY)
    assert Severity.WARN in sev(evaluate(r), "STATUS")


def test_pending_delete_warns():
    r = parse_rdap(variant(status=["pending delete", "redemptionPeriod"]), "example.org", TODAY)
    assert Severity.WARN in sev(evaluate(r), "STATUS")


def test_normal_status_ok_and_no_transfer_lock_info():
    assert sev(evaluate(parse_rdap(BASE, "example.org", TODAY)), "STATUS") == [Severity.OK]
    unlocked = parse_rdap(variant(status=["active"]), "example.org", TODAY)
    assert Severity.INFO in sev(evaluate(unlocked), "STATUS")


def test_dnssec_findings():
    unsigned = parse_rdap(variant(secureDNS={"delegationSigned": False}), "example.org", TODAY)
    assert sev(evaluate(unsigned), "DNSSEC") == [Severity.INFO]
    assert sev(evaluate(parse_rdap(BASE, "example.org", TODAY)), "DNSSEC") == [Severity.OK]


def test_registrant_data_not_in_parsed_result():
    r = parse_rdap(BASE, "example.org", TODAY)
    blob = json.dumps(r.to_dict(), ensure_ascii=False)
    for secret in PRIVATE:
        assert secret not in blob


def test_registrant_data_not_in_any_output(capsys, tmp_path):
    html_path = tmp_path / "r.html"
    f = rdap_fetch()
    for extra in (["--json"], [], ["--html", str(html_path)]):
        main(["rdap", "example.org", *extra], fetch=f, today=TODAY)
    out = capsys.readouterr().out + html_path.read_text(encoding="utf-8")
    assert "Example Registrar, Inc." in out
    for secret in PRIVATE:
        assert secret not in out


# --- bootstrap / fallback --------------------------------------------------------------------

def test_bootstrap_cached_and_prefers_https():
    f = rdap_fetch()
    b = Bootstrap(f, 5)
    assert b.base_url("example.org") == "https://rdap.example-pir.test/"
    assert b.base_url("www.example.org") == "https://rdap.example-pir.test/"
    assert b.base_url("example.pl") == "https://rdap.dns.pl/"
    assert b.base_url("example.xyz") is None
    assert sum("data.iana.org" in u for u in f.urls()) == 1


def test_lookup_uses_registry_url():
    f = rdap_fetch()
    r = lookup("example.org", f, 5, TODAY)
    assert r.found and r.source == "rdap.example-pir.test"
    assert f.urls()[-1] == "https://rdap.example-pir.test/domain/example.org"
    assert not any("rdap.org/" in u for u in f.urls())


def test_fallback_to_rdap_org_when_bootstrap_fails():
    f = FakeFetch().on("data.iana.org", FetchError("błąd sieci: x")).on("rdap.org/domain/example.org", ok("rdap_domain.json"))
    r = lookup("example.org", f, 5, TODAY)
    assert r.found and r.source == "rdap.org"


def test_fallback_when_registry_errors():
    f = FakeFetch().on("data.iana.org", ok("rdap_bootstrap.json")) \
        .on("rdap.example-pir.test", Response(503, "")).on("rdap.org/domain", ok("rdap_domain.json"))
    assert lookup("example.org", f, 5, TODAY).source == "rdap.org"


def test_fallback_when_tld_unknown():
    f = FakeFetch().on("data.iana.org", ok("rdap_bootstrap.json")).on("rdap.org/domain/example.xyz", ok("rdap_domain.json"))
    assert lookup("example.xyz", f, 5, TODAY).source == "rdap.org"


def test_404_is_not_found_not_fallback():
    f = FakeFetch().on("data.iana.org", ok("rdap_bootstrap.json")).on("rdap.example-pir.test", Response(404, ""))
    r = lookup("nieistnieje.org", f, 5, TODAY)
    assert r.found is False
    assert not any("rdap.org/domain" in u for u in f.urls())
    assert evaluate(r)[0].severity == Severity.WARN


def test_all_routes_fail_raises():
    f = FakeFetch().on("data.iana.org", Response(500, "")).on("rdap.org/domain", FetchError("przekroczono limit czasu"))
    with pytest.raises(RdapError) as ei:
        lookup("example.org", f, 5, TODAY)
    assert "bootstrap IANA" in str(ei.value) and "limit czasu" in str(ei.value)


def test_bad_json_from_registry_falls_back():
    f = FakeFetch().on("data.iana.org", ok("rdap_bootstrap.json")) \
        .on("rdap.example-pir.test", Response(200, "<html>")).on("rdap.org/domain", ok("rdap_domain.json"))
    assert lookup("example.org", f, 5, TODAY).source == "rdap.org"


# --- CLI -------------------------------------------------------------------------------------

def test_cli_rdap_json_ok(capsys):
    code = main(["rdap", "https://Example.org/x", "--json"], fetch=rdap_fetch(), today=date(2027, 8, 1))
    out = json.loads(capsys.readouterr().out)
    assert code == 1  # wygasa za 12 dni: WARN
    assert out["subject"] == "example.org" and out["counts"]["WARN"] == 1
    assert out["result"]["registrar"] == "Example Registrar, Inc."


def test_cli_rdap_exit_zero_when_healthy(capsys):
    assert main(["rdap", "example.org"], fetch=rdap_fetch(), today=TODAY) == 0
    assert "Example Registrar, Inc." in capsys.readouterr().out


def test_cli_rdap_failed_exit_1_and_message(capsys):
    f = FakeFetch().on("data.iana.org", FetchError("x")).on("rdap.org", FetchError("y"))
    code = main(["rdap", "example.org"], fetch=f, today=TODAY)
    assert code == 1 and "nie udało się sprawdzić" in capsys.readouterr().out


def test_cli_rdap_invalid_domain():
    assert main(["rdap", "not a domain"], fetch=FakeFetch()) == 2
