from __future__ import annotations

import json
from datetime import datetime, timezone

import pytest
from conftest import FakeClient, fixture_text

from hibp_monitor.breaches import (
    Breach, check_domain, empty_state, fetch_catalog, fetch_domain_breaches, find_new, load_config,
    load_state, normalize_domain, parse_breaches, save_state, update_state,
)
from hibp_monitor.cli import main
from hibp_monitor.http import HibpError, Response

BASE = "https://haveibeenpwned.com/api/v3/breaches"


def test_parse_breaches_fields():
    (b,) = parse_breaches(fixture_text("breaches_adobe.json"))
    assert b.name == "Adobe" and b.domain == "adobe.com"
    assert b.added_date == "2013-12-04T00:00:00Z"
    assert b.pwn_count == 152445165
    assert "Passwords" in b.data_classes and b.is_verified


def test_parse_breaches_rejects_garbage():
    with pytest.raises(HibpError):
        parse_breaches("<html>nie json</html>")
    with pytest.raises(HibpError):
        parse_breaches('{"Name": "x"}')


def test_normalize_domain():
    assert normalize_domain(" Adobe.COM. ") == "adobe.com"
    for bad in ("", "nodot", "a b.com", "http://adobe.com", "-x.com"):
        with pytest.raises(ValueError):
            normalize_domain(bad)


def test_fetch_domain_sends_domain_query_and_handles_404():
    c = FakeClient({BASE: Response(200, fixture_text("breaches_adobe.json"))})
    assert len(fetch_domain_breaches(c, "Adobe.com")) == 1
    assert c.calls[0][0] == BASE + "?domain=adobe.com"
    assert fetch_domain_breaches(FakeClient(default=Response(404)), "nic.example") == []
    with pytest.raises(HibpError):
        fetch_domain_breaches(FakeClient(default=Response(500)), "adobe.com")


def test_fetch_catalog_uses_plain_endpoint():
    c = FakeClient({BASE: Response(200, fixture_text("breaches_adobe.json"))})
    assert len(fetch_catalog(c)) == 1
    assert c.calls[0][0] == BASE


def test_first_run_reports_everything_then_nothing():
    c = FakeClient({BASE: Response(200, fixture_text("breaches_adobe.json"))})
    state = empty_state()
    r1 = check_domain(c, state, "adobe.com")
    assert r1.first_run and [b.name for b in r1.new] == ["Adobe"]
    r2 = check_domain(c, state, "adobe.com")
    assert not r2.first_run and r2.new == [] and r2.total == 1
    assert state["domains"]["adobe.com"]["last_added"] == "2013-12-04T00:00:00Z"


def test_diff_reports_only_new_breach():
    state = empty_state()
    check_domain(FakeClient({BASE: Response(200, fixture_text("breaches_adobe.json"))}), state, "adobe.com")
    c2 = FakeClient({BASE: Response(200, fixture_text("breaches_adobe_v2.json"))})
    r = check_domain(c2, state, "adobe.com")
    assert [b.name for b in r.new] == ["FikcyjnyNowy"]
    assert state["domains"]["adobe.com"]["last_added"] == "2026-09-20T10:00:00Z"
    assert state["domains"]["adobe.com"]["seen"] == ["Adobe", "FikcyjnyNowy"]


def test_find_new_by_added_date_watermark():
    old = Breach(name="Stary", added_date="2020-01-01T00:00:00Z")
    fresh = Breach(name="Stary", added_date="2026-01-01T00:00:00Z")  # ta sama nazwa, pozniejszy AddedDate
    ds = {"seen": ["Stary"], "last_added": "2020-01-01T00:00:00Z"}
    assert find_new(ds, [old]) == []
    assert find_new(ds, [fresh]) == [fresh]


def test_state_roundtrip_and_corruption(tmp_path):
    p = tmp_path / "sub" / "state.json"
    st = empty_state()
    update_state(st, "adobe.com", parse_breaches(fixture_text("breaches_adobe.json")),
                 now=datetime(2026, 10, 3, 12, 0, tzinfo=timezone.utc))
    save_state(p, st)
    assert load_state(p) == st
    assert st["domains"]["adobe.com"]["last_run"] == "2026-10-03T12:00:00Z"
    assert not list(p.parent.glob("*.tmp"))
    assert load_state(tmp_path / "brak.json") == empty_state()
    p.write_text("{ zepsute", encoding="utf-8")
    with pytest.raises(HibpError):
        load_state(p)


def test_load_config(tmp_path):
    cfg = tmp_path / "config.toml"
    cfg.write_text('user_agent = "x/1"\ndomains = ["Adobe.com"]\nstate_file = "s.json"\n', encoding="utf-8")
    c = load_config(cfg)
    assert c["domains"] == ["adobe.com"] and c["user_agent"] == "x/1" and c["state_file"] == tmp_path / "s.json"
    with pytest.raises(HibpError):
        load_config(tmp_path / "nie-ma.toml")
    cfg.write_text('domains = ["zla domena"]\n', encoding="utf-8")
    with pytest.raises(HibpError):
        load_config(cfg)


def _run(argv, client, tmp_path, capsys):
    code = main(argv, client=client, pause=lambda s: None)
    cap = capsys.readouterr()
    return code, cap.out, cap.err


def test_cli_breaches_two_runs_and_json(tmp_path, capsys):
    cfg = tmp_path / "config.toml"
    cfg.write_text('domains = ["adobe.com"]\n', encoding="utf-8")
    c1 = FakeClient({BASE: Response(200, fixture_text("breaches_adobe.json"))})
    code, out, _ = _run(["breaches", "--config", str(cfg)], c1, tmp_path, capsys)
    assert code == 0 and "pierwsze uruchomienie" in out and "Adobe" in out
    assert (tmp_path / "state.json").exists()

    c2 = FakeClient({BASE: Response(200, fixture_text("breaches_adobe_v2.json"))})
    code, out, _ = _run(["breaches", "--config", str(cfg), "--json"], c2, tmp_path, capsys)
    data = json.loads(out)
    assert code == 0
    assert [b["name"] for b in data["domains"][0]["new"]] == ["FikcyjnyNowy"]
    assert data["domains"][0]["total_breaches"] == 2


def test_cli_no_save_keeps_state_empty(tmp_path, capsys):
    c = FakeClient({BASE: Response(200, fixture_text("breaches_adobe.json"))})
    st = tmp_path / "st.json"
    code, out, _ = _run(["breaches", "--domain", "adobe.com", "--state", str(st), "--no-save"], c, tmp_path, capsys)
    assert code == 0 and not st.exists()


def test_cli_missing_config_is_readable_error(tmp_path, capsys):
    code, _, err = _run(["breaches", "--config", str(tmp_path / "x.toml")], FakeClient(), tmp_path, capsys)
    assert code == 2 and "config.example.toml" in err


def test_cli_catalog_since_and_limit(tmp_path, capsys):
    c = FakeClient({BASE: Response(200, fixture_text("breaches_adobe_v2.json"))})
    code, out, _ = _run(["breaches", "--catalog", "--since", "2026-01-01", "--json"], c, tmp_path, capsys)
    data = json.loads(out)
    assert code == 0 and data["total"] == 1 and data["breaches"][0]["name"] == "FikcyjnyNowy"
