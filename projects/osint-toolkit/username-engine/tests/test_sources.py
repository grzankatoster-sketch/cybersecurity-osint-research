import json

import pytest

from username_engine.sources import from_maigret, from_wmn, load_db, merge, save_db, site_key

WMN = {"sites": [
    {"name": "GitHub", "uri_check": "https://api.github.com/users/{account}",
     "uri_pretty": "https://github.com/{account}", "e_code": 200, "e_string": "\"login\":",
     "m_code": 404, "m_string": "Not Found", "known": ["blue"], "cat": "coding"},
    {"name": "Filmweb", "uri_check": "https://www.filmweb.pl/user/{account}", "e_code": 200,
     "e_string": "userName", "m_code": 301, "m_string": "", "known": ["x"], "cat": "hobby"},
    {"name": "Broken", "uri_check": "https://b.com/{account}", "e_code": 200, "e_string": "a",
     "m_code": 404, "m_string": "b", "known": [], "cat": "misc", "valid": False},
]}

MAIGRET = {
    "engines": {"XenForo": {"name": "XenForo", "site": {
        "absenceStrs": ["The specified member cannot be found"], "presenseStrs": ["member-header"],
        "checkType": "message", "url": "{urlMain}{urlSubpath}/members/?username={username}"}}},
    "sites": {
        "GitHub": {"url": "https://github.com/{username}", "checkType": "status_code",
                   "urlMain": "https://www.github.com/", "tags": ["coding", "us"], "usernameClaimed": "blue"},
        "SomeForum": {"engine": "XenForo", "urlMain": "https://forum.example.pl/", "tags": ["pl", "forum"],
                      "absenceStrs": ["Nie znaleziono"], "usernameClaimed": "jan"},
        "Old": {"url": "https://old.com/{username}", "disabled": True},
        "Steam": {"url": "https://steam.com/id/{username}", "type": "steam_id"},
        "Rel": {"url": "{urlMain}{username}", "urlMain": "https://rel.example.com"},
    },
}


def test_wmn_import_maps_fields():
    sites = {s.name: s for s in from_wmn(WMN)}
    gh = sites["GitHub"]
    assert gh.url == "https://github.com/{username}"
    assert gh.probe_url == "https://api.github.com/users/{username}"
    assert gh.e_strings == ['"login":'] and gh.m_code == 404 and gh.source == "wmn"
    assert sites["Filmweb"].m_strings == []      # pusty m_string nie przechodzi do reguły
    assert "Broken" not in sites                 # valid: false pomijany


def test_maigret_engine_merge_and_filters():
    sites = {s.name: s for s in from_maigret(MAIGRET)}
    assert "Old" not in sites and "Steam" not in sites
    forum = sites["SomeForum"]
    assert forum.url == "https://forum.example.pl/members/?username={username}"
    assert forum.e_strings == ["member-header"]
    assert set(forum.m_strings) == {"The specified member cannot be found", "Nie znaleziono"}
    assert forum.check_type == "message"
    assert sites["GitHub"].check_type == "status_code" and sites["GitHub"].e_strings == []
    assert sites["Rel"].url == "https://rel.example.com/{username}"


def test_merge_dedupes_by_domain_and_keeps_first():
    merged = merge(from_wmn(WMN), from_maigret(MAIGRET))
    gh = [s for s in merged if site_key(s) == "github.com/{username}"]
    assert len(gh) == 1 and gh[0].source == "wmn"
    assert "us" in gh[0].tags                    # tagi z drugiego źródła dochodzą


def test_custom_rules_win_over_bases():
    from username_engine.sources import from_custom
    custom = from_custom({"sites": [
        {"name": "GitHub (nasza)", "url": "https://github.com/{username}", "check_type": "status_code",
         "tags": ["global", "coding"], "known": ["github"]},
        {"name": "Off", "url": "https://off.com/{username}", "disabled": True}]})
    merged = merge(custom, from_wmn(WMN), from_maigret(MAIGRET))
    gh = [s for s in merged if site_key(s) == "github.com/{username}"]
    assert len(gh) == 1 and gh[0].source == "custom" and gh[0].name == "GitHub (nasza)"
    assert not any(s.name == "Off" for s in merged)


def test_merge_makes_names_unique():
    from username_engine.models import Site
    a = [Site("Forum", "https://a.com/{username}", source="wmn")]
    b = [Site("Forum", "https://b.com/u/{username}", source="maigret")]
    names = [s.name for s in merge(a, b)]
    assert names == ["Forum", "Forum [maigret]"]


def test_save_and_load_roundtrip(tmp_path):
    sites = merge(from_wmn(WMN), from_maigret(MAIGRET))
    path = tmp_path / "sites.json"
    save_db(sites, path, {"built": "test"})
    loaded = load_db(path)
    assert [s.name for s in loaded] == [s.name for s in sites]
    assert loaded[0].e_strings == sites[0].e_strings


def test_load_rejects_bad_format(tmp_path):
    bad = tmp_path / "bad.json"
    bad.write_text(json.dumps([1, 2]), encoding="utf-8")
    with pytest.raises(ValueError):
        load_db(bad)
