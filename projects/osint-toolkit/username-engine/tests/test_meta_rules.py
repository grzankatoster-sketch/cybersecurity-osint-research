"""Reguły Meta (Facebook/Instagram/Threads) usunięte: działały tylko dzięki podszywaniu się pod robota podglądu
linków (User-Agent facebookexternalhit). Zostają ogólne mechanizmy: znacznik związany z nazwą, absence_unproven,
--sites z czytelnym błędem dla nieznanych (w tym usuniętych) nazw."""
import json
import re
from pathlib import Path

import pytest

from username_engine import cli
from username_engine.classify import classify, matched_evidence
from username_engine.dorks import SOCIAL_DOMAINS
from username_engine.models import Response, Site, Status
from username_engine.sources import from_custom

ROOT = Path(__file__).resolve().parents[1]
CUSTOM = ROOT / "src" / "username_engine" / "resources" / "custom_sites.json"
BUILT_DB = ROOT / "data" / "sites.json"
REMOVED = ("Facebook", "Instagram", "Threads")
CRAWLER_UA = re.compile(r"facebookexternalhit|facebot|twitterbot|googlebot|bingbot|slackbot|telegrambot|whatsapp|"
                        r"linkedinbot|discordbot|applebot|yandexbot|baiduspider|duckduckbot|embedly|"
                        r"skypeuripreview|pinterestbot|crawler|spider", re.I)

# reguły „znacznik z nazwą” i „brak znacznika != brak konta” (wcześniej na przykładzie Instagram/Facebook)
MARKED = Site("Profil", "https://profil.example/{username}/", check_type="message",
              e_strings=["app://user?username={username}"], m_strings=['"pageID":"httpErrorPage"'])
UNPROVEN = Site("Katalog", "https://katalog.example/{username}", e_strings=["app://profile/", "app://page/"],
                absence_unproven=True)


def _site_dicts(path: Path) -> list[dict]:
    return json.loads(path.read_text(encoding="utf-8"))["sites"]


def test_marker_must_contain_checked_name_case_insensitive():
    page = '<meta property="al:ios:url" content="app://user?username=natgeo">'
    assert classify(MARKED, Response(200, page), "NatGeo")[0] is Status.FOUND
    assert matched_evidence(MARKED, Response(200, page), "natgeo") == ["app://user?username={username}"]


def test_marker_for_other_account_is_not_a_hit():
    page = '<meta content="app://user?username=someoneelse">'
    status, _, reason = classify(MARKED, Response(200, page), "natgeo")
    assert status is Status.ERROR and "nierozpoznana" in reason


@pytest.mark.parametrize("name", ["natgeo1", "natgeo.foo", "natgeo_extra", "natgeo%31"])
def test_similar_name_marker_does_not_confirm_exact_account(name):
    page = f'<meta content="app://user?username={name}">'
    assert classify(MARKED, Response(200, page), "natgeo")[0] is not Status.FOUND


def test_absence_unproven_changed_html_is_error_not_absence():
    status, _, reason = classify(UNPROVEN, Response(200, "<html>nowy układ strony</html>"), "jan.kowalski")
    assert status is Status.ERROR and "nie dowodzi braku" in reason


def test_absence_unproven_marker_found_and_404_still_absence():
    assert classify(UNPROVEN, Response(200, '<meta content="app://profile/123">'), "jan.kowalski")[0] is Status.FOUND
    assert classify(UNPROVEN, Response(404, ""), "jan.kowalski")[0] is Status.NOT_FOUND


def test_absence_unproven_validated_and_roundtrips():
    with pytest.raises(ValueError):
        Site.from_dict({"name": "A", "url": "https://a/{username}", "absence_unproven": "tak"})
    assert Site.from_dict(UNPROVEN.to_dict()).absence_unproven is True
    assert "absence_unproven" not in MARKED.to_dict()


def test_meta_rules_removed_from_custom_rules_and_no_crawler_user_agent_left():
    custom = _site_dicts(CUSTOM)
    assert not [s["name"] for s in custom if s["name"] in REMOVED]
    fake_ua = [s["name"] for s in custom for k, v in (s.get("headers") or {}).items()
               if k.lower() == "user-agent" and CRAWLER_UA.search(v)]
    assert fake_ua == []
    assert {s.name for s in from_custom({"sites": custom})}.isdisjoint(REMOVED)


@pytest.mark.skipif(not BUILT_DB.exists(), reason="brak zbudowanej bazy (scripts/build_db.py)")
def test_built_db_has_no_meta_rules_nor_crawler_user_agent():
    sites = _site_dicts(BUILT_DB)
    assert [s["name"] for s in sites if s["name"] in REMOVED] == []
    fake_ua = [s["name"] for s in sites for k, v in (s.get("headers") or {}).items()
               if k.lower() == "user-agent" and CRAWLER_UA.search(v)]
    assert fake_ua == []


def test_threads_dork_domains():
    assert {"threads.com", "threads.net"} <= set(SOCIAL_DOMAINS)


def test_site_selector_before_limit_and_unknown_names():
    sites = [Site(n, f"https://{n.lower()}.example/{{username}}") for n in ("A", "Github", "Reddit", "Gitlab")]
    names = cli.parse_site_names("github, Reddit,github")
    assert names == ["github", "Reddit"]
    assert [s.name for s in cli.select_sites(sites, None, 1, names)] == ["Github"]
    assert cli.unknown_site_names(sites, ["Reddit", "Myspace"]) == ["Myspace"]


def test_cli_unknown_site_exits_2(tmp_path, capsys):
    db = tmp_path / "sites.json"
    db.write_text(json.dumps({"sites": [UNPROVEN.to_dict()]}), encoding="utf-8")
    assert cli.main(["natgeo", "--db", str(db), "--sites", "Katalogg", "--no-variants"]) == 2
    err = capsys.readouterr().err
    assert "Nieznane serwisy" in err and "Katalogg" in err and "Meta" not in err


def test_cli_removed_meta_names_give_readable_error(tmp_path, capsys):
    db = tmp_path / "sites.json"
    db.write_text(json.dumps({"sites": [UNPROVEN.to_dict()]}), encoding="utf-8")
    assert cli.main(["natgeo", "--db", str(db), "--sites", "Facebook,Instagram,Threads", "--no-variants"]) == 2
    err = capsys.readouterr().err
    assert "Nieznane serwisy w --sites: Facebook, Instagram, Threads" in err
    assert "usunięt" in err and "ręcznie" in err
    assert "np. Facebook" not in err            # przykład w komunikacie nie podpowiada usuniętych nazw


def test_cli_known_site_still_selectable_with_sites(tmp_path, monkeypatch):
    db = tmp_path / "sites.json"
    db.write_text(json.dumps({"sites": [UNPROVEN.to_dict(), MARKED.to_dict()]}), encoding="utf-8")
    seen = []

    class F:
        def __init__(self, *a, **k): pass
        async def __aenter__(self): return self
        async def __aexit__(self, *e): pass
        async def fetch(self, method, url, headers=None, body=None):
            seen.append(url)
            return Response(404, "", final_url=url)

    monkeypatch.setattr(cli, "Fetcher", F)
    assert cli.main(["natgeo", "--db", str(db), "--sites", "katalog", "--no-variants", "--include-broken"]) == 0
    assert seen and all("katalog.example" in u for u in seen)
