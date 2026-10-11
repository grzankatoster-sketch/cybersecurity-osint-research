"""Serwisy sportowe/fitness i polskie (04.10.2026): reguła Strava (tylko numeryczne ID), komplet pól wpisów custom,
tag fitness w bazie i nakładka tag_overrides."""
import asyncio
import json
from pathlib import Path

import pytest

from username_engine import cli
from username_engine.engine import check_site
from username_engine.models import Response, Site, Status
from username_engine.sources import apply_tag_overrides, from_custom, load_db

ROOT = Path(__file__).resolve().parents[1]
RES = ROOT / "src" / "username_engine" / "resources"
BUILT_DB = ROOT / "data" / "sites.json"
needs_db = pytest.mark.skipif(not BUILT_DB.exists(), reason="brak zbudowanej bazy (scripts/build_db.py)")
NEW = ["Strava", "Mountain Project", "Hevy", "XContest", "Komoot", "Relive", "Runkeeper", "theTopo (27crags)",
       "Traseo", "BikeStats"]
FITNESS = ["Strava", "Garmin Connect", "Sports Tracker", "SmashRun", "MyFitnessPal Community", "MyFitnessPal Author",
           "run-log.com", "community.whoop.com"]


class FakeFetcher:
    def __init__(self, handler):
        self.handler, self.calls = handler, []

    async def fetch(self, method, url, headers=None, body=None):
        self.calls.append(url)
        return self.handler(url)


def custom():
    return {s.name: s for s in from_custom(json.loads((RES / "custom_sites.json").read_text(encoding="utf-8")))}


def db():
    return {s.name: s for s in load_db(BUILT_DB)}


def test_strava_name_is_unsupported_without_request():
    strava = custom()["Strava"]
    f = FakeFetcher(lambda url: Response(200, "x"))
    r = asyncio.run(check_site(strava, "jane", f))
    assert r.status is Status.UNSUPPORTED and f.calls == []


def test_strava_numeric_id_is_requested_and_classified():
    strava = custom()["Strava"]
    page = '<meta property="og:url" content="https://www.strava.com/athletes/304133"/>'

    def handler(url):
        return Response(200, page, final_url=url) if url.endswith("/304133") else Response(404, "", final_url=url)

    f = FakeFetcher(handler)
    found = asyncio.run(check_site(strava, "304133", f))
    missing = asyncio.run(check_site(strava, "999999999", f))
    assert found.status is Status.FOUND and found.confidence >= 0.6
    assert missing.status is Status.NOT_FOUND
    assert len(f.calls) >= 2


@pytest.mark.parametrize("name", NEW)
def test_new_custom_entries_have_required_fields(name):
    s = custom()[name]
    assert "{username}" in s.url and s.known and s.source == "custom"
    assert "sport" in s.tags or "fitness" in s.tags
    assert s.check_type == "status_code" or s.e_strings, "reguła bez znacznika ani kodu"
    if s.regex:
        import re
        assert all(re.search(s.regex, k) for k in s.known), "znane konto niezgodne z regułą"


def test_polish_entries_have_pl_tag_via_site_tags():
    from username_engine.sources import site_tags
    d = custom()
    assert "pl" in site_tags(d["BikeStats"]) and "pl" in site_tags(d["Traseo"])


@needs_db
def test_strava_in_database_uses_numeric_rule():
    s = db()["Strava"]
    assert s.regex == "^[0-9]{1,12}$" and s.source == "custom" and s.known == ["304133"]


@needs_db
@pytest.mark.parametrize("name", FITNESS)
def test_database_platforms_have_fitness_tag(name):
    assert "fitness" in db()[name].tags


@needs_db
def test_fitness_tag_works_with_cli_filter():
    sites = cli.select_sites(list(db().values()), "fitness", None)
    names = {s.name for s in sites}
    assert set(FITNESS) <= names and "Hevy" in names


def test_apply_tag_overrides_adds_tags_without_touching_rules():
    a = Site("Garmin Connect", "https://x/{username}", tags=["health"], e_strings=["a"])
    b = Site("Inny", "https://y/{username}", tags=["social"])
    n = apply_tag_overrides([a, b], {"tags": {"garmin connect": ["fitness", "health"]}})
    assert n == 1 and a.tags == ["health", "fitness"] and a.e_strings == ["a"] and b.tags == ["social"]
    assert apply_tag_overrides([a], {"tags": {"Garmin Connect": ["fitness"]}}) == 0   # idempotentne


@needs_db
def test_tag_overrides_file_is_valid_and_applied_in_database():
    ov = json.loads((RES / "tag_overrides.json").read_text(encoding="utf-8"))
    sites = db()
    for name, tags in ov["tags"].items():
        assert name in sites, f"{name}: brak w bazie"
        assert set(tags) <= set(sites[name].tags)
