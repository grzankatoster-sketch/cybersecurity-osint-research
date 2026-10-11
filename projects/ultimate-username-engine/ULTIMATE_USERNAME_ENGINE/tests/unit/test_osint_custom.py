"""F3.2: data/osint_custom.json overlay loaded next to catalog.json, preference for its variants."""

from __future__ import annotations

import json
import shutil
from dataclasses import replace
from pathlib import Path

import pytest

from ultimate_username.domain.models import (
    Control,
    DetectionSpec,
    Provenance,
    Rule,
    SiteDefinition,
    Verdict,
)
from ultimate_username.registry import OVERLAY_FILES, SiteRegistry
from ultimate_username.runtime_policy import (
    MODES,
    OSINT_CUSTOM_BONUS,
    RuntimePolicy,
    runtime_selection,
    technical_quality,
    variant_bonus,
)
from ultimate_username.selection import select_services, service_key

DATA = Path(__file__).resolve().parents[2] / "data"

# data/catalog.json is derived from third-party catalogues and is not published (see NOTICE.md);
# rebuild it with tools/import_catalogs.py to run this module.
pytestmark = pytest.mark.skipif(
    not (DATA / "catalog.json").is_file(),
    reason="data/catalog.json not present (rebuild locally, see NOTICE.md)",
)
ADD = {
    "Hejto",
    "Hevy",
    "Komoot",
    "Mountain Project",
    "Relive",
    "Runkeeper",
    "Tekstowo.pl",
    "theTopo (27crags)",
    "Traseo",
    "XContest",
}
REPLACE = {
    "forum.centrala-termica.ro",
    "GitCode",
    "kiwifarms.cc",
    "Pepper.pl",
    "Radiomed",
    "Strava",
}
HOLDOUT_FILE = DATA.parents[1] / "bench" / "ground_truth" / "dev_excluded_hosts.json"


@pytest.fixture(scope="module")
def overlay() -> SiteRegistry:
    return SiteRegistry.from_json((DATA / "osint_custom.json").read_text("utf-8-sig"))


@pytest.fixture(scope="module")
def merged() -> SiteRegistry:
    return SiteRegistry.from_path(DATA / "catalog.json")


def test_overlay_has_the_ten_additions_and_six_preferred_variants(overlay):
    names = {e.definition.name for e in overlay.entries}
    assert names == ADD | REPLACE
    assert len(overlay.entries) == 16


def test_overlay_entries_are_valid_and_marked_osint_custom(overlay):
    for entry in overlay.entries:
        assert not entry.issues, entry.id
        assert entry.definition.provenance.donor == "osint-custom"
        assert entry.id.startswith("osint:")


def test_negative_verified_only_in_osint_custom(merged):
    flagged = {
        e.id for e in merged.entries if e.definition and e.definition.detection.negative_verified
    }
    assert flagged
    for sid in flagged:
        assert merged.get(sid).definition.provenance.donor == "osint-custom"


def test_catalog_is_unchanged_and_never_contains_osint_custom():
    catalog = json.loads((DATA / "catalog.json").read_text("utf-8-sig"))
    assert len(catalog) == 8956
    assert not [r for r in catalog if r["provenance"]["donor"] == "osint-custom"]


def test_merged_registry_has_no_duplicate_ids_and_all_valid(merged):
    ids = [e.id for e in merged.entries]
    assert len(ids) == len(set(ids)) == 8956 + 16
    assert not [e.id for e in merged.entries if e.issues]


def test_from_path_without_overlay_keeps_only_the_catalog():
    plain = SiteRegistry.from_path(DATA / "catalog.json", overlays=False)
    assert len(plain.entries) == 8956


def test_overlay_only_loads_next_to_a_file_named_catalog_json(tmp_path):
    other = tmp_path / "mine.json"
    other.write_text("[]", "utf-8")
    shutil.copy(DATA / "osint_custom.json", tmp_path / "osint_custom.json")
    assert SiteRegistry.from_path(other).entries == ()
    shutil.copy(other, tmp_path / "catalog.json")
    assert len(SiteRegistry.from_path(tmp_path / "catalog.json").entries) == 16
    assert OVERLAY_FILES == ("osint_custom.json",)


def test_missing_overlay_file_is_fine(tmp_path):
    (tmp_path / "catalog.json").write_text("[]", "utf-8")
    assert SiteRegistry.from_path(tmp_path / "catalog.json").entries == ()


def test_validate_command_includes_the_overlay(tmp_path, capsys):
    from ultimate_username.cli import main

    (tmp_path / "catalog.json").write_text("[]", encoding="utf-8")
    assert main(["validate", str(tmp_path / "catalog.json")]) == 0
    assert json.loads(capsys.readouterr().out)["records"] == 0
    shutil.copy(DATA / "osint_custom.json", tmp_path / "osint_custom.json")
    assert main(["validate", str(tmp_path / "catalog.json")]) == 0
    assert json.loads(capsys.readouterr().out)["records"] == 16


def test_duplicate_id_between_catalog_and_overlay_stays_observable(tmp_path):
    record = json.loads((DATA / "osint_custom.json").read_text("utf-8"))[0]
    (tmp_path / "catalog.json").write_text(json.dumps([record]), "utf-8")
    shutil.copy(DATA / "osint_custom.json", tmp_path / "osint_custom.json")
    merged = SiteRegistry.from_path(tmp_path / "catalog.json")
    assert [e.issues for e in merged.entries if e.id == record["id"]] != [(), ()]


def test_no_overlay_host_is_holdout_or_tuned(overlay):
    banned: set[str] = set()
    excluded = json.loads(HOLDOUT_FILE.read_text("utf-8"))
    for key in ("holdout_hosts", "tuned_hosts"):
        banned |= {h.lower() for h in excluded.get(key, [])}
    tuned = DATA.parents[1] / "bench" / "ground_truth" / "tuned_services.json"
    banned |= {h.lower().removeprefix("www.") for h in _hosts(json.loads(tuned.read_text("utf-8")))}
    from urllib.parse import urlsplit

    for entry in overlay.entries:
        host = (urlsplit(entry.definition.profile_url).hostname or "").lower().removeprefix("www.")
        assert not any(host == b or host.endswith("." + b) for b in banned), host


def _hosts(value) -> set[str]:
    found: set[str] = set()
    if isinstance(value, str):
        found.add(value)
    elif isinstance(value, dict):
        for k, v in value.items():
            found |= _hosts(k) | _hosts(v)
    elif isinstance(value, list):
        for v in value:
            found |= _hosts(v)
    return {h for h in found if "." in h and " " not in h and "/" not in h}


def test_preferred_variants_share_a_service_with_catalog_variants(merged):
    keys = {}
    for e in merged.entries:
        keys.setdefault(service_key(e.definition), []).append(e)
    for e in merged.entries:
        if e.definition.name in REPLACE and e.definition.provenance.donor == "osint-custom":
            assert len(keys[service_key(e.definition)]) >= 2, e.definition.name


def test_osint_custom_bonus_is_a_variant_key_and_never_part_of_the_score(merged):
    for e in merged.entries:
        d = e.definition
        assert not any("OSINT_CUSTOM_PREFERRED" in r for r in technical_quality(e).reasons)
        custom = d.provenance.donor == "osint-custom"
        assert variant_bonus(e) == (OSINT_CUSTOM_BONUS if custom else 0)


POSTS = Rule("message", "Posts by")
NOT_FOUND_404 = Rule("status", statuses=(404,))


def _site(sid, donor="native", present=POSTS, absent=NOT_FOUND_404, **kw):
    return SiteDefinition(
        sid,
        sid,
        kw.pop("url", f"https://{sid}.test/u/{{username}}"),
        DetectionSpec(present, absent),
        provenance=Provenance(donor=donor),
        controls=(Control("alice", Verdict.FOUND),),
        **kw,
    )


@pytest.mark.parametrize("mode", ["quick", "normal", "deep"])
def test_bonus_does_not_lift_an_overlay_service_to_the_queue_head(mode):
    plain = Rule("status", statuses=tuple(range(200, 300)))
    sites = [
        _site("custom", "osint-custom", present=plain, absent=None),  # weak, single variant
        _site("native-a"),
        _site("native-b"),
    ]
    registry = SiteRegistry(sites)
    policy = replace(MODES[mode], min_quality=-100)
    selection = runtime_selection(registry, select_services(registry, "alice"), policy)
    assert selection.selected[-1] == "custom"
    values = dict(selection.quality_order)
    assert values["custom"].value == technical_quality(registry.get("custom")).value
    assert values["custom"].value < values["native-a"].value
    assert not any("OSINT_CUSTOM_PREFERRED" in r for r in values["custom"].reasons)


def test_variant_bonus_keeps_the_osint_variant_primary_inside_its_service():
    shared = "https://svc.test/u/{username}"
    catalog_variant = _site("a-catalog", "whatsmyname", url=shared)
    custom_variant = _site("z-osint", "osint-custom", url=shared)
    registry = SiteRegistry([catalog_variant, custom_variant])
    selection = runtime_selection(
        registry, select_services(registry, "alice"), replace(MODES["normal"], min_quality=-100)
    )
    (service,) = selection.services
    assert service.primary == "z-osint" and service.alternatives == ("a-catalog",)
    assert service.quality.value == technical_quality(registry.get("z-osint")).value
    assert "OSINT_CUSTOM_PREFERRED:+0" in service.quality.reasons
    # the same two variants as separate services: no variant ordering, no reason
    other = SiteRegistry([catalog_variant, _site("z-osint", "osint-custom")])
    plain = runtime_selection(other, select_services(other, "alice"), MODES["normal"])
    assert not any("OSINT_CUSTOM_PREFERRED" in r for s in plain.services for r in s.quality.reasons)


def test_preferred_variant_becomes_primary_without_deleting_alternatives(merged):
    # The OSINT identifier patterns are real constraints (Strava ids are numeric), so the
    # preferred variant competes only for names it accepts; try a word and a number.
    checked = set()
    for username in ("zzqxprobeuser", "12345678"):
        plan = select_services(merged, username)
        selection = runtime_selection(merged, plan, RuntimePolicy(service_budget=1_000_000))
        by_key = {s.key: s for s in selection.services}
        for e in merged.entries:
            d = e.definition
            if d.provenance.donor == "osint-custom" and d.name in REPLACE:
                service = by_key.get(service_key(d))
                if service is None or e.id not in (service.primary, *service.alternatives):
                    continue  # username rejected by this definition's identifier pattern
                assert service.primary == e.id, d.name
                assert len(service.alternatives) >= 1
                assert all(not a.startswith("osint:") for a in service.alternatives)
                checked.add(d.name)
    assert checked == REPLACE
