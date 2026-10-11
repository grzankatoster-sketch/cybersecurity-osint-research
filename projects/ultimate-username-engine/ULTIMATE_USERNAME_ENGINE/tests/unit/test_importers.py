import copy
import json

from ultimate_username.domain.models import HttpMethod
from ultimate_username.importers import find_conflicts, import_data
from ultimate_username.planning import plan_request


def sherlock(**overrides):
    return {
        "url": "https://example.test/u/{}",
        "errorType": "status_code",
        "username_claimed": "alice",
        "username_unclaimed": "missing",
        **overrides,
    }


def wmn(**overrides):
    return {
        "name": "Example",
        "uri_check": "https://example.test/api/{account}",
        "uri_pretty": "https://example.test/u/{account}",
        "e_code": 200,
        "e_string": "profile",
        "m_code": 404,
        "m_string": "missing",
        "known": ["alice"],
        "cat": "social",
        **overrides,
    }


def test_sherlock_string_and_list_redirect_identical():
    first = import_data("sherlock", {"Example": sherlock(errorType="response_url")})
    second = import_data("sherlock", {"Example": sherlock(errorType=["response_url"])})
    assert first.sites == second.sites
    assert not first.sites[0].redirects.follow
    assert first.sites[0].controls[1].username == "missing"


def test_wmn_every_request_field_and_disabled_preserved():
    row = wmn(
        post_body='{"username":"{account}","nested":[false,0]}',
        headers={"Content-Type": "application/json", "X-Test": "yes"},
        strip_bad_char=".",
        valid=False,
    )
    imported = import_data("whatsmyname", {"sites": [row]})
    assert imported.records[0].status == "IMPORTED"
    site = imported.sites[0]
    plan = plan_request('a.b"#', site, "task")
    assert site.disabled
    assert plan.request.method == HttpMethod.POST
    assert plan.profile_url == "https://example.test/u/ab%22%23"
    assert plan.request.url == "https://example.test/api/ab%22%23"
    assert json.loads(plan.request.body) == {"username": 'ab"#', "nested": [False, 0]}
    assert plan.username.raw == 'a.b"#'
    assert plan.username.transformations
    assert ("X-Test", "yes") in plan.request.headers


def test_wmn_empty_markers_are_diagnostics_not_empty_predicates():
    record = import_data("whatsmyname", {"sites": [wmn(m_string="")]}).records[0]
    assert record.status == "IMPORTED"
    assert record.site.detection.absent.strategy == "status"
    assert any("EMPTY_MARKER" in n for n in record.diagnostics)


def test_unknown_fields_and_bad_record_do_not_silently_default():
    batch = import_data(
        "sherlock", {"Good": sherlock(), "Bad": {"url": 7}, "Unknown": sherlock(presenceStrs=["x"])}
    )
    assert [r.status for r in batch.records] == ["IMPORTED", "INVALID", "UNSUPPORTED"]
    assert ("presenceStrs", "UNSUPPORTED") in batch.records[-1].field_map
    assert "presenceStrs" in batch.records[-1].source_json


def test_maigret_engine_merge_does_not_mutate_and_quarantines_conflict():
    data = {
        "engines": {
            "Example": {
                "site": {
                    "url": "{urlMain}/u/{username}",
                    "checkType": "message",
                    "presenseStrs": ["profile"],
                    "headers": {"X": "engine"},
                }
            }
        },
        "sites": {
            "Good": {"engine": "Example", "urlMain": "https://example.test"},
            "Conflict": {
                "engine": "Example",
                "urlMain": "https://example.test",
                "headers": {"X": "local"},
            },
        },
    }
    original = copy.deepcopy(data)
    batch = import_data("maigret", data)
    assert data == original
    assert batch.records[0].status == "IMPORTED"
    assert batch.sites[0].headers == (("X", "engine"),)
    assert batch.records[1].status == "UNSUPPORTED"
    assert any("AMBIGUOUS_ENGINE_MERGE" in n for n in batch.records[1].diagnostics)


def test_conflicts_retain_variants_and_never_choose_winner():
    first = import_data("sherlock", {"Example": sherlock()})
    second = import_data("whatsmyname", {"sites": [wmn()]})
    conflicts = find_conflicts(first.sites + second.sites)
    assert len(conflicts) == 1
    assert len(conflicts[0].variant_ids) == 2
    assert "detection" in conflicts[0].differing_fields
    assert "no variant selected" in conflicts[0].resolution


def test_missing_wmn_controls_and_bad_payload_rejected():
    batch = import_data(
        "whatsmyname",
        {
            "sites": [
                wmn(known=[]),
                wmn(
                    name="broken", post_body="{broken", headers={"Content-Type": "application/json"}
                ),
            ]
        },
    )
    assert all(r.status == "INVALID" for r in batch.records)
