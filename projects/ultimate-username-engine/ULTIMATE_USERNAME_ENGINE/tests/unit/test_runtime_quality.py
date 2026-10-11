import asyncio
import json
from dataclasses import replace

import pytest

from ultimate_username.cli import main
from ultimate_username.detection import DetectionEngine
from ultimate_username.domain.codec import from_json, to_json
from ultimate_username.domain.metadata import EnrichmentMode, ProfileMetadata
from ultimate_username.domain.models import (
    DetectionResult,
    DetectionSpec,
    Rule,
    SiteDefinition,
    TransportResponse,
    Verdict,
)
from ultimate_username.engine import SearchOptions, UsernameEngine
from ultimate_username.enrichment import enrich
from ultimate_username.field_model import FieldGroup, Usefulness, field_spec
from ultimate_username.planning import plan_request
from ultimate_username.presentation import analyst_document, analyst_record
from ultimate_username.registry import SiteRegistry
from ultimate_username.selection import prepared_registry, select_services, service_key
from ultimate_username.transport import FakeTransport


def github():
    return SiteDefinition(
        "github:api",
        "GitHub",
        "https://github.com/{username}",
        DetectionSpec(Rule("status", statuses=(200,)), Rule("status", statuses=(404,))),
        probe_url="https://api.github.com/users/{username}",
    )


def payload():
    return {
        "login": "jankowalski",
        "id": 123,
        "node_id": "fixture-node",
        "name": "Fixture User",
        "avatar_url": "https://avatars.githubusercontent.com/u/123",
        "html_url": "https://github.com/jankowalski",
        "url": "https://api.github.com/users/jankowalski",
        "company": "Fixture Company",
        "blog": "https://example.test/",
        "location": "Fixture City",
        "email": "fixture@example.test",
        "bio": "Fixture bio",
        "twitter_username": "fixture_handle",
        "public_repos": 0,
        "public_gists": 2,
        "followers": 0,
        "following": 3,
        "created_at": "2020-01-01T00:00:00Z",
        "updated_at": "2026-01-01T00:00:00Z",
        "hireable": False,
    }


def response(data=None, status=200, url="https://api.github.com/users/JanKowalski"):
    return TransportResponse(
        url,
        status,
        json.dumps(payload() if data is None else data).encode(),
        (("Content-Type", "application/json; charset=utf-8"),),
        url,
    )


@pytest.mark.parametrize("username", ["JanKowalski", "jankowalski", "JANKOWALSKI"])
def test_github_owner_normalization_and_all_reference_fields(username):
    resp = response(url="https://api.github.com/users/" + username)
    metadata = enrich(resp, username, github(), DetectionResult(Verdict.PROBABLE))
    assert metadata.state == "SUCCESS"
    expected = {
        "username": "jankowalski",
        "user_id": "123",
        "node_id": "fixture-node",
        "avatar_url": payload()["avatar_url"],
        "profile_url": payload()["html_url"],
        "display_name": "Fixture User",
        "email": "fixture@example.test",
        "twitter_username": "fixture_handle",
        "followers": 0,
        "public_repos_count": 0,
        "is_looking_for_job": False,
    }
    for key, value in expected.items():
        assert metadata.get(key) == value
    assert len(metadata.fields + metadata.extra_fields) == 19
    assert from_json(ProfileMetadata, to_json(metadata)) == metadata


@pytest.mark.parametrize("change", [{"login": "other"}, {"html_url": "https://github.com/other"}])
def test_github_conflicting_owner_rejects_entire_object(change):
    data = payload() | change
    metadata = enrich(response(data), "JanKowalski", github(), DetectionResult(Verdict.PROBABLE))
    assert not metadata.fields and not metadata.extra_fields
    assert "OWNER_BINDING_FAILED" in metadata.diagnostics
    assert "display_name" in metadata.coverage.rejected_fields


@pytest.mark.parametrize(
    "url",
    [
        "http://api.github.com/users/JanKowalski",
        "https://api.github.com.evil.test/users/JanKowalski",
        "https://api.github.com/users/Other",
        "https://api.github.com/users/JanKowalski/followers",
    ],
)
def test_case_insensitive_binding_does_not_leak_to_other_origins_or_resources(url):
    metadata = enrich(response(url=url), "JanKowalski", github(), DetectionResult(Verdict.PROBABLE))
    assert not metadata.fields


def test_generic_platform_remains_case_sensitive():
    site = replace(github(), profile_url="https://example.test/{username}", probe_url=None)
    resp = response({"username": "alice", "name": "Fixture User"}, url="https://example.test/Alice")
    assert not enrich(resp, "Alice", site, DetectionResult(Verdict.PROBABLE)).fields


def test_null_invalid_and_missing_are_distinct_and_no_fabricated_values():
    metadata = enrich(
        response(payload() | {"bio": None, "email": "not-an-email", "followers": -1}),
        "JanKowalski",
        github(),
        DetectionResult(Verdict.PROBABLE),
    )
    assert metadata.get("bio") is None and "bio" in metadata.coverage.null_fields
    assert {"email", "followers"} <= set(metadata.coverage.invalid_fields)
    assert "banner_url" not in metadata.coverage.available_fields
    assert "user_id" in metadata.coverage.extracted_fields
    assert not metadata.coverage.missing_fields


@pytest.mark.parametrize("kind", ["og", "jsonld", "embedded"])
def test_bound_html_sources_still_extract(kind):
    site = replace(
        github(), name="Fixture", profile_url="https://example.test/{username}", probe_url=None
    )
    content = {
        "og": (
            '<link rel="canonical" href="https://example.test/alice">'
            '<meta property="profile:username" content="alice">'
            '<meta property="og:type" content="profile">'
            '<meta property="og:title" content="Fixture User">'
        ),
        "jsonld": (
            '<script type="application/ld+json">{"@type":"Person",'
            '"alternateName":"alice","url":"https://example.test/alice",'
            '"name":"Fixture User"}</script>'
        ),
        "embedded": (
            '<script id="__NEXT_DATA__" type="application/json">'
            '{"props":{"pageProps":{"user":{"username":"alice",'
            '"displayName":"Fixture User"}}}}</script>'
        ),
    }[kind]
    resp = TransportResponse(
        "https://example.test/alice", 200, content.encode(), (("Content-Type", "text/html"),)
    )
    assert (
        enrich(resp, "alice", site, DetectionResult(Verdict.PROBABLE)).get("display_name")
        == "Fixture User"
    )


@pytest.mark.parametrize(
    "kind,status,body,url",
    [
        (
            "homepage",
            200,
            '<meta property="og:title" content="GitHub">',
            "https://github.com/JanKowalski",
        ),
        (
            "error",
            404,
            '<meta property="og:title" content="Error">',
            "https://github.com/JanKowalski",
        ),
        ("login", 200, '<meta property="og:title" content="Login">', "https://github.com/login"),
        (
            "blocked",
            403,
            '<meta property="og:title" content="Denied">',
            "https://github.com/JanKowalski",
        ),
        ("challenge", 200, "<title>Just a moment</title>", "https://github.com/JanKowalski"),
    ],
)
def test_nonprofile_pages_do_not_become_useful_metadata(kind, status, body, url):
    resp = TransportResponse(url, status, body.encode(), (("Content-Type", "text/html"),), url)
    metadata = enrich(resp, "JanKowalski", github(), DetectionResult(Verdict.PROBABLE))
    assert not metadata.fields
    assert metadata.diagnostics


@pytest.mark.parametrize(
    "body,ctype,reason",
    [
        (b"", "application/json", "BODY_UNAVAILABLE"),
        (b"{broken", "application/json", "PARSER_EMPTY"),
        (b"binary", "application/pdf", "CONTENT_TYPE_UNSUPPORTED"),
        (b"{}", "application/json", "NO_EXTRACTOR_MATCHED"),
    ],
)
def test_empty_diagnostics(body, ctype, reason):
    resp = replace(response(), body=body, headers=(("Content-Type", ctype),))
    assert (
        reason
        in enrich(resp, "JanKowalski", github(), DetectionResult(Verdict.PROBABLE)).diagnostics
    )


def test_bound_generic_fields_default_avatar_and_request_id_are_not_useful():
    data = payload() | {
        "name": "GitHub",
        "bio": "Accept all cookies",
        "avatar_url": "https://example.test/default-avatar.png",
        "request_id": "secret-diagnostic",
    }
    meta = enrich(response(data), "JanKowalski", github(), DetectionResult(Verdict.PROBABLE))
    assert all(meta.get(key) is None for key in ("display_name", "bio", "avatar_url", "request_id"))
    assert {"display_name", "bio", "avatar_url"} <= set(meta.coverage.rejected_fields)


@pytest.mark.parametrize(
    "change,expected",
    [
        ({}, "FOUND"),
        ({"login": "other"}, "UNKNOWN"),
        ({"id": None}, "UNKNOWN"),
        ({"html_url": "https://github.com/other"}, "UNKNOWN"),
        ({"id": True}, "UNKNOWN"),
    ],
)
def test_native_github_detection_requires_independent_structured_evidence(change, expected):
    registry = prepared_registry(SiteRegistry([github()]))
    site = registry.entries[0].definition
    assert not registry.entries[0].issues
    result = DetectionEngine().detect(
        response(payload() | change), plan_request("JanKowalski", site, "test")
    )
    assert result.verdict == expected
    assert prepared_registry(registry).revision == registry.revision


@pytest.mark.parametrize(
    "status,body,expected,state",
    [
        (404, {"message": "Not Found"}, "NOT_FOUND", "OK"),
        (404, {"message": "Something else"}, "UNKNOWN", "OK"),
        (403, {"message": "Denied"}, "UNKNOWN", "BLOCKED"),
        (429, {"message": "Limit"}, "UNKNOWN", "RATE_LIMITED"),
    ],
)
def test_github_negative_and_obstruction_gates(status, body, expected, state):
    site = prepared_registry(SiteRegistry([github()])).entries[0].definition
    result = DetectionEngine().detect(
        response(body, status), plan_request("JanKowalski", site, "test")
    )
    assert (result.verdict, result.state) == (expected, state)


def test_prioritization_grouping_and_explicit_selection():
    low = replace(
        github(), id="low", probe_url=None, profile_url="https://www.github.com/{username}"
    )
    other = replace(low, id="other", profile_url="https://other.test/{username}")
    registry = prepared_registry(SiteRegistry([low, other, github()]))
    plan = select_services(registry, "JanKowalski")
    assert plan.selected[0] == "github:api"
    assert len(plan.services) == 2 and "low" not in plan.selected
    assert plan.services[0].alternatives == ("low",)
    explicit = select_services(registry, "JanKowalski", ids=["low", "github:api"])
    assert len(explicit.selected) == 2
    assert len(select_services(registry, "JanKowalski", mode="all").selected) == 3


def test_distinct_profile_routes_and_subdomains_are_not_merged():
    a = replace(github(), profile_url="https://example.test/u/{username}")
    b = replace(a, profile_url="https://example.test/channel/{username}")
    c = replace(a, profile_url="https://www.example.test/u/{username}")
    assert len({service_key(a), service_key(b), service_key(c)}) == 3


def test_generic_twitch_negative_rule_is_quarantined():
    site = SiteDefinition(
        "twitch",
        "Twitch",
        "https://www.twitch.tv/{username}",
        DetectionSpec(absent=Rule("message", "Twitch is the world")),
    )
    registry = prepared_registry(SiteRegistry([site]))
    assert registry.entries[0].definition.disabled
    assert select_services(registry, "alice").excluded == (("twitch", "QUARANTINE"),)


def test_quality_budget_order_reuses_response_and_not_tested_summary():
    async def run():
        weak = replace(
            github(), id="weak", profile_url="https://weak.test/{username}", probe_url=None
        )
        registry = prepared_registry(SiteRegistry([weak, github()]))
        plan = select_services(registry, "JanKowalski")
        transport = FakeTransport(
            handler=lambda request, index: replace(response(), requested_url=request.url)
        )
        async with UsernameEngine(registry, transport) as engine:
            results = [
                r
                async for r in engine.search_stream(
                    "JanKowalski",
                    site_ids=plan.selected,
                    options=SearchOptions(request_budget=1, enrichment_mode=EnrichmentMode.BASIC),
                )
            ]
        assert transport.total == 1 and transport.requests[0].url.startswith(
            "https://api.github.com/"
        )
        profile = next(r for r in results if r.site_id == "github:api")
        assert profile.profile_metadata.get("user_id") == "123"
        assert profile.profile_metadata.request_count == 0
        untested = next(r for r in results if not r.attempts)
        assert analyst_record(untested, registry)["status"] == "NOT_TESTED"
        doc = analyst_document(
            results, registry, username="JanKowalski", selection=plan, only_matches=True
        )
        counts = doc["summary"]["counts"]
        assert counts["tested"] == 1 and counts["not_tested"] == 1
        assert counts["found"] == 1 and counts["profiles_with_metadata"] == 1
        assert len(doc["profiles"]) == 1
        text = json.dumps(doc)
        assert all(
            x not in text
            for x in ("body_sha256", "task_id", "job_id", "definition_revision", "queue_wait")
        )

    asyncio.run(run())


def test_probable_enrichment_does_not_promote_verdict():
    async def run():
        transport = FakeTransport(handler=lambda request, index: response())
        async with UsernameEngine(SiteRegistry([github()]), transport) as engine:
            result = (
                await engine.search(
                    "JanKowalski", options=SearchOptions(enrichment_mode=EnrichmentMode.BASIC)
                )
            )[0]
        assert result.detection.verdict == "PROBABLE"
        assert result.profile_metadata.get("user_id") == "123"
        assert transport.total == 1

    asyncio.run(run())


@pytest.mark.parametrize("view", ["analyst", "debug"])
def test_cli_views_keep_complete_export_and_create_clean_companion(tmp_path, capsys, view):
    output = tmp_path / "results.json"
    code = main(
        [
            "demo",
            "alice",
            "--view",
            view,
            "--only-matches",
            "--output",
            str(output),
            "--journal",
            str(tmp_path / "journal.sqlite"),
        ]
    )
    assert code == 1
    complete = json.loads(output.read_text(encoding="utf-8"))
    assert len(complete) == 4 and all("attempts" in r for r in complete)
    analyst = json.loads(output.with_suffix(".analyst.json").read_text(encoding="utf-8"))
    assert len(analyst["profiles"]) == 1
    assert analyst["summary"]["counts"]["tested"] == 4
    err = capsys.readouterr().err
    assert ('"task_id"' in err) == (view == "debug")


def test_field_usefulness_is_separate_from_evidence_confidence():
    assert field_spec("email").group == FieldGroup.CORRELATION
    assert field_spec("avatar_url").group == FieldGroup.MEDIA
    assert field_spec("followers").usefulness == Usefulness.MEDIUM
    assert field_spec("body_sha256").usefulness == Usefulness.TECHNICAL


@pytest.mark.parametrize(
    "change,expected",
    [
        ({}, "FOUND"),
        ({"username": "someone_else"}, "UNKNOWN"),
        ({"id": None}, "UNKNOWN"),
        ({"type_of": "article"}, "UNKNOWN"),
    ],
)
def test_reviewed_dev_json_adapter(change, expected):
    site = SiteDefinition(
        "dev",
        "DEV",
        "https://dev.to/{username}",
        DetectionSpec(Rule("status", statuses=(200,))),
        probe_url="https://dev.to/api/users/by_username?url={username}",
    )
    prepared = prepared_registry(SiteRegistry([site])).entries[0].definition
    data = {"type_of": "user", "id": 1, "username": "fixture", "name": "Fixture User"} | change
    url = "https://dev.to/api/users/by_username?url=fixture"
    resp = TransportResponse(
        url, 200, json.dumps(data).encode(), (("Content-Type", "application/json"),), url
    )
    assert (
        DetectionEngine().detect(resp, plan_request("fixture", prepared, "test")).verdict
        == expected
    )


@pytest.mark.parametrize(
    "page,alternate,accepted",
    [
        ("https://example.test/alice", None, True),
        ("https://example.test/bob", None, False),
        ("https://example.test/alice", "bob", False),
    ],
)
def test_jsonld_main_entity_page_binding_without_inventing_username(page, alternate, accepted):
    obj = {
        "@type": "Person",
        "url": "https://example.test/alice",
        "mainEntityOfPage": {"@id": page},
        "name": "Fixture Person",
    }
    if alternate is not None:
        obj["alternateName"] = alternate
    body = '<script type="application/ld+json">' + json.dumps(obj) + "</script>"
    site = replace(
        github(), name="Fixture", profile_url="https://example.test/{username}", probe_url=None
    )
    resp = TransportResponse(
        "https://example.test/alice", 200, body.encode(), (("Content-Type", "text/html"),)
    )
    meta = enrich(resp, "alice", site, DetectionResult(Verdict.PROBABLE))
    assert (meta.get("display_name") == "Fixture Person") == accepted
    assert meta.get("username") is None


def test_exhaustion_after_an_attempt_is_not_labeled_not_tested():
    async def run():
        site = github()
        site = replace(site, retry=replace(site.retry, max_attempts=2, base_delay=0, max_delay=0))
        registry = SiteRegistry([site])
        transport = FakeTransport(
            handler=lambda request, index: response({"error": "temporary"}, 500)
        )
        async with UsernameEngine(registry, transport) as engine:
            result = (await engine.search("JanKowalski", options=SearchOptions(request_budget=1)))[
                0
            ]
        assert result.detection.state == "BUDGET_EXHAUSTED" and len(result.attempts) == 1
        assert analyst_record(result, registry)["status"] != "NOT_TESTED"
        document = analyst_document([result], registry, username="JanKowalski")
        assert document["summary"]["counts"]["tested"] == 1
        assert document["summary"]["counts"]["not_tested"] == 0

    asyncio.run(run())


def test_blocked_primary_never_automatically_tries_an_alternative():
    async def run():
        alternate = replace(github(), id="alternative", probe_url=None)
        registry = prepared_registry(SiteRegistry([alternate, github()]))
        plan = select_services(registry, "JanKowalski")
        transport = FakeTransport(
            handler=lambda request, index: response({"message": "denied"}, 403)
        )
        async with UsernameEngine(registry, transport) as engine:
            results = [r async for r in engine.search_stream("JanKowalski", site_ids=plan.selected)]
        assert transport.total == 1
        assert len(results) == 1 and results[0].detection.state == "BLOCKED"

    asyncio.run(run())
