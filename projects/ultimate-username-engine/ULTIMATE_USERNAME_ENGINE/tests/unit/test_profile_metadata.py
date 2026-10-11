import asyncio
import json
from dataclasses import replace
from pathlib import Path

import pytest

from ultimate_username.domain.codec import from_json, to_json
from ultimate_username.domain.metadata import EnrichmentMode, MetadataState, ProfileMetadata
from ultimate_username.domain.models import (
    DetectionResult,
    DetectionSpec,
    Rule,
    SiteDefinition,
    TransportResponse,
    Verdict,
)
from ultimate_username.engine import SearchOptions, UsernameEngine
from ultimate_username.enrichment import enrich, normalize_field
from ultimate_username.extraction import ExtractionConfig
from ultimate_username.profile_service import ProfileService
from ultimate_username.registry import SiteRegistry
from ultimate_username.scheduler import SchedulerConfig
from ultimate_username.transport import FakeTransport

CASES = json.loads(
    (Path(__file__).parents[1] / "fixtures/enrichment/cases.json").read_text(encoding="utf-8")
)


def fixture(case):
    site = SiteDefinition(
        case["id"], case["id"], case["url"], DetectionSpec(Rule("status", statuses=(200,)))
    )
    response = TransportResponse(
        case["url"],
        case["status"],
        case["body"].encode(),
        (
            (
                "Content-Type",
                "application/json" if case["kind"] == "json" else "text/html; charset=utf-8",
            ),
        ),
        case["url"],
    )
    return site, response


@pytest.mark.parametrize("case", CASES, ids=lambda c: c["id"])
def test_controlled_profile_corpus(case):
    site, response = fixture(case)
    result = enrich(response, case["username"], site, DetectionResult(Verdict.FOUND))
    values = {
        f.name: list(f.value) if isinstance(f.value, tuple) else f.value
        for f in result.fields + result.extra_fields
    }
    # This explicitly retained negative coverage case documents a donor capability not ported.
    if case["id"] == "patreon_rsc_not_ported":
        assert values == {}
    else:
        assert values == case["expected"]
    assert from_json(ProfileMetadata, to_json(result)) == result
    assert result.html_parse_count <= 1
    for candidate in result.candidates:
        assert candidate.source_site == site.id
        assert candidate.source_url == case["url"]
        assert candidate.evidence and candidate.observed_at and candidate.validation == "VALID"


@pytest.mark.regression("MAIGRET_ENRICHMENT_001", "MAIGRET_ENRICHMENT_002")
def test_generic_metadata_and_other_owner_are_rejected():
    for name in ("generic_site", "itch_generic", "wrong_owner", "jsonld_organization"):
        case = next(c for c in CASES if c["id"] == name)
        site, response = fixture(case)
        assert not enrich(response, "alice", site, DetectionResult(Verdict.FOUND)).fields


@pytest.mark.regression("MAIGRET_ENRICHMENT_003")
def test_malformed_json_does_not_suppress_other_extractors():
    case = next(c for c in CASES if c["id"] == "malformed_with_fallback")
    site, response = fixture(case)
    result = enrich(response, "alice", site, DetectionResult(Verdict.FOUND))
    assert result.state == MetadataState.PARTIAL and len(result.fields) == 5
    assert result.parser_failures == 1


@pytest.mark.regression("MAIGRET_ENRICHMENT_004")
def test_duplicates_preserved_and_priority_explained():
    case = next(c for c in CASES if c["id"] == "og_duplicates")
    site, response = fixture(case)
    result = enrich(response, "alice", site, DetectionResult(Verdict.FOUND))
    assert result.conflicts == ("display_name",)
    assert len([c for c in result.candidates if c.name == "display_name"]) == 2


@pytest.mark.regression("MAIGRET_ENRICHMENT_005")
def test_typed_zero_false_and_missing_remain_distinct():
    case = next(c for c in CASES if c["id"] == "empty_optional")
    site, response = fixture(case)
    result = enrich(response, "alice", site, DetectionResult(Verdict.FOUND))
    assert type(result.get("followers")) is int and result.get("followers") == 0
    assert result.get("verified") is False and result.get("bio") is None


@pytest.mark.regression("MAIGRET_ENRICHMENT_006")
def test_profile_state_is_not_viewer_state():
    case = next(c for c in CASES if c["id"] == "hydration_owner")
    site, response = fixture(case)
    assert (
        enrich(response, "alice", site, DetectionResult(Verdict.FOUND)).get("display_name")
        == "Alicja Testowa"
    )


@pytest.mark.regression("MAIGRET_ENRICHMENT_007")
@pytest.mark.parametrize(
    "value,expected",
    [("1.2K", 1200), ("1,2K", None), (-1, None), (True, None), ("1.23", None), ("0", 0)],
)
def test_counter_validation(value, expected):
    assert normalize_field("followers", value, "https://example.test/") == expected


@pytest.mark.regression("MAIGRET_ENRICHMENT_008")
def test_dates_do_not_invent_timezone_or_relative_dates():
    assert normalize_field("created_at", "2020-01-02", "https://example.test/") == "2020-01-02"
    assert normalize_field("created_at", "yesterday", "https://example.test/") is None
    assert (
        normalize_field("created_at", "2020-01-02T03:04:05", "https://example.test/")
        == "2020-01-02T03:04:05"
    )


@pytest.mark.regression("MAIGRET_ENRICHMENT_009")
def test_bound_response_reuses_one_html_parse():
    case = next(c for c in CASES if c["id"] == "og_profile")
    site, response = fixture(case)
    result = enrich(response, "alice", site, DetectionResult(Verdict.FOUND))
    assert result.html_parse_count == 1 and result.response_storage == "NONE"
    assert not hasattr(result, "body") and not hasattr(result, "document")


def definition(**kwargs):
    return SiteDefinition(
        "demo",
        "Demo",
        "https://demo.example.test/u/{username}",
        DetectionSpec(Rule("message", "profile"), binding=Rule("redirect", "{profile_url}")),
        enrichment_urls=("https://demo.example.test/api/{username}",),
        **kwargs,
    )


class InlineProfiles(ProfileService):
    async def run(self, response, username, site, detection):
        return enrich(response, username, site, detection)


@pytest.mark.parametrize(
    "mode,budget,requests,fields",
    [
        (EnrichmentMode.OFF, 1, 1, 0),
        (EnrichmentMode.BASIC, 1, 1, 2),
        (EnrichmentMode.FULL, 0, 1, 2),
        (EnrichmentMode.FULL, 1, 2, 3),
    ],
)
def test_modes_and_shared_scheduler_budget(mode, budget, requests, fields):
    async def run():
        def handler(request, index):
            body = (
                b'{"username":"alice","name":"Alicja","profile":true}'
                if index == 0
                else b'{"username":"alice","followers":12}'
            )
            return TransportResponse(
                request.url, 200, body, (("Content-Type", "application/json"),)
            )

        transport = FakeTransport(handler=handler)
        metrics = []
        async with UsernameEngine(
            SiteRegistry([definition()]),
            transport,
            profiles=InlineProfiles(),
            metrics=metrics.append,
            config=SchedulerConfig(concurrency=1, per_origin=1, per_job=1),
        ) as engine:
            result = (
                await engine.search(
                    "alice",
                    options=SearchOptions(enrichment_mode=mode, enrichment_request_budget=budget),
                )
            )[0]
            assert result.detection.verdict == Verdict.FOUND
            assert len(result.profile_metadata.fields) == fields
            assert engine.scheduler.stats.completed == 1
            assert engine.scheduler.stats.peak_active == 1
            assert len(result.attempts) + len(result.enrichment_attempts) == requests
            if mode != EnrichmentMode.OFF:
                assert {m.event for m in metrics} >= {
                    "enrichment_attempts",
                    "fields_extracted",
                    "parser_failures",
                    "extractor_failures",
                    "metadata_conflicts",
                    "enrichment_latency",
                }
            assert not engine._additional_inputs and not engine._enrichment_inputs

    asyncio.run(run())


@pytest.mark.regression("MAIGRET_ENRICHMENT_010")
@pytest.mark.parametrize("status", [301, 401, 403, 429, 500])
def test_followup_errors_never_change_detection_or_discard_base_fields(status):
    async def run():
        calls = []

        def handler(request, index):
            calls.append(request)
            return TransportResponse(
                request.url,
                200 if index == 0 else status,
                b'{"username":"alice","name":"Alicja","profile":true}',
                (("Content-Type", "application/json"), ("Location", "https://other.example.test/")),
            )

        events = []
        async with UsernameEngine(
            SiteRegistry([definition(headers=(("Authorization", "fixture"),))]),
            FakeTransport(handler=handler),
            profiles=InlineProfiles(),
            sink=events.append,
        ) as engine:
            result = (
                await engine.search(
                    "alice",
                    options=SearchOptions(
                        enrichment_mode=EnrichmentMode.FULL, enrichment_request_budget=1
                    ),
                )
            )[0]
        assert result.detection.verdict == Verdict.FOUND
        assert result.profile_metadata.get("display_name") == "Alicja"
        assert result.profile_metadata.state == MetadataState.PARTIAL
        assert len(calls) == 2 and calls[1].headers == ()
        assert (
            events[0].detection.verdict == Verdict.FOUND
            and events[0].profile_metadata.state == MetadataState.SKIPPED
        )

    asyncio.run(run())


def test_registry_rejects_unbounded_or_cross_origin_followups():
    for urls in [
        ("https://other.test/{username}",),
        ("https://demo.example.test/a", "https://demo.example.test/b"),
    ]:
        entry = SiteRegistry([replace(definition(), enrichment_urls=urls)]).entries[0]
        assert entry.issues


def test_process_deadline_and_success():
    async def run():
        case = next(c for c in CASES if c["id"] == "og_profile")
        site, response = fixture(case)
        result = await ProfileService().run(response, "alice", site, DetectionResult(Verdict.FOUND))
        assert result.get("username") == "alice"
        timed = await ProfileService(ExtractionConfig(timeout=0.00001)).run(
            response, "alice", site, DetectionResult(Verdict.FOUND)
        )
        assert timed.state == MetadataState.TIMEOUT

    asyncio.run(run())


def test_plugin_failure_preserves_other_fields():
    from ultimate_username.enrichment import EXTRACTORS

    class Broken:
        def extract(self, document, context):
            raise ValueError("controlled")

    case = next(c for c in CASES if c["id"] == "og_profile")
    site, response = fixture(case)
    result = enrich(
        response, "alice", site, DetectionResult(Verdict.FOUND), extractors=(*EXTRACTORS, Broken())
    )
    assert result.state == MetadataState.PARTIAL and len(result.fields) == 5
    assert result.extractor_failures == 1


@pytest.mark.regression("MAIGRET_ENRICHMENT_011")
def test_body_limit_and_unicode_encoding():
    case = next(c for c in CASES if c["id"] == "og_profile")
    site, response = fixture(case)
    assert (
        enrich(
            replace(response, body=b"x" * 1048577), "alice", site, DetectionResult(Verdict.FOUND)
        ).state
        == MetadataState.ERROR
    )
    result = enrich(replace(response, body=b"\xff"), "alice", site, DetectionResult(Verdict.FOUND))
    assert result.state == MetadataState.ERROR and result.parser_failures == 1


@pytest.mark.regression("MAIGRET_ENRICHMENT_012")
def test_no_email_inference_from_username():
    case = next(c for c in CASES if c["id"] == "github_json")
    site, response = fixture(case)
    assert enrich(response, "alice", site, DetectionResult(Verdict.FOUND)).get("email") is None


def test_api_resource_url_does_not_replace_public_profile_url():
    case = next(c for c in CASES if c["id"] == "github_json")
    site, response = fixture(case)
    data = json.loads(response.body)
    data = {"url": "https://api.github.com/users/alice", **data}
    result = enrich(
        replace(response, body=json.dumps(data).encode()),
        "alice",
        site,
        DetectionResult(Verdict.FOUND),
    )
    assert result.get("profile_url") == case["url"]


def test_probable_detection_stays_probable_with_bound_metadata():
    async def run():
        site = replace(definition(), detection=DetectionSpec(Rule("status", statuses=(200,))))
        fake = FakeTransport(
            handler=lambda r, i: TransportResponse(
                r.url, 200, b'{"username":"alice","followers":0}'
            )
        )
        async with UsernameEngine(SiteRegistry([site]), fake, profiles=InlineProfiles()) as engine:
            result = (
                await engine.search(
                    "alice", options=SearchOptions(enrichment_mode=EnrichmentMode.BASIC)
                )
            )[0]
        assert result.detection.verdict == Verdict.PROBABLE
        assert result.profile_metadata.get("followers") == 0

    asyncio.run(run())


def test_full_second_parser_deadline_keeps_base_metadata():
    class SlowSecond(InlineProfiles):
        async def run(self, response, username, site, detection):
            if "/api/" in response.requested_url:
                await asyncio.sleep(1)
            return await super().run(response, username, site, detection)

    async def run():
        fake = FakeTransport(
            handler=lambda r, i: TransportResponse(
                r.url, 200, b'{"username":"alice","name":"Alicja","profile":true}'
            )
        )
        async with UsernameEngine(
            SiteRegistry([definition()]), fake, profiles=SlowSecond()
        ) as engine:
            result = (
                await engine.search(
                    "alice",
                    options=SearchOptions(
                        job_timeout=0.05,
                        enrichment_mode=EnrichmentMode.FULL,
                        enrichment_request_budget=1,
                    ),
                )
            )[0]
            assert result.detection.verdict == Verdict.FOUND
            assert result.profile_metadata.get("display_name") == "Alicja"
            assert result.profile_metadata.state == MetadataState.PARTIAL
            assert not engine._additional_inputs

    asyncio.run(run())


def test_profile_process_cancellation_releases_slot():
    async def run():
        case = next(c for c in CASES if c["id"] == "og_profile")
        site, response = fixture(case)
        service = ProfileService(ExtractionConfig(workers=1))
        task = asyncio.create_task(
            service.run(response, "alice", site, DetectionResult(Verdict.FOUND))
        )
        await asyncio.sleep(0.001)
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
        result = await asyncio.wait_for(
            service.run(response, "alice", site, DetectionResult(Verdict.FOUND)), 4
        )
        assert result.get("username") == "alice"

    asyncio.run(run())


def test_document_is_released_without_waiting_for_cyclic_gc(monkeypatch):
    import gc
    import weakref

    import ultimate_username.enrichment as module

    original = module.ParsedDocument
    references = []

    def capture(response):
        document = original(response)
        references.append(weakref.ref(document))
        return document

    monkeypatch.setattr(module, "ParsedDocument", capture)
    case = next(c for c in CASES if c["id"] == "jsonld_profile")
    site, response = fixture(case)
    enabled = gc.isenabled()
    gc.disable()
    try:
        result = enrich(response, "alice", site, DetectionResult(Verdict.FOUND))
        assert result.fields
        assert all(reference() is None for reference in references)
    finally:
        if enabled:
            gc.enable()
