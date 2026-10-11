import asyncio
import json
import time
from dataclasses import replace

from ultimate_username.domain.models import (
    DetectionSpec,
    ExtractionRule,
    ExtractionState,
    Rule,
    SiteDefinition,
    TransportResponse,
    Verdict,
)
from ultimate_username.engine import UsernameEngine
from ultimate_username.extraction import (
    ExtractionConfig,
    ExtractionService,
    extract,
    patreon_bootstrap,
)
from ultimate_username.registry import SiteRegistry
from ultimate_username.transport import FakeTransport


def response(body):
    return TransportResponse(
        "https://example.test/u/alice", 200, body, final_url="https://example.test/u/alice"
    )


def test_malformed_empty_then_matching_extractor_continues():
    rules = (
        ExtractionRule("broken", "json", path=("field",)),
        ExtractionRule("empty", "regex", pattern="not_here=(.*)"),
        ExtractionRule("good", "regex", pattern=r"name=(\w+)"),
    )
    result = extract(response(b"name=alice"), "alice", rules)
    assert result.state == ExtractionState.PARTIAL
    assert [(f.name, f.value()) for f in result.fields] == [("good", "alice")]
    assert result.errors[0].phase == "extraction"


def test_typed_values_and_conflicting_observations_do_not_alias():
    rules = (
        ExtractionRule("same", "json", path=("zero",)),
        ExtractionRule("same", "json", path=("false",)),
        ExtractionRule("list", "json", path=("list",)),
        ExtractionRule("string", "json", path=("string",)),
    )
    first = extract(response(b'{"zero":0,"false":false,"list":[1],"string":"[x]"}'), "alice", rules)
    second = extract(response(b'{"zero":7,"false":true}'), "bob", rules)
    assert [f.value() for f in first.fields] == [0, False, [1], "[x]"]
    assert second.fields[0].value() == 7 and first.fields[0].value() == 0


def test_exact_host_and_owner_guard_exclude_viewer():
    rules = (
        ExtractionRule(
            "owner_id",
            "json",
            path=("owner", "id"),
            owner_path=("owner", "name"),
            expected_host="example.test",
        ),
        ExtractionRule("viewer_id", "json", path=("viewer", "id"), owner_path=("viewer", "name")),
    )
    body = b'{"owner":{"name":"alice","id":12},"viewer":{"name":"bob","id":99}}'
    result = extract(response(body), "alice", rules)
    assert [(f.name, f.value(), f.relation) for f in result.fields] == [("owner_id", 12, "OWNER")]
    foreign = TransportResponse("https://evil.test/?next=https://example.test", 200, body)
    assert not extract(foreign, "alice", rules[:1]).fields


def test_discourse_and_xenforo_profile_guards_and_attribute_order():
    body = (
        b"<link href='https://example.test/u/alice' rel='canonical'>"
        b"<meta content='Bio' property='og:description'>"
    )
    rules = (ExtractionRule("bio", "discourse", path=("bio",)),)
    assert extract(response(body), "alice", rules).fields[0].value() == "Bio"
    assert not extract(response(body.replace(b"/u/alice", b"/t/topic")), "alice", rules).fields
    assert not extract(response(body), "bob", rules).fields
    xenforo = b'<meta content="https://example.test/members/alice.42/" property="og:url">'
    result = extract(response(xenforo), "alice", (ExtractionRule("id", "xenforo", path=("uid",)),))
    assert result.fields[0].value() == "42"


def test_patreon_rsc_byte_length_and_json_string_escaping():
    value = 'żółć "quoted"'
    stream = (
        "\n1:T"
        + format(len(value.encode("utf-8")), "x")
        + ","
        + value
        + '\n0:{"pageBootstrap":{"bio":"$1","n":0}}'
    )
    html = "self.__next_f.push([1," + json.dumps(stream) + "])"
    assert patreon_bootstrap(html) == {"bio": value, "n": 0}


def slow_worker(connection, response, username, rules):
    time.sleep(5)


def test_parser_process_deadline_preserves_found_and_base_committed_first():
    async def run():
        service = ExtractionService(ExtractionConfig(timeout=0.08), worker=slow_worker)
        definition = SiteDefinition(
            "test",
            "Test",
            "https://example.test/u/{username}",
            DetectionSpec(
                present=Rule("message", "profile"), binding=Rule("redirect", "{profile_url}")
            ),
            extractors=(ExtractionRule("name", "regex", pattern="name=(.*)"),),
        )
        events = []
        transport = FakeTransport(
            handler=lambda r, i: TransportResponse(r.url, 200, b"profile name=alice")
        )
        async with UsernameEngine(
            SiteRegistry([definition]), transport, extraction=service, sink=events.append
        ) as engine:
            result = (await engine.search("alice"))[0]
            assert result.detection.verdict == Verdict.FOUND
            assert result.enrichment.state == ExtractionState.TIMEOUT
            assert events[0].enrichment.state == ExtractionState.SKIPPED
            assert events[0].detection.verdict == Verdict.FOUND
            assert not engine._enrichment_inputs
        assert service.active == 0

    asyncio.run(run())


def test_process_success_and_cancellation_cleanup():
    async def run():
        service = ExtractionService()
        rules = (ExtractionRule("name", "json", path=("name",)),)
        result = await service.run(response(b'{"name":"alice"}'), "alice", rules)
        assert result.fields[0].value() == "alice"
        slow = ExtractionService(worker=slow_worker)
        task = asyncio.create_task(slow.run(response(b"{}"), "alice", rules))
        await asyncio.sleep(0.03)
        task.cancel()
        try:
            await task
        except asyncio.CancelledError:
            pass
        assert slow.active == 0

    asyncio.run(run())


def test_missing_profile_with_nonempty_extraction_remains_missing():
    async def run():
        definition = SiteDefinition(
            "x",
            "X",
            "https://example.test/{username}",
            DetectionSpec(absent=Rule("message", "missing")),
            extractors=(ExtractionRule("name", "json", path=("name",)),),
        )
        fake = FakeTransport(
            handler=lambda r, i: TransportResponse(r.url, 200, b'{"missing":true,"name":"alice"}')
        )
        async with UsernameEngine(SiteRegistry([definition]), fake) as engine:
            result = (await engine.search("alice"))[0]
            assert result.enrichment.fields[0].value() == "alice"
            assert result.detection.verdict == Verdict.NOT_FOUND

    asyncio.run(run())


def test_slow_parser_does_not_block_another_http_job():
    async def run():
        slow = SiteDefinition(
            "slow",
            "Slow",
            "https://example.test/{username}",
            DetectionSpec(Rule("message", "profile"), binding=Rule("redirect", "{profile_url}")),
            extractors=(ExtractionRule("name", "json", path=("name",)),),
        )
        quick = replace(slow, id="quick", extractors=())
        service = ExtractionService(ExtractionConfig(timeout=0.3), worker=slow_worker)
        started = asyncio.Event()
        fake = FakeTransport(handler=lambda r, i: TransportResponse(r.url, 200, b"profile"))
        async with UsernameEngine(
            SiteRegistry([slow, quick]),
            fake,
            extraction=service,
            metrics=lambda m: (
                started.set() if m.event == "result" and m.site_id == "slow" else None
            ),
        ) as engine:
            blocked = asyncio.create_task(engine.search_sites("alice", ["slow"]))
            await started.wait()
            result = await asyncio.wait_for(engine.search_sites("bob", ["quick"]), 0.15)
            assert result[0].detection.verdict == Verdict.FOUND
            assert not blocked.done()
            await blocked

    asyncio.run(run())
