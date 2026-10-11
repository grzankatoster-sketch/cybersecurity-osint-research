import asyncio
from dataclasses import replace
from time import monotonic

import pytest

from ultimate_username.detection import DetectionEngine
from ultimate_username.domain.codec import from_json, to_json
from ultimate_username.domain.models import (
    DetectionSpec,
    ErrorCode,
    ExecutionState,
    RateProfile,
    RetryPolicy,
    Rule,
    SearchResult,
    SiteDefinition,
    TimeoutProfile,
    TransportResponse,
    Verdict,
)
from ultimate_username.engine import SearchOptions, UsernameEngine
from ultimate_username.planning import plan_request
from ultimate_username.registry import SiteRegistry
from ultimate_username.scheduler import SchedulerConfig
from ultimate_username.transport import FakeTransport


def site(i=0, **changes):
    return SiteDefinition(
        str(i),
        str(i),
        f"https://h{i % 4}.test/{{username}}",
        DetectionSpec(
            Rule("message", "profile"),
            Rule("message", "missing"),
            Rule("redirect", "{profile_url}"),
        ),
        **changes,
    )


@pytest.mark.parametrize("strategy", ["status", "message", "regex", "json", "redirect", "header"])
@pytest.mark.parametrize(
    ("status", "expected"),
    [
        (403, ExecutionState.BLOCKED),
        (429, ExecutionState.RATE_LIMITED),
        (500, ExecutionState.SERVER_ERROR),
    ],
)
def test_failure_gate_for_every_detector(strategy, status, expected):
    rule = {
        "status": Rule("status", statuses=(200,)),
        "message": Rule("message", "profile"),
        "regex": Rule("regex", "profile"),
        "json": Rule("json", '"profile"', path=("name",)),
        "redirect": Rule("redirect", "{profile_url}"),
        "header": Rule("header", "profile", scope="X-User"),
    }[strategy]
    plan = plan_request("alice", replace(site(), detection=DetectionSpec(present=rule)), "test")
    result = DetectionEngine().detect(
        TransportResponse(
            plan.request.url, status, b'{"name":"profile"}', final_url=plan.profile_url
        ),
        plan,
    )
    assert result.verdict == Verdict.UNKNOWN and result.state == expected


def test_generic_cloudflare_captcha_mentions_and_escaped_unicode():
    plan = plan_request("Żółć", site(), "test")
    response = TransportResponse(
        plan.request.url,
        200,
        b"profile discusses captcha and cloudflare",
        final_url=plan.profile_url,
    )
    assert DetectionEngine().detect(response, plan).verdict == Verdict.FOUND
    plan = replace(
        plan,
        site=replace(
            plan.site,
            detection=DetectionSpec(
                Rule("json", "{username}", path=("name",)),
                binding=Rule("redirect", "{profile_url}"),
            ),
        ),
    )
    response = replace(response, body=rb'{"name":"\u017b\u00f3\u0142\u0107"}')
    assert DetectionEngine().detect(response, plan).verdict == Verdict.FOUND


def test_exception_timeout_and_success_produce_three_terminal_records():
    async def run():
        def handler(request, index):
            if request.url.startswith("https://h1."):
                raise ValueError("fixture")
            return TransportResponse(request.url, 200, b"profile")

        transport = FakeTransport(handler=handler, delay=0.005)
        registry = SiteRegistry([site(0), site(1), site(2, timeout=TimeoutProfile(total=0.001))])
        async with UsernameEngine(registry, transport) as engine:
            results = await engine.search("alice")
            assert len(results) == 3
            assert {r.detection.state for r in results} == {
                ExecutionState.OK,
                ExecutionState.INTERNAL_ERROR,
                ExecutionState.TIMEOUT,
            }
            for result in results:
                assert from_json(SearchResult, to_json(result)) == result

    asyncio.run(run())


def test_hundred_lifecycles_leave_no_tasks_and_counters_are_per_job():
    async def run():
        registry = SiteRegistry(site(i) for i in range(3))
        for _ in range(100):
            transport = FakeTransport(
                handler=lambda r, i: TransportResponse(r.url, 200, b"profile")
            )
            async with UsernameEngine(registry, transport) as engine:
                for name in ("A", "a"):
                    results = await engine.search(name)
                    assert len(results) == 3
                    assert all(r.username.raw == name for r in results)
                assert [s.emitted for s in engine.summaries] == [3, 3]
                assert engine.summaries[0].job_id != engine.summaries[1].job_id
            assert transport.closed
        assert not [t for t in asyncio.all_tasks() if t.get_name().startswith("uee-")]

    asyncio.run(run())


def test_slow_first_completion_stream_and_ten_thousand_bounded():
    class Delayed(FakeTransport):
        async def send(self, request):
            if request.url.startswith("https://h0."):
                await asyncio.sleep(0.01)
            return await super().send(request)

    async def run():
        transport = Delayed(handler=lambda r, i: TransportResponse(r.url, 200, b"profile"))
        registry = SiteRegistry(site(i, rate=RateProfile(4)) for i in range(10000))
        config = SchedulerConfig(concurrency=8, per_origin=4, queue_capacity=32, job_buffer=32)
        async with UsernameEngine(registry, transport, config=config) as engine:
            stream = engine.search_stream("alice", options=SearchOptions(job_timeout=120))
            first = await anext(stream)
            assert first.site_id != "0"
            count = 1
            async for _ in stream:
                count += 1
            assert count == 10000
            assert engine.scheduler.stats.peak_pending <= 32
            assert engine.scheduler.stats.peak_tasks <= 9
            assert transport.peak_active <= 8

    asyncio.run(run())


def test_retry_cooldown_does_not_occupy_worker_or_starve_healthy_origin():
    async def run():
        events = []

        def handler(request, index):
            events.append((request.url, monotonic()))
            if request.url.startswith("https://h0."):
                return TransportResponse(request.url, 429, headers=(("Retry-After", ".02"),))
            return TransportResponse(request.url, 200, b"profile")

        retry = RetryPolicy(2, base_delay=0, max_delay=0)
        transport = FakeTransport(handler=handler)
        config = SchedulerConfig(concurrency=1, max_jobs=4, queue_capacity=8, job_buffer=4)
        async with UsernameEngine(
            SiteRegistry([site(0, retry=retry), site(1)]), transport, config=config
        ) as engine:
            results = await asyncio.gather(*(engine.search(f"u{i}") for i in range(4)))
            assert all(len(r) == 2 for r in results)
            blocked = [t for u, t in events if u.startswith("https://h0.")]
            assert all(b - a >= 0.018 for a, b in zip(blocked, blocked[1:], strict=False))
            assert "https://h1." in events[1][0]
            assert engine.scheduler.stats.peak_active == 1

    asyncio.run(run())


def test_slow_cancellation_cleanup_holds_slot():
    class CleanupTransport(FakeTransport):
        async def send(self, request):
            self.active += 1
            self.peak_active = max(self.active, self.peak_active)
            try:
                await asyncio.sleep(1)
            finally:
                await asyncio.sleep(0.01)
                self.active -= 1

    async def run():
        transport = CleanupTransport()
        registry = SiteRegistry(site(i, timeout=TimeoutProfile(total=0.005)) for i in range(4))
        async with UsernameEngine(
            registry, transport, config=SchedulerConfig(concurrency=1)
        ) as engine:
            results = await engine.search("alice")
            assert all(r.detection.state == ExecutionState.TIMEOUT for r in results)
            assert transport.peak_active == 1 and transport.active == 0

    asyncio.run(run())


def test_queue_job_deadlines_and_admission_limit():
    async def run():
        transport = FakeTransport(handler=lambda r, i: TransportResponse(r.url, 200), delay=0.02)
        registry = SiteRegistry([site(0), site(1, timeout=TimeoutProfile(queue=0.001))])
        config = SchedulerConfig(concurrency=1, max_jobs=1)
        async with UsernameEngine(registry, transport, config=config) as engine:
            task = asyncio.create_task(engine.search("alice"))
            await asyncio.sleep(0.001)
            with pytest.raises(ValueError, match="Maximum concurrent jobs"):
                await engine.search("bob")
            results = await task
            assert any(
                r.detection.errors and r.detection.errors[0].code == ErrorCode.QUEUE_TIMEOUT
                for r in results
            )
            values = await engine.search("alice", options=SearchOptions(job_timeout=0.001))
            assert any(
                r.detection.errors and r.detection.errors[0].code == ErrorCode.JOB_TIMEOUT
                for r in values
            )

    asyncio.run(run())
