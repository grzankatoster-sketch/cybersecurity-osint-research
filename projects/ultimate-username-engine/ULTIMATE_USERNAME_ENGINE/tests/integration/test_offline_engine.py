import asyncio
from dataclasses import replace

import pytest

from ultimate_username.domain.models import (
    DetectionSpec,
    ErrorCode,
    ExecutionState,
    HttpMethod,
    RateProfile,
    RedirectPolicy,
    RetryPolicy,
    Rule,
    SearchError,
    SiteDefinition,
    TimeoutProfile,
    TransportResponse,
    Verdict,
)
from ultimate_username.engine import SearchOptions, UsernameEngine
from ultimate_username.registry import SiteRegistry
from ultimate_username.scheduler import SchedulerConfig
from ultimate_username.transport import FakeTransport


def site(i=0, **kwargs):
    return SiteDefinition(
        str(i),
        f"Site {i}",
        f"https://h{i % 4}.test/{{username}}",
        DetectionSpec(
            present=Rule("message", "profile"), binding=Rule("redirect", "{profile_url}")
        ),
        **kwargs,
    )


def good(request, index):
    return TransportResponse(request.url, 200, b"profile")


def test_bounded_parallel_jobs_and_complete_results():
    async def run():
        transport = FakeTransport(handler=good, delay=0.001)
        registry = SiteRegistry(site(i, rate=RateProfile(3)) for i in range(100))
        config = SchedulerConfig(
            concurrency=7, per_origin=2, per_job=4, queue_capacity=20, job_buffer=12
        )
        async with UsernameEngine(registry, transport, config=config) as engine:
            first, second = await asyncio.gather(engine.search("alice"), engine.search("bob"))
            assert len(first) == len(second) == 100
            assert all(r.detection.verdict == Verdict.FOUND for r in first + second)
            assert len({r.task_id for r in first + second}) == 200
            assert transport.peak_active <= 7
            assert max(transport.peak_origins.values()) <= 2
            assert engine.scheduler.stats.peak_pending <= 20
            assert engine.scheduler.stats.peak_tasks <= 8
        assert transport.closed and transport.active == 0
        assert not [t for t in asyncio.all_tasks() if t.get_name().startswith("uee-")]

    asyncio.run(run())


def test_retry_transient_errors_and_preserve_attempts():
    async def run():
        definition = site(
            retry=RetryPolicy(max_attempts=3, base_delay=0.001, max_delay=0.01, jitter=False)
        )
        url = "https://h0.test/alice"
        transport = FakeTransport(
            {
                url: [
                    TransportResponse(url, 429, headers=(("Retry-After", ".01"),)),
                    TransportResponse(url, 503),
                    good(type("R", (), {"url": url}), 0),
                ]
            }
        )
        async with UsernameEngine(SiteRegistry([definition]), transport) as engine:
            result = (await engine.search("alice"))[0]
            assert result.detection.verdict == Verdict.FOUND
            assert [a.status for a in result.attempts] == [429, 503, 200]
            assert result.attempts[0].retry_after == ".01"

    asyncio.run(run())


@pytest.mark.parametrize("status", [403, 404, 401])
def test_non_retryable_status_not_retried(status):
    async def run():
        transport = FakeTransport(handler=lambda r, i: TransportResponse(r.url, status))
        async with UsernameEngine(SiteRegistry([site(retry=RetryPolicy(3))]), transport) as engine:
            result = (await engine.search("alice"))[0]
            assert len(result.attempts) == transport.total == 1

    asyncio.run(run())


def test_cancel_awaits_active_requests_and_other_job_survives():
    async def run():
        transport = FakeTransport(handler=good, delay=0.015)
        async with UsernameEngine(SiteRegistry(site(i) for i in range(80)), transport) as engine:
            cancelled = asyncio.create_task(engine.search("alice"))
            surviving = asyncio.create_task(engine.search_sites("bob", ["1"]))
            await asyncio.sleep(0.005)
            cancelled.cancel()
            with pytest.raises(asyncio.CancelledError):
                await cancelled
            assert len(await surviving) == 1
        assert transport.active == 0
        assert not [t for t in asyncio.all_tasks() if t.get_name().startswith("uee-")]

    asyncio.run(run())


def test_stream_early_close_cancels_queued_and_active():
    async def run():
        transport = FakeTransport(handler=good)
        async with UsernameEngine(SiteRegistry(site(i) for i in range(100)), transport) as engine:
            stream = engine.search_stream("alice")
            await anext(stream)
            await stream.aclose()
            assert transport.total < 100
            assert transport.active == 0

    asyncio.run(run())


def test_invalid_and_disabled_do_not_abort_valid_work():
    async def run():
        registry = SiteRegistry(
            [site(0), replace(site(1), profile_url="bad"), site(2, disabled=True)]
        )
        transport = FakeTransport(handler=good)
        async with UsernameEngine(registry, transport) as engine:
            results = {r.site_id: r for r in await engine.search("alice")}
            assert results["0"].detection.verdict == Verdict.FOUND
            assert results["1"].detection.state == ExecutionState.CONFIG_ERROR
            assert results["2"].detection.state == ExecutionState.SKIPPED
            assert transport.total == 1
            assert await engine.search_sites("alice", []) == []

    asyncio.run(run())


@pytest.mark.parametrize(
    "code",
    [
        ErrorCode.DNS_NOT_FOUND,
        ErrorCode.TLS_ERROR,
        ErrorCode.CONNECTION_RESET,
        ErrorCode.READ_TIMEOUT,
    ],
)
def test_fake_network_errors_not_missing(code):
    async def run():
        transport = FakeTransport(
            handler=lambda r, i: TransportResponse(
                r.url, error=SearchError(code, "network", "fixture")
            )
        )
        async with UsernameEngine(SiteRegistry([site()]), transport) as engine:
            result = (await engine.search("alice"))[0]
            assert result.detection.verdict == Verdict.UNKNOWN
            assert result.detection.state != ExecutionState.OK

    asyncio.run(run())


def test_attempt_deadline_and_budget_bound():
    async def run():
        transport = FakeTransport(handler=good, delay=0.02)
        registry = SiteRegistry([site(0, timeout=TimeoutProfile(total=0.001)), site(1)])
        async with UsernameEngine(
            registry, transport, config=SchedulerConfig(concurrency=1)
        ) as engine:
            results = await engine.search("alice", options=SearchOptions(request_budget=1))
            assert {r.detection.state for r in results} == {
                ExecutionState.TIMEOUT,
                ExecutionState.BUDGET_EXHAUSTED,
            }
            assert transport.total == 1

    asyncio.run(run())


def test_redirect_destination_rescheduled_and_auth_removed():
    async def run():
        def handler(request, index):
            if request.url.startswith("https://h0.test"):
                return TransportResponse(
                    request.url, 302, headers=(("Location", "https://dest.test/alice"),)
                )
            return good(request, index)

        definition = site(
            headers=(("Authorization", "secret"), ("X-Api-Key", "secret")),
            redirects=RedirectPolicy(True, allowed_origins=("https://dest.test",)),
        )
        transport = FakeTransport(handler=handler)
        async with UsernameEngine(SiteRegistry([definition]), transport) as engine:
            result = (await engine.search("alice"))[0]
            assert result.final_url == "https://dest.test/alice"
            assert len(result.attempts) == 2
            assert transport.requests[1].headers == ()
            assert "https://dest.test:443" in engine.scheduler.stats.origin_peak

    asyncio.run(run())


@pytest.mark.parametrize(
    ("status", "method", "body"),
    [(303, HttpMethod.GET, None), (307, HttpMethod.POST, b"x"), (308, HttpMethod.POST, b"x")],
)
def test_redirect_post_rules(status, method, body):
    async def run():
        def handler(request, index):
            return (
                TransportResponse(request.url, status, headers=(("Location", "/next"),))
                if index == 0
                else good(request, index)
            )

        definition = site(method=HttpMethod.POST, raw_body="x", redirects=RedirectPolicy(True))
        transport = FakeTransport(handler=handler)
        async with UsernameEngine(SiteRegistry([definition]), transport) as engine:
            await engine.search("alice")
            assert (transport.requests[1].method, transport.requests[1].body) == (method, body)

    asyncio.run(run())


def test_slow_consumer_backpressure_and_lazy_source():
    async def run():
        transport = FakeTransport(handler=good)
        config = SchedulerConfig(job_buffer=4, queue_capacity=4)
        async with UsernameEngine(
            SiteRegistry(site(i) for i in range(100)), transport, config=config
        ) as engine:
            stream = engine.search_stream("alice")
            await anext(stream)
            await asyncio.sleep(0.02)
            assert engine.scheduler.stats.admitted <= 5
            await stream.aclose()

    asyncio.run(run())
