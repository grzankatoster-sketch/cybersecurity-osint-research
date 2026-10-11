"""F3.4: per-request retry of transient failures and the closing rescan_errors pass."""

from __future__ import annotations

import asyncio
from dataclasses import replace

import pytest

from ultimate_username.cli import parser
from ultimate_username.domain.models import (
    DetectionSpec,
    ErrorCode,
    ExecutionState,
    HttpMethod,
    RetryPolicy,
    Rule,
    SearchError,
    SiteDefinition,
    TransportResponse,
)
from ultimate_username.engine import SearchOptions, UsernameEngine
from ultimate_username.registry import SiteRegistry
from ultimate_username.runtime_policy import MODES, RuntimePolicy, runtime_selection
from ultimate_username.scheduler import SchedulerConfig
from ultimate_username.selection import select_services
from ultimate_username.transport import FakeTransport


def site(sid="a", host="a.test", **changes):
    base = SiteDefinition(
        sid,
        sid,
        f"https://{host}/u/{{username}}",
        DetectionSpec(
            Rule("message", "owner={username}"),
            Rule("message", "no such account"),
            Rule("message", "owner={username}"),
        ),
        probe_url=f"https://{host}/api/{{username}}",
    )
    return replace(base, **changes)


def failure(request, code=ErrorCode.CONNECTION_RESET, retryable=True):
    return TransportResponse(request.url, error=SearchError(code, "transport", "x", retryable))


def ok(request):
    return TransportResponse(request.url, 200, b"owner=alice", (), request.url)


def status(request, code):
    return TransportResponse(request.url, code, b"", (), request.url)


def policy(**changes):
    values = dict(
        request_budget=50,
        retry_budget=10,
        transient_retries=2,
        rescan_errors=False,
        retry_min_delay=0.01,
        rate_limit_seconds=0.02,
    )
    values.update(changes)
    return RuntimePolicy(**values)


async def run(sites, handler, runtime, *, config=None, delay=0, metrics=None, seed=None):
    registry = SiteRegistry(sites)
    assert not [e for e in registry.entries if e.issues]
    selection = runtime_selection(registry, select_services(registry, "alice"), runtime)
    transport = FakeTransport(handler=handler, delay=delay)
    journal = []
    async with UsernameEngine(
        registry,
        transport,
        config=config,
        sink=journal.append,
        metrics=metrics,
        random_seed=seed,
    ) as engine:
        results = [
            r
            async for r in engine.search_stream(
                "alice",
                site_ids=selection.selected,
                options=SearchOptions(request_budget=runtime.request_budget),
                runtime=runtime,
                selection=selection,
            )
        ]
        summary = engine.summaries[-1]
    return results, transport, summary, journal


def test_transient_error_then_success_is_one_retry():
    results, transport, summary, _ = asyncio.run(
        run([site()], lambda r, i: failure(r) if i == 0 else ok(r), policy())
    )
    assert results[0].detection.verdict == "FOUND"
    assert transport.total == 2
    assert dict(summary.request_counts) == {"PRIMARY_CHECK": 1, "RETRY": 1}


def test_at_most_two_retries_then_the_error_stays():
    results, transport, summary, _ = asyncio.run(run([site()], lambda r, i: failure(r), policy()))
    assert transport.total == 3
    assert dict(summary.request_counts) == {"PRIMARY_CHECK": 1, "RETRY": 2}
    assert results[0].detection.state == ExecutionState.NETWORK_ERROR


@pytest.mark.parametrize("code", [502, 503, 504])
def test_gateway_statuses_are_retried(code):
    results, transport, _, _ = asyncio.run(
        run([site()], lambda r, i: status(r, code) if i < 2 else ok(r), policy())
    )
    assert transport.total == 3 and results[0].detection.verdict == "FOUND"


@pytest.mark.parametrize(
    "code", [ErrorCode.CONNECT_TIMEOUT, ErrorCode.READ_TIMEOUT, ErrorCode.DNS_TEMPORARY]
)
def test_timeouts_and_temporary_dns_are_retried(code):
    results, transport, _, _ = asyncio.run(
        run([site()], lambda r, i: failure(r, code) if i == 0 else ok(r), policy())
    )
    assert transport.total == 2 and results[0].detection.verdict == "FOUND"


@pytest.mark.parametrize("code", [ErrorCode.DNS_NOT_FOUND, ErrorCode.TLS_ERROR])
def test_permanent_network_errors_are_not_retried(code):
    results, transport, _, _ = asyncio.run(
        run([site()], lambda r, i: failure(r, code, retryable=False), policy(rescan_errors=True))
    )
    assert transport.total == 1  # no retry and no rescan either
    assert results[0].detection.state == ExecutionState.NETWORK_ERROR


def test_plain_500_and_404_keep_the_site_policy():
    for code in (500, 404):
        _, transport, _, _ = asyncio.run(run([site()], lambda r, i, c=code: status(r, c), policy()))
        assert transport.total == 1


def test_retries_spend_the_retry_budget():
    _, transport, summary, _ = asyncio.run(
        run([site()], lambda r, i: failure(r), policy(retry_budget=1))
    )
    assert transport.total == 2 and dict(summary.request_counts)["RETRY"] == 1


def test_retries_spend_the_request_budget_too():
    _, transport, _, _ = asyncio.run(
        run([site()], lambda r, i: failure(r), policy(request_budget=2))
    )
    assert transport.total == 2


def test_no_transient_retries_by_default_or_when_zero():
    assert RuntimePolicy().transient_retries == 0
    _, transport, _, _ = asyncio.run(
        run([site()], lambda r, i: failure(r), policy(transient_retries=0))
    )
    assert transport.total == 1


def test_site_policy_can_still_allow_more_attempts():
    wide = site(retry=RetryPolicy(max_attempts=4, base_delay=0, max_delay=0))
    _, transport, _, _ = asyncio.run(run([wide], lambda r, i: failure(r), policy()))
    assert transport.total == 4


def test_non_idempotent_post_is_not_retried():
    post = site(method=HttpMethod.POST, json_body='{"u": "{username}"}')
    _, transport, _, _ = asyncio.run(run([post], lambda r, i: failure(r), policy()))
    assert transport.total == 1


def test_delay_is_exponential_and_jittered_with_the_engine_random():
    delays = []

    def metrics(metric):
        if metric.event == "retry":
            delays.append(metric.elapsed)

    class Half:
        @staticmethod
        def random():
            return 0.5

    slow = site(retry=RetryPolicy(max_attempts=1, base_delay=0.2, max_delay=5))

    async def scenario():
        registry = SiteRegistry([slow])
        runtime = policy(retry_min_delay=0.001)
        selection = runtime_selection(registry, select_services(registry, "alice"), runtime)
        transport = FakeTransport(handler=lambda r, i: failure(r))
        async with UsernameEngine(registry, transport, metrics=metrics) as engine:
            engine.random = Half()  # type: ignore[assignment]
            async for _ in engine.search_stream(
                "alice", site_ids=selection.selected, runtime=runtime, selection=selection
            ):
                pass

    asyncio.run(scenario())
    assert delays == pytest.approx([0.1, 0.2])  # base * 2**(n-1) * jitter(0.5)


def test_rescan_replaces_a_transient_error_with_a_later_success():
    runtime = policy(transient_retries=0, rescan_errors=True)
    results, transport, summary, journal = asyncio.run(
        run([site()], lambda r, i: failure(r) if i == 0 else ok(r), runtime)
    )
    assert len(results) == 1 and results[0].detection.verdict == "FOUND"
    assert transport.total == 2
    assert dict(summary.request_counts) == {"PRIMARY_CHECK": 1, "RESCAN_CHECK": 1}
    assert [a.budget_reason for a in results[0].attempts] == ["PRIMARY_CHECK", "RESCAN_CHECK"]
    # F3.6: continuous numbering and the original observation stays in the chain
    assert [a.number for a in results[0].attempts] == [1, 2]
    assert [o.role for o in results[0].fallback_chain] == ["PRIMARY_CHECK", "RESCAN_CHECK"]
    # one journal row per task, and the last one is the success under the original ids
    rows = [r for r in journal if r.task_id == results[0].task_id]
    assert rows[-1].detection.state == ExecutionState.OK
    assert rows[-1].job_id == results[0].job_id
    assert not [r for r in journal if r.job_id.endswith(":rescan")]


def test_post_with_a_timeout_is_not_rescanned():
    post = site(method=HttpMethod.POST, json_body='{"u": "{username}"}')
    runtime = policy(transient_retries=0, rescan_errors=True)
    timeout = lambda r, i: failure(r, ErrorCode.READ_TIMEOUT)  # noqa: E731
    results, transport, summary, _ = asyncio.run(run([post], timeout, runtime))
    assert transport.total == 1 and "RESCAN_CHECK" not in dict(summary.request_counts)
    assert results[0].detection.state in (ExecutionState.TIMEOUT, ExecutionState.NETWORK_ERROR)
    get_results, get_transport, _, _ = asyncio.run(run([site()], timeout, runtime))
    assert get_transport.total == 2  # the same failure on a GET is looked at once more
    idempotent = site(method=HttpMethod.POST, json_body='{"u": "{username}"}', idempotent=True)
    _, idem_transport, _, _ = asyncio.run(run([idempotent], timeout, runtime))
    assert idem_transport.total == 2


def test_held_error_is_journalled_before_the_rescan_and_overwritten_after_it():
    journal: list = []
    seen: dict = {}

    def handler(request, index):
        if index == 0:
            return failure(request)
        seen["at_rescan"] = [(r.task_id, r.detection.state) for r in journal]
        return ok(request)

    async def scenario():
        runtime = policy(transient_retries=0, rescan_errors=True)
        registry = SiteRegistry([site()])
        selection = runtime_selection(registry, select_services(registry, "alice"), runtime)
        async with UsernameEngine(
            registry, FakeTransport(handler=handler), sink=journal.append
        ) as engine:
            return [
                r
                async for r in engine.search_stream(
                    "alice",
                    site_ids=selection.selected,
                    options=SearchOptions(request_budget=50),
                    runtime=runtime,
                    selection=selection,
                )
            ]

    (final,) = asyncio.run(scenario())
    # an interruption during the rescan leaves the ERROR in the journal ...
    assert [state for _, state in seen["at_rescan"]] == [ExecutionState.NETWORK_ERROR]
    # ... and the success replaces it under the same task id
    assert {r.task_id for r in journal} == {final.task_id}
    assert journal[-1].detection.state == ExecutionState.OK


def test_persistent_error_stays_and_is_not_overwritten_in_the_journal():
    runtime = policy(transient_retries=0, rescan_errors=True)
    results, transport, summary, journal = asyncio.run(
        run([site()], lambda r, i: failure(r), runtime)
    )
    assert transport.total == 2 and len(results) == 1
    assert results[0].detection.state == ExecutionState.NETWORK_ERROR
    assert len(results[0].attempts) == 1  # the original result, untouched
    assert dict(summary.request_counts) == {"PRIMARY_CHECK": 1, "RESCAN_CHECK": 1}
    assert {r.detection.state for r in journal} == {ExecutionState.NETWORK_ERROR}
    assert all(not r.job_id.endswith(":rescan") for r in journal)


def test_rescan_failing_for_budget_keeps_the_original_error():
    runtime = policy(transient_retries=0, rescan_errors=True, request_budget=1)
    results, transport, _, journal = asyncio.run(run([site()], lambda r, i: failure(r), runtime))
    assert transport.total == 1
    assert results[0].detection.errors[0].code == ErrorCode.CONNECTION_RESET
    assert ErrorCode.REQUEST_BUDGET not in {e.code for r in journal for e in r.detection.errors}


def test_rescan_runs_inside_the_request_budget():
    sites = [site(str(i), f"s{i}.test") for i in range(6)]
    runtime = policy(transient_retries=0, rescan_errors=True, request_budget=9)
    results, transport, summary, _ = asyncio.run(run(sites, lambda r, i: failure(r), runtime))
    assert transport.total == 9  # 6 first + 3 of the 6 rescans, then the budget is gone
    assert summary.budget_remaining == 0 and len(results) == 6
    assert {r.detection.state for r in results} == {ExecutionState.NETWORK_ERROR}


def test_rescan_off_sends_nothing_extra():
    _, transport, _, _ = asyncio.run(
        run([site()], lambda r, i: failure(r), policy(transient_retries=0))
    )
    assert transport.total == 1


def test_rescan_ignores_blocks_and_other_non_network_states():
    results, transport, _, _ = asyncio.run(
        run([site()], lambda r, i: status(r, 403), policy(transient_retries=0, rescan_errors=True))
    )
    assert transport.total == 1 and results[0].detection.state == ExecutionState.BLOCKED


def test_rescan_runs_after_the_main_pass_with_half_the_concurrency():
    sites = [site(str(i), f"s{i}.test") for i in range(12)]
    seen = {"first": 0, "rescan": []}
    state = {}

    def handler(request, index):
        transport = state["transport"]
        if index < 12:
            seen["first"] += 1
            return failure(request)
        assert seen["first"] == 12  # every first attempt happened before any rescan request
        seen["rescan"].append(transport.active)
        return ok(request)

    async def scenario():
        runtime = policy(transient_retries=0, rescan_errors=True)
        registry = SiteRegistry(sites)
        selection = runtime_selection(registry, select_services(registry, "alice"), runtime)
        transport = FakeTransport(handler=handler, delay=0.01)
        state["transport"] = transport
        config = SchedulerConfig(concurrency=8, per_job=8, per_origin=2)
        async with UsernameEngine(registry, transport, config=config) as engine:
            return [
                r
                async for r in engine.search_stream(
                    "alice",
                    site_ids=selection.selected,
                    options=SearchOptions(request_budget=100),
                    runtime=runtime,
                    selection=selection,
                )
            ], transport

    results, transport = asyncio.run(scenario())
    assert len(results) == 12
    assert all(r.detection.verdict == "FOUND" for r in results)
    assert transport.peak_active == 8
    assert seen["rescan"] and max(seen["rescan"]) <= 4


def test_modes_and_cli_flag():
    assert not MODES["quick"].rescan_errors
    assert all(MODES[m].rescan_errors for m in ("normal", "deep", "exhaustive"))
    assert all(MODES[m].transient_retries == 2 for m in ("normal", "deep", "exhaustive"))
    assert MODES["quick"].retry_budget == 0
    assert not RuntimePolicy().rescan_errors
    assert parser().parse_args(["search", "alice", "--no-rescan"]).no_rescan
    assert not parser().parse_args(["search", "alice"]).no_rescan


def test_policy_validation():
    with pytest.raises(ValueError):
        RuntimePolicy(transient_retries=-1)
    with pytest.raises(ValueError):
        RuntimePolicy(rescan_errors=1)  # type: ignore[arg-type]


# --- F3.7: nothing may wait idle until the job deadline -------------------------------------


def headed(request, code, **headers):
    return TransportResponse(
        request.url,
        code,
        b"",
        tuple((k.replace("_", "-"), v) for k, v in headers.items()),
        request.url,
    )


async def timed_run(sites, handler, runtime):
    import time

    started = time.monotonic()
    out = await run(sites, handler, runtime)
    return (*out, time.monotonic() - started)


@pytest.mark.parametrize("code", [503, 429])
def test_huge_retry_after_does_not_park_the_retry_until_the_deadline(code):
    # Observed in the full scan: a 503 with "Retry-After: 259200" made the retry wait for the
    # job deadline (3600 s). A pause the server asks for beyond the give-up limit means no retry.
    runtime = policy(job_timeout=5, retry_min_delay=0.01, rate_limit_seconds=0.02)
    results, transport, _, _, wall = asyncio.run(
        timed_run([site()], lambda r, i: headed(r, code, Retry_After="259200"), runtime)
    )
    assert wall < 2 and transport.total == 1
    assert results[0].detection.state in (ExecutionState.SERVER_ERROR, ExecutionState.RATE_LIMITED)


def test_http_date_retry_after_in_the_far_future_is_not_waited_for():
    runtime = policy(job_timeout=5)
    _, transport, _, _, wall = asyncio.run(
        timed_run(
            [site()],
            lambda r, i: headed(r, 503, Retry_After="Fri, 10 Oct 2036 21:00:00 GMT"),
            runtime,
        )
    )
    assert wall < 2 and transport.total == 1


def test_retry_delay_is_capped_and_never_beyond_the_deadline():
    delays = []
    runtime = policy(job_timeout=5, retry_min_delay=0.01)

    def metrics(metric):
        if metric.event == "retry":
            delays.append(metric.elapsed)

    async def scenario():
        registry = SiteRegistry([site()])
        selection = runtime_selection(registry, select_services(registry, "alice"), runtime)
        transport = FakeTransport(handler=lambda r, i: headed(r, 503, Retry_After="40"))
        async with UsernameEngine(registry, transport, metrics=metrics) as engine:
            async for _ in engine.search_stream(
                "alice",
                site_ids=selection.selected,
                options=SearchOptions(request_budget=50, job_timeout=5),
                runtime=runtime,
                selection=selection,
            ):
                pass

    asyncio.run(scenario())
    # A 40 s Retry-After is within the give-up limit but longer than the job: capped, not honoured.
    assert all(d <= 5 for d in delays)


def test_many_transient_errors_with_exhausted_budget_and_rescan_finish_at_once():
    sites = [site(f"s{i}", f"h{i}.test") for i in range(30)]
    runtime = policy(job_timeout=5, retry_budget=1, rescan_errors=True, request_budget=500)

    def handler(request, i):
        if "h0.test" in request.url:
            return headed(request, 503, Retry_After="259200")
        return failure(request)

    results, transport, summary, _, wall = asyncio.run(timed_run(sites, handler, runtime))
    assert wall < 2, wall
    assert len(results) == 30
    assert dict(summary.request_counts).get("RETRY", 0) <= 1
