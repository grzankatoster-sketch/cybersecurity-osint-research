import asyncio
import json
from dataclasses import replace
from time import monotonic

import pytest

import ultimate_username.cli as cli_module
from ultimate_username.cli import main, parser
from ultimate_username.domain.codec import from_json, to_json
from ultimate_username.domain.metadata import EnrichmentMode
from ultimate_username.domain.models import (
    DetectionSpec,
    ErrorCode,
    ExecutionState,
    RedirectPolicy,
    RetryPolicy,
    Rule,
    SearchError,
    SiteDefinition,
    TransportResponse,
)
from ultimate_username.engine import SearchOptions, UsernameEngine
from ultimate_username.presentation import analyst_record
from ultimate_username.registry import SiteRegistry
from ultimate_username.request_economy import DefinitionHealth, economy
from ultimate_username.runtime_policy import (
    MODES,
    RuntimePolicy,
    public_alternative,
    runtime_selection,
    technical_quality,
)
from ultimate_username.scheduler import SchedulerConfig
from ultimate_username.selection import select_services
from ultimate_username.transport import FakeTransport


def site(sid="api", host="fixture.test", **changes):
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


def alternative(primary):
    return replace(primary, id=primary.id + ":html", probe_url=None)


def response(request, status=200, body=b"owner=alice", headers=()):
    return TransportResponse(request.url, status, body, headers, request.url)


async def run(
    sites,
    handler,
    *,
    budget=10,
    retry=0,
    fallback=2,
    config=None,
    enrichment=0,
    policy=None,
    delay=0,
):
    registry = SiteRegistry(sites)
    assert not [e for e in registry.entries if e.issues]
    policy = policy or RuntimePolicy(
        request_budget=budget,
        retry_budget=retry,
        fallback_limit=fallback,
        enrichment_budget=enrichment,
        retry_min_delay=0.01,
        rate_limit_seconds=0.02,
    )
    selection = runtime_selection(registry, select_services(registry, "alice"), policy)
    transport = FakeTransport(handler=handler, delay=delay)
    async with UsernameEngine(registry, transport, config=config) as engine:
        results = [
            r
            async for r in engine.search_stream(
                "alice",
                site_ids=selection.selected,
                options=SearchOptions(
                    request_budget=budget,
                    enrichment_mode=EnrichmentMode.FULL if enrichment else EnrichmentMode.OFF,
                    enrichment_request_budget=enrichment,
                ),
                runtime=policy,
                selection=selection,
            )
        ]
        summary = engine.summaries[-1]
    return results, transport, summary, registry, selection


@pytest.mark.parametrize("budget", [1, 2, 20, 50, 100])
def test_hard_cap_under_concurrency_and_not_tested(budget):
    sites = [site(str(i), f"s{i}.test") for i in range(120)]
    results, transport, summary, registry, _ = asyncio.run(
        run(sites, lambda r, i: response(r), budget=budget, delay=0.001)
    )
    assert transport.total == budget
    assert sum(dict(summary.request_counts).values()) == budget
    assert summary.budget_remaining == 0
    assert sum(not r.attempts for r in results) == 120 - budget
    assert all(
        analyst_record(r, registry)["status"] == "NOT_TESTED" for r in results if not r.attempts
    )


def test_fallback_recovers_with_one_canonical_result_and_full_trace():
    primary = site()
    results, transport, summary, _, selection = asyncio.run(
        run(
            [primary, alternative(primary), replace(primary, id="duplicate")],
            lambda r, i: response(r, 403) if "/api/" in r.url else response(r),
        )
    )
    assert transport.total == 2 and len(results) == 1
    result = results[0]
    assert result.detection.verdict == "FOUND"
    assert result.site_id == "api:html"
    assert [o.detection.state for o in result.fallback_chain] == ["BLOCKED", "OK"]
    assert [a.budget_reason for a in result.attempts] == ["PRIMARY_CHECK", "FALLBACK_CHECK"]
    assert dict(summary.request_counts) == {"PRIMARY_CHECK": 1, "FALLBACK_CHECK": 1}
    stats = economy(
        results,
        request_budget=10,
        canonical_services=len(selection.services),
        definitions_considered=selection.compatible,
    )
    assert stats["recovered_canonical_services"] == 1
    assert stats["fallback_success"] == 1
    assert stats["duplicate_primary_slots_prevented"] == 2
    assert stats["block_observations"] == {"HTTP_403": 1}
    assert from_json(type(result), to_json(result)) == result


@pytest.mark.parametrize(
    "status,body,expected,count",
    [
        (404, b"no such account", "NOT_FOUND", 1),
        (429, b"limited", "UNKNOWN", 1),
        (403, b"denied", "FOUND", 2),
        (410, b"removed", "FOUND", 2),
        (500, b"broken", "FOUND", 2),
    ],
)
def test_fallback_policy(status, body, expected, count):
    primary = site()
    results, transport, _, _, _ = asyncio.run(
        run(
            [primary, alternative(primary)],
            lambda r, i: response(r, status, body) if i == 0 else response(r),
        )
    )
    assert transport.total == count and results[0].detection.verdict == expected
    if status == 429:
        assert results[0].detection.state == "RATE_LIMITED"


@pytest.mark.parametrize("budget,expected_requests", [(1, 1), (2, 2), (3, 2)])
def test_fallback_is_charged_to_global_budget(budget, expected_requests):
    primary = site()
    results, transport, _, _, _ = asyncio.run(
        run(
            [primary, alternative(primary)],
            lambda r, i: response(r, 403) if i == 0 else response(r),
            budget=budget,
        )
    )
    assert transport.total == expected_requests
    if budget == 1:
        assert results[0].detection.state == "BLOCKED"


def test_retry_charged_and_429_at_most_one_retry():
    primary = site(retry=RetryPolicy(max_attempts=10, base_delay=0, max_delay=0))
    results, transport, summary, _, _ = asyncio.run(
        run([primary], lambda r, i: response(r, 429, headers=(("Retry-After", "0.01"),)), retry=5)
    )
    assert transport.total == 2
    assert results[0].detection.state == "RATE_LIMITED"
    assert dict(summary.request_counts) == {"PRIMARY_CHECK": 1, "RETRY": 1}
    assert results[0].attempts[1].budget_reason == "RETRY"


def test_retry_budget_shared_across_services():
    sites = [
        site(str(i), f"s{i}.test", retry=RetryPolicy(max_attempts=5, base_delay=0, max_delay=0))
        for i in range(10)
    ]
    results, transport, summary, _, _ = asyncio.run(
        run(sites, lambda r, i: response(r, 500), retry=2, budget=100)
    )
    assert transport.total == 12
    assert dict(summary.request_counts)["RETRY"] == 2
    assert all(r.detection.state == "SERVER_ERROR" for r in results)


@pytest.mark.parametrize("status", [403, 429, 500])
def test_circuit_breaker_stops_repeated_origin_failure(status):
    sites = [site(str(i), profile_url=f"https://fixture.test/{i}/{{username}}") for i in range(6)]
    results, transport, _, _, _ = asyncio.run(
        run(
            sites,
            lambda r, i: response(r, status),
            config=SchedulerConfig(concurrency=1, per_job=1, per_origin=1),
        )
    )
    assert transport.total == 3
    assert sum(r.detection.state == "DEGRADED" for r in results) == 3


def test_cooldown_does_not_stop_another_origin():
    times = []

    def handler(request, index):
        times.append((request.url, monotonic()))
        return response(request, 429, headers=(("Retry-After", "0.05"),))

    a = site("a")
    b = site("b", profile_url="https://fixture.test/second/{username}")
    c = site("c", "other.test")
    asyncio.run(
        run([a, b, c], handler, config=SchedulerConfig(concurrency=1, per_job=1, per_origin=1))
    )
    assert "other.test" in times[1][0]
    assert times[2][1] - times[0][1] >= 0.045


def test_enrichment_is_charged_to_global_and_enrichment_limits():
    primary = site(enrichment_urls=("https://fixture.test/details/{username}",))
    results, transport, summary, _, _ = asyncio.run(
        run([primary], lambda r, i: response(r), budget=2, enrichment=1)
    )
    assert transport.total == 2
    assert dict(summary.request_counts) == {"PRIMARY_CHECK": 1, "ENRICHMENT": 1}
    assert results[0].enrichment_attempts[0].budget_reason == "ENRICHMENT"


def test_missing_credential_does_not_send_or_assert_absence(monkeypatch):
    monkeypatch.delenv("UEE_CRED_TEST_KEY", raising=False)
    primary = site(credential_env="UEE_CRED_TEST_KEY")
    results, transport, _, registry, _ = asyncio.run(run([primary], lambda r, i: response(r)))
    assert transport.total == 0
    assert results[0].detection.state == "API_REQUIRED"
    assert analyst_record(results[0], registry)["status"] == "NOT_TESTED"
    assert results[0].fallback_chain[0].block_class == "API_REQUIRES_KEY"


def test_missing_api_credential_can_use_public_html(monkeypatch):
    monkeypatch.delenv("UEE_CRED_TEST_KEY", raising=False)
    primary = site(credential_env="UEE_CRED_TEST_KEY")
    alt = replace(alternative(primary), credential_env="")
    results, transport, _, _, _ = asyncio.run(run([primary, alt], lambda r, i: response(r)))
    assert transport.total == 1 and results[0].detection.verdict == "FOUND"
    assert results[0].attempts[0].budget_reason == "FALLBACK_CHECK"


def test_credential_value_never_enters_export(monkeypatch):
    monkeypatch.setenv("UEE_CRED_TEST_KEY", "test-secret-not-for-export")
    # Credentials are deny-by-default: the operator authorises the variable for this host only.
    monkeypatch.setenv("UEE_CREDENTIAL_SCOPES", "UEE_CRED_TEST_KEY=fixture.test")
    results, transport, _, _, _ = asyncio.run(
        run([site(credential_env="UEE_CRED_TEST_KEY")], lambda r, i: response(r))
    )
    assert transport.requests[0].headers == (
        ("Authorization", "Bearer test-secret-not-for-export"),
    )
    assert "test-secret" not in to_json(results)


@pytest.mark.parametrize(
    "changes",
    [
        {"headers": (("Authorization", "secret"),)},
        {"headers": (("Cookie", "secret"),)},
        {"credential_env": "SOME_KEY"},
        {"context_id": "private"},
        {"probe_url": "https://unrelated.test/u/{username}"},
        {"probe_url": "https://fixture.test/u/{username}?token=secret"},
        {"discovery_only": True},
        {"probe_url": "https://fixture.test/api/{username}"},
    ],
)
def test_only_distinct_public_registry_endpoint_is_eligible(changes):
    primary = site()
    assert not public_alternative(primary, replace(alternative(primary), **changes))


def test_discovery_evidence_never_found():
    results, _, _, registry, _ = asyncio.run(
        run([site(discovery_only=True)], lambda r, i: response(r))
    )
    assert results[0].detection.verdict == "UNKNOWN"
    assert results[0].source_kind == "INDEX_EVIDENCE"
    assert analyst_record(results[0], registry)["status"] == "DISCOVERY_ONLY"


def test_quality_diversity_and_service_ceiling():
    sites = [
        site(str(i), f"s{i}.test", category="social" if i < 4 else "developer") for i in range(5)
    ]
    registry = SiteRegistry(sites)
    plan = runtime_selection(
        registry, select_services(registry, "alice"), RuntimePolicy(service_budget=2)
    )
    assert len(plan.selected) == 2
    assert {registry.get(sid).definition.category for sid in plan.selected} == {
        "social",
        "developer",
    }
    assert len(plan.services) == 5
    score = technical_quality(registry.entries[0])
    assert score.value == sum(int(s.rsplit(":", 1)[1]) for s in score.reasons)


def test_modes_and_strict_config():
    assert parser().parse_args(["search", "alice"]).mode == "normal"
    assert MODES["quick"].retry_budget == 0 and MODES["quick"].enrichment_budget == 0
    assert MODES["exhaustive"].request_budget < 100_000
    with pytest.raises(ValueError):
        from_json(RuntimePolicy, '{"unbounded": true}')
    for kwargs in (
        {"request_budget": 0},
        {"retry_budget": -1},
        {"job_timeout": float("inf")},
        {"service_budget": 0},
        {"fallback_limit": 3},
    ):
        with pytest.raises(ValueError):
            RuntimePolicy(**kwargs)


def test_health_is_local_revision_scoped_and_idempotent(tmp_path):
    primary = site()
    results, _, _, _, _ = asyncio.run(
        run(
            [primary, alternative(primary)],
            lambda r, i: response(r, 403) if i == 0 else response(r),
        )
    )
    health = DefinitionHealth(tmp_path / "health.sqlite")
    try:
        health.record(results)
        health.record(results)
        rows = health.db.execute(
            "SELECT site_id, checks, blocked_responses FROM definition_health ORDER BY site_id"
        ).fetchall()
        assert rows == [("api", 1, 1), ("api:html", 1, 0)]
    finally:
        health.close()


def test_cli_rejects_invalid_runtime_before_journal(tmp_path):
    path = tmp_path / "run.sqlite"
    assert main(["search", "alice", "--retry-budget", "-1", "--journal", str(path)]) == 2
    assert not path.exists()


def test_cancellation_after_reservation_is_accounted():
    async def scenario():
        registry = SiteRegistry([site()])
        policy = RuntimePolicy()
        plan = runtime_selection(registry, select_services(registry, "alice"), policy)
        entered = asyncio.Event()

        class WaitingTransport(FakeTransport):
            async def send(self, request):
                entered.set()
                return await super().send(request)

        transport = WaitingTransport(delay=10, handler=lambda r, i: response(r))
        committed = []
        async with UsernameEngine(registry, transport, sink=committed.append) as engine:
            stream = engine.search_stream(
                "alice", site_ids=plan.selected, runtime=policy, selection=plan
            )
            task = asyncio.create_task(anext(stream))
            await entered.wait()
            task.cancel()
            with pytest.raises(asyncio.CancelledError):
                await task
            await stream.aclose()
            assert dict(engine.summaries[-1].request_counts) == {"PRIMARY_CHECK": 1}
        assert committed[-1].attempts[0].state == ExecutionState.CANCELLED

    asyncio.run(scenario())


def test_fallback_not_starved_behind_buffered_primary_slots():
    sites = []
    for i in range(60):
        primary = site(str(i), f"s{i}.test")
        sites.extend((primary, alternative(primary)))
    results, transport, summary, _, _ = asyncio.run(
        run(
            sites,
            lambda r, i: response(r, 403) if "/api/" in r.url else response(r),
            budget=20,
            delay=0.001,
        )
    )
    assert transport.total == 20
    assert dict(summary.request_counts)["FALLBACK_CHECK"] > 0
    assert any(r.detection.verdict == "FOUND" for r in results)


def test_second_fallback_is_bounded_and_preserves_both_blocks():
    primary = site()
    variants = [primary] + [
        replace(primary, id=f"api:alt{i}", probe_url=f"https://fixture.test/alt{i}/{{username}}")
        for i in range(1, 4)
    ]
    results, transport, _, _, _ = asyncio.run(
        run(variants, lambda r, i: response(r, 403) if i < 2 else response(r))
    )
    assert transport.total == 3 and len(results[0].fallback_chain) == 3
    assert results[0].detection.verdict == "FOUND"
    assert [s.detection.state for s in results[0].fallback_chain] == ["BLOCKED", "BLOCKED", "OK"]


def test_inconclusive_fallback_preserves_primary_block():
    primary = site()
    results, transport, _, _, _ = asyncio.run(
        run(
            [primary, alternative(primary)],
            lambda r, i: response(r, 403) if i == 0 else response(r, 200, b"generic page"),
        )
    )
    assert transport.total == 2
    assert results[0].detection.state == "BLOCKED"
    assert results[0].fallback_chain[-1].detection.verdict == "UNKNOWN"


def test_redirect_after_retry_is_a_hop_not_another_retry():
    primary = site(
        retry=RetryPolicy(max_attempts=2, base_delay=0, max_delay=0),
        redirects=RedirectPolicy(follow=True),
    )

    def handler(request, index):
        if index == 0:
            return response(request, 500)
        if index == 1:
            return response(request, 302, headers=(("Location", "/u/alice"),))
        return response(request)

    results, transport, summary, _, _ = asyncio.run(run([primary], handler, budget=3, retry=1))
    assert transport.total == 3 and results[0].detection.verdict == "FOUND"
    assert dict(summary.request_counts) == {"PRIMARY_CHECK": 2, "RETRY": 1}


def test_circuit_breaker_also_limits_timeouts():
    sites = [site(str(i), profile_url=f"https://fixture.test/{i}/{{username}}") for i in range(6)]
    results, transport, _, _, _ = asyncio.run(
        run(
            sites,
            lambda r, i: TransportResponse(
                r.url,
                error=SearchError(ErrorCode.READ_TIMEOUT, "transport", "Controlled timeout", True),
            ),
            config=SchedulerConfig(concurrency=1, per_job=1, per_origin=1),
        )
    )
    assert transport.total == 3
    assert sum(r.detection.state == "TIMEOUT" for r in results) == 3
    assert sum(r.detection.state == "DEGRADED" for r in results) == 3


def test_enrichment_429_also_sets_origin_cooldown_without_losing_found():
    primary = site(enrichment_urls=("https://fixture.test/details/{username}",))
    results, _, summary, _, _ = asyncio.run(
        run(
            [primary],
            lambda r, i: response(r) if i == 0 else response(r, 429),
            enrichment=1,
            budget=2,
        )
    )
    assert results[0].detection.verdict == "FOUND"
    assert results[0].enrichment_attempts[0].block_class == "HTTP_429"
    assert dict(summary.request_counts) == {"PRIMARY_CHECK": 1, "ENRICHMENT": 1}


def test_cli_exports_one_recovered_service_and_request_economy(tmp_path, monkeypatch, capsys):
    primary = site()
    source = tmp_path / "registry.json"
    source.write_text(to_json([primary, alternative(primary)]), encoding="utf-8")
    transport = FakeTransport(handler=lambda r, i: response(r, 403) if i == 0 else response(r))
    monkeypatch.setattr(cli_module, "AiohttpTransport", lambda config: transport)
    output = tmp_path / "output.json"
    assert (
        main(
            [
                "search",
                "alice",
                "--registry",
                str(source),
                "--request-budget",
                "2",
                "--enrich",
                "off",
                "--output",
                str(output),
                "--journal",
                str(tmp_path / "journal.sqlite"),
            ]
        )
        == 0
    )
    raw = json.loads(output.read_text(encoding="utf-8"))
    analyst = json.loads(output.with_suffix(".analyst.json").read_text(encoding="utf-8"))
    assert len(raw) == 1 and len(raw[0]["fallback_chain"]) == 2
    assert analyst["profiles"][0]["source"] == "fallback"
    assert analyst["request_economy"]["total_requests"] == 2
    assert (tmp_path / "definition-health.sqlite").exists()
    assert "Request economy" in capsys.readouterr().err


def test_cli_not_tested_includes_services_excluded_by_service_limit(tmp_path, monkeypatch):
    source = tmp_path / "registry.json"
    source.write_text(to_json([site("a", "a.test"), site("b", "b.test")]), encoding="utf-8")
    monkeypatch.setattr(
        cli_module,
        "AiohttpTransport",
        lambda config: FakeTransport(handler=lambda r, i: response(r)),
    )
    output = tmp_path / "output.json"
    assert (
        main(
            [
                "search",
                "alice",
                "--registry",
                str(source),
                "--service-budget",
                "1",
                "--enrich",
                "off",
                "--output",
                str(output),
                "--journal",
                str(tmp_path / "journal.sqlite"),
            ]
        )
        == 0
    )
    analyst = json.loads(output.with_suffix(".analyst.json").read_text(encoding="utf-8"))
    assert analyst["summary"]["counts"]["not_tested"] == 1
    assert analyst["summary"]["not_tested_reasons"]["SERVICE_BUDGET"] == 1


def test_normal_mode_budgets_follow_f3_3():
    normal = MODES["normal"]
    assert (normal.service_budget, normal.request_budget, normal.control_budget) == (800, 1100, 150)
    # F3.6: retries (also the transient ones) and the rescan need room beyond primaries + controls
    assert normal.retry_budget == 60
    assert (normal.job_timeout, normal.min_quality) == (300, 0)
    assert normal.health_skip and normal.enrichment_budget == 0
    spare = normal.request_budget - normal.service_budget - normal.control_budget
    assert spare >= normal.retry_budget
