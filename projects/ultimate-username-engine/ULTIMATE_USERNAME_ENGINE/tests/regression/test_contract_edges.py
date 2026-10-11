import asyncio
import importlib
import json
import socket
from dataclasses import replace
from pathlib import Path

import aiohttp
import pytest

from ultimate_username.detection import DetectionEngine
from ultimate_username.domain.codec import from_json, to_json
from ultimate_username.domain.models import (
    DetectionSpec,
    ErrorCode,
    ExecutionState,
    RateProfile,
    Rule,
    SearchResult,
    SiteDefinition,
    TransportResponse,
    Verdict,
)
from ultimate_username.engine import UsernameEngine
from ultimate_username.http_transport import classify_exception
from ultimate_username.metadata_import import import_metadata
from ultimate_username.planning import plan_request
from ultimate_username.registry import SiteRegistry
from ultimate_username.scheduler import Scheduler, SchedulerConfig
from ultimate_username.storage import export_results
from ultimate_username.transport import FakeTransport


def test_dns_root_causes_distinct_and_serializable():
    for number, code in [
        (socket.EAI_NONAME, ErrorCode.DNS_NOT_FOUND),
        (socket.EAI_AGAIN, ErrorCode.DNS_TEMPORARY),
    ]:
        error = classify_exception(
            aiohttp.ClientConnectorDNSError(None, socket.gaierror(number, "fixture"))
        )
        assert error.code == code and error.cause_type == "ClientConnectorDNSError"
        assert error.retryable == (number == socket.EAI_AGAIN)
    assert classify_exception(aiohttp.ConnectionTimeoutError()).code == ErrorCode.CONNECT_TIMEOUT


def test_unknown_status_body_cannot_prove_account():
    site = SiteDefinition(
        "x",
        "X",
        "https://example.test/{username}",
        DetectionSpec(Rule("message", "profile"), binding=Rule("redirect", "{profile_url}")),
    )
    plan = plan_request("alice", site, "task")
    response = TransportResponse(plan.request.url, body=b"profile", final_url=plan.profile_url)
    result = DetectionEngine().detect(response, plan)
    assert result.verdict == Verdict.UNKNOWN


def test_late_marker_export_and_error_json_roundtrip(tmp_path):
    async def run():
        site = SiteDefinition(
            "x",
            "X",
            "https://example.test/{username}",
            DetectionSpec(Rule("message", "profile"), binding=Rule("redirect", "{profile_url}")),
        )
        fake = FakeTransport(
            handler=lambda r, i: TransportResponse(r.url, 200, b"x" * 5000 + b"profile")
        )
        async with UsernameEngine(SiteRegistry([site]), fake) as engine:
            result = (await engine.search("alice"))[0]
            assert result.detection.verdict == Verdict.FOUND
            assert from_json(SearchResult, to_json(result)) == result
            return result

    result = asyncio.run(run())
    export_results(tmp_path / "out.json", [result])
    assert (
        json.loads((tmp_path / "out.json").read_text("utf-8"))[0]["detection"]["verdict"] == "FOUND"
    )


def test_import_has_no_network_file_writes_or_plugin_loading(monkeypatch):
    def forbidden(*args, **kwargs):
        raise AssertionError("Unexpected side effect")

    monkeypatch.setattr(socket.socket, "connect", forbidden)
    monkeypatch.setattr(Path, "write_text", forbidden)
    for name in (
        "ultimate_username",
        "ultimate_username.metadata_import",
        "ultimate_username.registry",
    ):
        importlib.reload(importlib.import_module(name))


def test_hundred_jobs_with_thirty_percent_rate_limits_share_all_limits():
    async def run():
        sites = [
            SiteDefinition(
                str(i),
                str(i),
                f"https://h{i}.test/{{username}}",
                DetectionSpec(
                    Rule("message", "profile"), binding=Rule("redirect", "{profile_url}")
                ),
                rate=RateProfile(4),
            )
            for i in range(10)
        ]

        def handler(request, index):
            limited = any(request.url.startswith(f"https://h{i}.") for i in range(3))
            return TransportResponse(
                request.url,
                429 if limited else 200,
                b"profile",
                headers=(("Retry-After", ".001"),) if limited else (),
            )

        transport = FakeTransport(handler=handler)
        config = SchedulerConfig(
            concurrency=8, per_origin=2, per_job=2, queue_capacity=32, job_buffer=4, max_jobs=100
        )
        async with UsernameEngine(SiteRegistry(sites), transport, config=config) as engine:
            jobs = await asyncio.gather(*(engine.search(f"u{i}") for i in range(100)))
            results = [r for job in jobs for r in job]
            assert len(results) == 1000
            assert sum(r.detection.state == ExecutionState.RATE_LIMITED for r in results) == 300
            assert sum(r.detection.verdict == Verdict.FOUND for r in results) == 700
            assert all(r.detection.verdict != Verdict.NOT_FOUND for r in results)
            assert transport.peak_active <= 8 and max(transport.peak_origins.values()) <= 2
            assert engine.scheduler.stats.peak_tasks <= 9

    asyncio.run(run())


def test_scheduler_source_exception_surfaces_without_orphans():
    async def run():
        scheduler = Scheduler()

        def broken():
            raise ValueError("bad source")
            yield

        try:
            with pytest.raises(RuntimeError, match="Work source failed"):
                async for _ in scheduler.stream(broken()):
                    pass
        finally:
            await scheduler.close()
        assert not [t for t in asyncio.all_tasks() if t.get_name().startswith("uee-")]

    asyncio.run(run())


@pytest.mark.parametrize(
    "field", ["concurrency", "per_origin", "per_job", "queue_capacity", "job_buffer", "max_jobs"]
)
def test_all_scheduler_limits_reject_zero_negative_and_bool(field):
    for value in [0, -1, False]:
        with pytest.raises(ValueError):
            replace(SchedulerConfig(), **{field: value})


def test_blackbird_metadata_supported_shapes_and_unsupported_diagnostic():
    metadata = {
        "sites": {
            "Service": [
                {
                    "schema": "JSON",
                    "type": "Array",
                    "name": "Courses",
                    "path": ["users", 0, "courses"],
                    "item-path": ["title"],
                },
                {
                    "schema": "HTML",
                    "type": "Image",
                    "name": "Image",
                    "path": 'src="([^"]+)"',
                    "prefix": "https:",
                },
                {"schema": "unknown", "type": "String", "name": "broken"},
            ]
        }
    }
    result = import_metadata(metadata)
    assert [r.status for r in result] == ["IMPORTED", "IMPORTED", "UNSUPPORTED"]
    assert result[0].rule.path == ("users", "0", "courses")
    assert result[0].rule.item_path == ("title",)
    assert result[1].rule.prefix == "https:"
