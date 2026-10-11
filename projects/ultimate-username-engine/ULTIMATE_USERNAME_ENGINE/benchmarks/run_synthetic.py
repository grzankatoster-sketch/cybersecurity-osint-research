"""Reproducible synthetic measurements, no external network or retained result list."""

import argparse
import asyncio
import gc
import json
import platform
import sys
import time
import tracemalloc
from collections import Counter
from datetime import UTC, datetime
from pathlib import Path

from ultimate_username.domain.models import (
    DetectionSpec,
    RateProfile,
    Rule,
    SiteDefinition,
    TransportResponse,
)
from ultimate_username.engine import SearchOptions, UsernameEngine
from ultimate_username.registry import SiteRegistry
from ultimate_username.scheduler import SchedulerConfig
from ultimate_username.storage import atomic_write
from ultimate_username.transport import FakeTransport


async def measure(size, concurrency=32, queue=128):
    gc.collect()
    tracemalloc.start()
    started = time.perf_counter()
    registry = SiteRegistry(
        SiteDefinition(
            str(i),
            f"Fixture {i}",
            f"https://h{i % 16}.example.test/u/{{username}}",
            DetectionSpec(Rule("message", "profile"), binding=Rule("redirect", "{profile_url}")),
            rate=RateProfile(4),
        )
        for i in range(size)
    )
    registry_seconds = time.perf_counter() - started
    _, registry_peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()
    observed_tasks = 0

    def handler(request, index):
        nonlocal observed_tasks
        observed_tasks = max(observed_tasks, len(asyncio.all_tasks()))
        return TransportResponse(request.url, 200, b"<title>profile</title>" + b"x" * 256)

    fake = FakeTransport(handler=handler, history_limit=0)
    config = SchedulerConfig(
        concurrency=concurrency,
        per_origin=4,
        per_job=concurrency,
        queue_capacity=queue,
        job_buffer=queue,
    )
    gc.collect()
    tracemalloc.start()
    started = time.perf_counter()
    verdicts = Counter()
    async with UsernameEngine(registry, fake, config=config) as engine:
        async for result in engine.search_stream(
            "fixture_user", options=SearchOptions(job_timeout=300, request_budget=size)
        ):
            verdicts[result.detection.verdict.value] += 1
        elapsed = time.perf_counter() - started
        _, work_peak = tracemalloc.get_traced_memory()
        detection_seconds = engine.detection_seconds
        stats = engine.scheduler.stats
    tracemalloc.stop()
    assert sum(verdicts.values()) == size and verdicts["FOUND"] == size
    assert stats.peak_pending <= queue and fake.peak_active <= concurrency
    assert max(fake.peak_origins.values()) <= 4 and fake.active == 0 and fake.closed
    assert not [t for t in asyncio.all_tasks() if t.get_name().startswith("uee-")]
    return {
        "sites": size,
        "registry_build_seconds": registry_seconds,
        "registry_build_peak_bytes": registry_peak,
        "scheduler_pipeline_seconds": elapsed,
        "work_peak_bytes_excluding_registry": work_peak,
        "observed_peak_asyncio_tasks": observed_tasks,
        "scheduler_peak_worker_tasks": stats.peak_active,
        "peak_pending": stats.peak_pending,
        "peak_http_active": fake.peak_active,
        "peak_per_origin": max(fake.peak_origins.values()),
        "detection_seconds": detection_seconds,
        "detection_microseconds_per_result": detection_seconds / size * 1e6,
        "results_per_second": size / elapsed,
        "verdicts": dict(verdicts),
        "global_limit": concurrency,
        "queue_capacity": queue,
        "cleanup_verified": True,
    }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--sizes", type=int, nargs="+", default=[100, 1000, 10000])
    parser.add_argument(
        "--output", type=Path, default=Path(__file__).resolve().parent / "results.json"
    )
    args = parser.parse_args()
    if any(n < 1 for n in args.sizes):
        parser.error("Sizes must be positive")
    results = [asyncio.run(measure(n)) for n in args.sizes]
    payload = {
        "timestamp_utc": datetime.now(UTC).isoformat(),
        "python": sys.version,
        "platform": platform.platform(),
        "tracemalloc_enabled": True,
        "runs": results,
    }
    atomic_write(args.output, [json.dumps(payload, indent=2)])
    print(json.dumps(payload, indent=2))


if __name__ == "__main__":
    main()
