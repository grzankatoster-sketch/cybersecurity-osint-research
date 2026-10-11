"""Offline benchmark: pure pipeline and actual spawn/scheduler costs reported separately."""

# ruff: noqa: E402
import asyncio
import gc
import json
import statistics
import sys
import time
import tracemalloc
from dataclasses import replace
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from ultimate_username.detection import DetectionEngine
from ultimate_username.domain.metadata import EnrichmentMode
from ultimate_username.domain.models import (
    DetectionSpec,
    Rule,
    SiteDefinition,
    TransportResponse,
)
from ultimate_username.engine import SearchOptions, UsernameEngine
from ultimate_username.enrichment import ParsedDocument, enrich, merge_metadata
from ultimate_username.planning import plan_request
from ultimate_username.registry import SiteRegistry
from ultimate_username.transport import FakeTransport


def percentile(values, q):
    return sorted(values)[min(len(values) - 1, int((len(values) - 1) * q))]


def main():
    site = SiteDefinition(
        "bench",
        "Bench",
        "https://profiles.example.test/u/{username}",
        DetectionSpec(Rule("message", "profile"), binding=Rule("redirect", "{profile_url}")),
        enrichment_urls=("https://profiles.example.test/api/{username}",),
    )
    cases = json.loads((ROOT / "tests/fixtures/enrichment/cases.json").read_text(encoding="utf-8"))
    case = next(c for c in cases if c["id"] == "og_profile")
    response = TransportResponse(
        case["url"], 200, case["body"].encode(), (("Content-Type", "text/html"),), case["url"]
    )
    extra = TransportResponse(
        "https://profiles.example.test/api/alice",
        200,
        b'{"username":"alice","followers":1200}',
        (("Content-Type", "application/json"),),
    )
    plan = plan_request("alice", site, "benchmark")
    detector = DetectionEngine()
    detected = detector.detect(response, plan)
    report = {
        "kind": "controlled synthetic fixtures; no live platform requests",
        "python": sys.version,
        "response_bytes": len(response.body),
        "pipeline": [],
        "memory": [],
        "process_pipeline": [],
    }
    for mode in ("off", "basic", "full"):
        timings = []
        parse = []
        extraction = []
        for _ in range(1000):
            start = time.perf_counter()
            detection = detector.detect(response, plan)
            if mode != "off":
                metadata = enrich(response, "alice", site, detection)
                if mode == "full":
                    metadata = merge_metadata(metadata, enrich(extra, "alice", site, detection))
                parse.append(metadata.parse_seconds)
                extraction.append(metadata.enrichment_seconds)
            timings.append(time.perf_counter() - start)
        report["pipeline"].append(
            {
                "mode": mode,
                "profiles": 1000,
                "network_seconds": 0,
                "process_startup_included": False,
                "mean_seconds": statistics.mean(timings),
                "p50_seconds": statistics.median(timings),
                "p95_seconds": percentile(timings, 0.95),
                "parse_mean": statistics.mean(parse) if parse else 0,
                "extraction_mean": statistics.mean(extraction) if extraction else 0,
            }
        )
    parse_times = {}
    for repeats in (1, 5):
        start = time.perf_counter()
        for _ in range(1000):
            for _ in range(repeats):
                ParsedDocument(response)
        parse_times[str(repeats)] = time.perf_counter() - start
    report["html_parse_once_vs_five"] = parse_times
    # Independent retention scenarios, allocated under tracemalloc. Not OS RSS.
    for count in (100, 1000, 10000):
        for component in ("body", "document", "json", "metadata", "streaming_metadata"):
            gc.collect()
            tracemalloc.start()
            items = []
            for _ in range(count):
                if component == "body":
                    value = bytes(bytearray(response.body))
                elif component == "document":
                    value = ParsedDocument(replace(response, body=bytes(bytearray(response.body))))
                elif component == "json":
                    value = json.loads('{"username":"alice","followers":1200,"bio":"Fixture bio"}')
                else:
                    value = enrich(response, "alice", site, detected)
                if component != "streaming_metadata":
                    items.append(value)
            current, peak = tracemalloc.get_traced_memory()
            tracemalloc.stop()
            report["memory"].append(
                {
                    "profiles": count,
                    "retained_component": component,
                    "current_bytes": current,
                    "peak_bytes": peak,
                }
            )
            del items, value
        print("memory profiles", count, flush=True)

    async def processes():
        for mode in EnrichmentMode:
            timings = []
            network = []
            parse = []
            extraction = []

            def handler(request, index):
                return replace(
                    extra if "/api/" in request.url else response,
                    requested_url=request.url,
                    final_url=request.url,
                )

            async with UsernameEngine(
                SiteRegistry([site]), FakeTransport(handler=handler, delay=0.001)
            ) as engine:
                for _ in range(5):
                    start = time.perf_counter()
                    result = (
                        await engine.search(
                            "alice",
                            options=SearchOptions(
                                enrichment_mode=mode, enrichment_request_budget=1
                            ),
                        )
                    )[0]
                    assert result.detection.verdict.value == "FOUND"
                    network.extend(
                        a.timing.elapsed for a in result.attempts + result.enrichment_attempts
                    )
                    timings.append(time.perf_counter() - start)
                    parse.append(result.profile_metadata.parse_seconds)
                    extraction.append(result.profile_metadata.enrichment_seconds)
                report["process_pipeline"].append(
                    {
                        "mode": mode.value,
                        "profiles": 5,
                        "network": "FakeTransport 1ms scheduled delay",
                        "request_count": len(network),
                        "network_total": sum(network),
                        "mean_seconds": statistics.mean(timings),
                        "p50_seconds": statistics.median(timings),
                        "p95_seconds": percentile(timings, 0.95),
                        "parse_mean": statistics.mean(parse),
                        "extraction_mean": statistics.mean(extraction),
                    }
                )

    asyncio.run(processes())
    target = ROOT / "artifacts/enrichment-benchmark.json"
    target.write_text(json.dumps(report, indent=2), encoding="utf-8")
    print(target)


if __name__ == "__main__":
    main()
