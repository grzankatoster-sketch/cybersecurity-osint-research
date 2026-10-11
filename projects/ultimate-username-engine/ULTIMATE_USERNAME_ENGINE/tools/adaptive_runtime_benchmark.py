"""Reproducible synthetic and real loopback HTTP cost experiment; no external scan."""

from __future__ import annotations

import argparse
import asyncio
import json
import socket
import sys
from collections import Counter
from dataclasses import replace
from pathlib import Path
from time import perf_counter

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from aiohttp import web  # noqa: E402

from ultimate_username.domain.codec import to_value  # noqa: E402
from ultimate_username.domain.metadata import EnrichmentMode  # noqa: E402
from ultimate_username.domain.models import (  # noqa: E402
    DetectionSpec,
    Rule,
    SiteDefinition,
    TransportResponse,
)
from ultimate_username.engine import SearchOptions, UsernameEngine  # noqa: E402
from ultimate_username.enrichment import enrich  # noqa: E402
from ultimate_username.http_transport import AiohttpTransport  # noqa: E402
from ultimate_username.presentation import useful_fields  # noqa: E402
from ultimate_username.profile_service import ProfileService  # noqa: E402
from ultimate_username.registry import SiteRegistry  # noqa: E402
from ultimate_username.request_economy import economy  # noqa: E402
from ultimate_username.runtime_policy import (  # noqa: E402
    MODES,
    RuntimePolicy,
    public_alternative,
    runtime_selection,
    technical_quality,
)
from ultimate_username.scheduler import SchedulerConfig  # noqa: E402
from ultimate_username.selection import (  # noqa: E402
    prepared_registry,
    select_services,
    service_key,
)
from ultimate_username.transport import FakeTransport  # noqa: E402


class InlineFixtureProfiles(ProfileService):
    """Actual parser, but no spawn overhead for trusted benchmark-owned fixtures."""

    async def run(self, response, username, site, detection):
        return enrich(response, username, site, detection)


def catalog(base):
    sites = []
    for i in range(120):
        profile = f"{base}/p/{i:03d}/{{username}}"
        primary = SiteDefinition(
            f"s{i:03d}:a",
            f"Fixture {i}",
            profile,
            DetectionSpec(
                Rule("json", "{username}", path=("username",)),
                Rule("json", "true", path=("missing",)),
                Rule("json", "{username}", path=("username",)),
            ),
            probe_url=f"{base}/api/{i:03d}/{{username}}",
            category=("developer", "social", "gaming", "forums")[i % 4],
        )
        html = replace(
            primary,
            id=f"s{i:03d}:h",
            probe_url=None,
            detection=DetectionSpec(
                Rule("message", "owner={username}"),
                Rule("message", "no such account"),
                Rule("message", "owner={username}"),
            ),
        )
        # Registry insertion deliberately reproduces historical donor duplication.
        sites.extend((primary, replace(primary, id=f"s{i:03d}:b"), html))
    return SiteRegistry(sites)


def fixture(path, base):
    _, endpoint, number, username = path.split("/")
    kind = int(number) % 10
    if kind == 2:
        return 429, b"limited", "text/plain", {"Retry-After": "0"}
    if kind == 3:
        return (
            404,
            (b'{"missing":true}' if endpoint == "api" else b"no such account"),
            "application/json",
            {},
        )
    if endpoint == "api":
        failures = {0: 403, 1: 403, 4: 500, 6: 410}
        if kind in failures:
            return failures[kind], b"endpoint unavailable", "text/plain", {}
        if kind == 5:
            return 200, b"{broken-json", "application/json", {}
        data = {
            "username": username,
            "name": "Fixture User " + number,
            "bio": "Controlled training fixture",
            "url": f"{base}/p/{number}/{username}",
            "location": "Fixture City",
            "followers": 3,
        }
        return 200, json.dumps(data).encode(), "application/json", {}
    page = (
        f'<html>owner={username}<meta property="og:url" content="{base}/p/{number}/{username}">'
        f'<meta property="og:title" content="Fixture User {number}">'
        '<meta property="og:description" content="Controlled training fixture"></html>'
    )
    return 200, page.encode(), "text/html", {}


async def experiment(kind):
    calls = []
    runner = None
    if kind == "loopback_http":
        app = web.Application()

        async def handle(request):
            calls.append(request.path)
            status, body, ctype, headers = fixture(request.path, base)
            return web.Response(status=status, body=body, content_type=ctype, headers=headers)

        app.router.add_get("/{tail:.*}", handle)
        runner = web.AppRunner(app)
        await runner.setup()
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.bind(("127.0.0.1", 0))
        base = f"http://127.0.0.1:{sock.getsockname()[1]}"
        await web.SockSite(runner, sock).start()
    else:
        base = "https://controlled.test"
    registry = catalog(base)
    plan = select_services(registry, "alice")
    rows = []
    try:
        for budget in (20, 50, 100):
            for strategy in (
                "A_first_N_historical",
                "B_static_quality",
                "C_canonical_quality",
                "D_canonical_quality_fallback",
            ):
                calls.clear()

                def fake(request, index):
                    from urllib.parse import urlsplit

                    path = urlsplit(request.url).path
                    calls.append(path)
                    status, body, ctype, headers = fixture(path, base)
                    return TransportResponse(
                        request.url,
                        status,
                        body,
                        (("Content-Type", ctype), *headers.items()),
                        request.url,
                    )

                transport = (
                    AiohttpTransport() if kind == "loopback_http" else FakeTransport(handler=fake)
                )
                # One origin hosts every fixture; isolate strategy comparison from circuit
                # experiments (covered independently) and use a finite 1ms fixture cooldown.
                policy = RuntimePolicy(
                    service_budget=120,
                    request_budget=budget,
                    retry_budget=0,
                    fallback_limit=2 if strategy.startswith("D") else 0,
                    circuit_threshold=1000,
                    rate_limit_seconds=0.001,
                    job_timeout=120,
                )
                chosen = runtime_selection(registry, plan, policy)
                if strategy.startswith("A"):
                    ids = tuple(e.id for e in registry.entries)
                elif strategy.startswith("B"):
                    ids = tuple(
                        e.id
                        for e in sorted(
                            registry.entries, key=lambda e: (-technical_quality(e).value, e.id)
                        )
                    )
                else:
                    ids = chosen.selected
                started = perf_counter()
                async with UsernameEngine(
                    registry,
                    transport,
                    config=SchedulerConfig(concurrency=1, per_origin=1, per_job=1, job_buffer=1),
                    profiles=InlineFixtureProfiles(),
                ) as engine:
                    results = [
                        r
                        async for r in engine.search_stream(
                            "alice",
                            site_ids=ids,
                            options=SearchOptions(
                                request_budget=budget, enrichment_mode=EnrichmentMode.BASIC
                            ),
                            runtime=policy if strategy[0] in "CD" else None,
                            selection=chosen if strategy[0] in "CD" else None,
                        )
                    ]
                tested = [r for r in results if r.attempts]
                groups = {}
                for result in tested:
                    key = service_key(registry.get(result.site_id).definition)
                    groups.setdefault(key, []).append(result)
                meaningful = sum(
                    any(r.detection.verdict in ("FOUND", "NOT_FOUND") for r in rs)
                    for rs in groups.values()
                )
                with_metadata = sum(any(useful_fields(r) for r in rs) for rs in groups.values())
                row = {
                    "strategy": strategy,
                    "budget": budget,
                    "unique_services_tested": len(groups),
                    "meaningful_unique_results": meaningful,
                    "blocked_unique_results": sum(
                        all(r.detection.state in ("BLOCKED", "RATE_LIMITED") for r in rs)
                        for rs in groups.values()
                    ),
                    "profiles_with_metadata": with_metadata,
                    "requests": len(calls),
                    "duplicate_endpoint_requests": len(calls) - len(set(calls)),
                    "meaningful_per_request": meaningful / len(calls),
                    "elapsed_ms": (perf_counter() - started) * 1000,
                    "economy": economy(
                        results,
                        request_budget=budget,
                        canonical_services=120,
                        definitions_considered=360,
                    ),
                }
                assert len(calls) <= budget
                assert sum(len(r.attempts) + len(r.enrichment_attempts) for r in results) == len(
                    calls
                )
                rows.append(row)
                print(
                    json.dumps({"kind": kind, **{k: v for k, v in row.items() if k != "economy"}}),
                    flush=True,
                )
        return {
            "kind": kind,
            "registry_definitions": 360,
            "canonical_services": 120,
            "parser": "production enrich(), inline for trusted fixtures; no spawn cost",
            "concurrency": 1,
            "rows": rows,
        }
    finally:
        if runner:
            await runner.cleanup()


def census(path):
    raw = SiteRegistry.from_json(path.read_text(encoding="utf-8-sig"))
    registry = prepared_registry(raw)
    plan = select_services(registry, "JanKowalski")
    endpoints = 0
    services = 0
    for service in runtime_selection(registry, plan, MODES["exhaustive"]).services:
        primary = registry.get(service.primary).definition
        eligible = {
            registry.get(sid).definition.probe_url or registry.get(sid).definition.profile_url
            for sid in service.alternatives
            if public_alternative(primary, registry.get(sid).definition)
        }
        endpoints += len(eligible)
        services += bool(eligible)
    output = {
        "catalog_path": str(path),
        "username_compatibility_example": "JanKowalski",
        "raw_definitions": len(raw.entries),
        "raw_canonical_templates": len(
            {service_key(e.definition) for e in raw.entries if e.definition}
        ),
        "prepared_revision": registry.revision,
        "enabled_valid": plan.valid,
        "compatible_definitions": plan.compatible,
        "canonical_compatible": len(plan.services),
        "compatible_alternative_definitions": sum(len(s.alternatives) for s in plan.services),
        "conflicting_groups": sum(s.rule_conflict for s in plan.services),
        "services_with_eligible_public_alternative": services,
        "eligible_distinct_alternative_endpoints": endpoints,
        "modes": {},
    }
    for name, policy in MODES.items():
        selection = runtime_selection(registry, plan, policy)
        output["modes"][name] = {
            "policy": to_value(policy),
            "selected": len(selection.selected),
            "excluded_reasons": dict(Counter(reason for _, reason in selection.excluded)),
            "first_20": list(selection.selected[:20]),
        }
    return output


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--catalog", type=Path)
    args = parser.parse_args()
    if args.catalog:
        result = census(args.catalog)
    else:

        async def run_all():
            return [await experiment(kind) for kind in ("synthetic_transport", "loopback_http")]

        result = asyncio.run(run_all())
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8")
    print("Saved " + str(args.output), flush=True)


if __name__ == "__main__":
    main()
