"""Two bounded public training cases through the adaptive production pipeline."""

from __future__ import annotations

import asyncio
import json
import sys
from datetime import UTC, datetime
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from ultimate_username.domain.codec import to_value  # noqa: E402
from ultimate_username.domain.metadata import EnrichmentMode  # noqa: E402
from ultimate_username.domain.models import DetectionSpec, Rule, SiteDefinition  # noqa: E402
from ultimate_username.engine import SearchOptions, UsernameEngine  # noqa: E402
from ultimate_username.http_transport import AiohttpTransport  # noqa: E402
from ultimate_username.presentation import analyst_document  # noqa: E402
from ultimate_username.registry import SiteRegistry  # noqa: E402
from ultimate_username.request_economy import economy  # noqa: E402
from ultimate_username.runtime_policy import RuntimePolicy, runtime_selection  # noqa: E402
from ultimate_username.selection import prepared_registry, select_services  # noqa: E402


async def run():
    status_spec = DetectionSpec(Rule("status", statuses=(200,)), Rule("status", statuses=(404,)))
    cases = [
        (
            "octocat",
            [
                SiteDefinition(
                    "github:api",
                    "GitHub",
                    "https://github.com/{username}",
                    status_spec,
                    probe_url="https://api.github.com/users/{username}",
                )
            ],
        ),
        (
            "ben",
            [
                SiteDefinition(
                    "dev:api",
                    "DEV",
                    "https://dev.to/{username}",
                    status_spec,
                    probe_url="https://dev.to/api/users/by_username?url={username}",
                ),
                SiteDefinition("dev:html", "DEV", "https://dev.to/{username}", status_spec),
            ],
        ),
    ]
    output = {
        "kind": "LIVE_PUBLIC_HTTP",
        "started_at": datetime.now(UTC).isoformat(),
        "maximum_requests": 4,
        "cases": [],
    }
    for username, sites in cases:
        registry = prepared_registry(SiteRegistry(sites))
        policy = RuntimePolicy(service_budget=1, request_budget=2, retry_budget=0, job_timeout=30)
        selection = runtime_selection(registry, select_services(registry, username), policy)
        async with UsernameEngine(registry, AiohttpTransport()) as engine:
            results = [
                r
                async for r in engine.search_stream(
                    username,
                    site_ids=selection.selected,
                    options=SearchOptions(
                        request_budget=2, job_timeout=30, enrichment_mode=EnrichmentMode.BASIC
                    ),
                    runtime=policy,
                    selection=selection,
                )
            ]
            summary = engine.summaries[-1]
        doc = analyst_document(results, registry, username=username, selection=selection)
        stats = economy(
            results,
            request_budget=2,
            canonical_services=len(selection.services),
            definitions_considered=selection.compatible,
        )
        output["cases"].append(
            {
                "username": username,
                "results": to_value(results),
                "summary": to_value(summary),
                "analyst": doc,
                "economy": stats,
            }
        )
        print(
            json.dumps(
                {
                    "username": username,
                    "economy": stats,
                    "verdicts": [r.detection.verdict.value for r in results],
                }
            ),
            flush=True,
        )
    return output


if __name__ == "__main__":
    result = asyncio.run(run())
    output_path = (
        Path(__file__).resolve().parents[1] / "artifacts/adaptive-budget/public-smoke.json"
    )
    output_path.write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8")
