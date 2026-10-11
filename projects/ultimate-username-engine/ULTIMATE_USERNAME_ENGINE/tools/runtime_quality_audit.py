"""Replay captured responses against a selectable source tree, without networking.

The same runner supports baseline and repaired packages in separate processes.
"""

from __future__ import annotations

import argparse
import asyncio
import base64
import json
import statistics
import sys
from dataclasses import replace
from pathlib import Path
from time import perf_counter


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--corpus", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--label", choices=("before", "after"), required=True)
    args = parser.parse_args()
    sys.dont_write_bytecode = True
    sys.path.insert(0, str(args.source.resolve()))
    from ultimate_username.domain.codec import from_value, to_value
    from ultimate_username.domain.metadata import EnrichmentMode
    from ultimate_username.domain.models import SiteDefinition, TransportResponse
    from ultimate_username.engine import SearchOptions, UsernameEngine
    from ultimate_username.registry import SiteRegistry
    from ultimate_username.transport import FakeTransport

    corpus = json.loads(args.corpus.read_text(encoding="utf-8"))

    async def one(case, mode):
        site = from_value(SiteDefinition, case["site"])
        registry = SiteRegistry([site])
        if args.label == "after":
            from ultimate_username.selection import prepared_registry

            registry = prepared_registry(registry)
        response = TransportResponse(
            case["url"],
            case["status"],
            base64.b64decode(case["body_base64"]),
            (("Content-Type", case["content_type"]),),
            case["final_url"],
            body_complete=case["body_complete"],
        )
        transport = FakeTransport(
            handler=lambda request, index: replace(response, requested_url=request.url)
        )
        start = perf_counter()
        async with UsernameEngine(registry, transport) as engine:
            result = (
                await engine.search(
                    case["username"],
                    options=SearchOptions(
                        enrichment_mode=mode,
                        request_budget=1,
                    ),
                )
            )[0]
        elapsed = (perf_counter() - start) * 1000
        fields = {
            f.name: to_value(f.value)
            for f in result.profile_metadata.fields + result.profile_metadata.extra_fields
        }
        row = {
            "id": case["id"],
            "expected_exists": case["expected_exists"],
            "response_sha256": case["body_sha256"],
            "source_content_type": case["content_type"],
            "body_type": case["expected_type"],
            "verdict": result.detection.verdict.value,
            "state": result.detection.state.value,
            "metadata_state": result.profile_metadata.state.value,
            "fields": fields,
            "field_count": len(fields),
            "requests": transport.total,
            "elapsed_ms": elapsed,
            "metadata": to_value(result.profile_metadata),
        }
        if args.label == "after":
            from ultimate_username.presentation import analyst_record

            row["analyst"] = analyst_record(result, registry)
        return row

    async def run():
        rows = [await one(case, EnrichmentMode.BASIC) for case in corpus if "status" in case]
        benchmark = {}
        case = next((c for c in corpus if c["id"] == "github:octocat"), None)
        for mode in (EnrichmentMode.OFF, EnrichmentMode.BASIC, EnrichmentMode.FULL) if case else ():
            samples = [await one(case, mode) for _ in range(5)]
            benchmark[mode.value] = {
                "median_ms": statistics.median(r["elapsed_ms"] for r in samples),
                "samples_ms": [r["elapsed_ms"] for r in samples],
                "request_counts": [r["requests"] for r in samples],
                "note": (
                    "Captured identical body; FULL has no follow-up URLs or extra budget; "
                    "process spawn included, network excluded"
                ),
            }
        summary = {
            "tested": sum(r["requests"] > 0 for r in rows),
            "found": sum(r["verdict"] == "FOUND" for r in rows),
            "probable": sum(r["verdict"] == "PROBABLE" for r in rows),
            "not_found": sum(r["verdict"] == "NOT_FOUND" for r in rows),
            "blocked": sum(r["state"] == "BLOCKED" for r in rows),
            "not_tested": sum(r["requests"] == 0 for r in rows),
            "profiles_with_metadata": sum(bool(r["fields"]) for r in rows),
            "useful_fields": sum(r["field_count"] for r in rows),
            "metadata_empty_despite_usable_body": sum(
                r["metadata_state"] == "EMPTY" and r["expected_exists"] for r in rows
            ),
        }
        return {"label": args.label, "summary": summary, "cases": rows, "performance": benchmark}

    result = asyncio.run(run())
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8")
    print(
        json.dumps(
            {
                "label": args.label,
                "summary": result["summary"],
                "performance_ms": {k: v["median_ms"] for k, v in result["performance"].items()},
            }
        )
    )


if __name__ == "__main__":
    main()
