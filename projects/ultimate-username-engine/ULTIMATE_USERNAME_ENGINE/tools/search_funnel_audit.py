"""Offline inventory, current selection and historical observed search funnel."""

from __future__ import annotations

import argparse
import json
import sys
from collections import Counter
from pathlib import Path

sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))


def main():
    from ultimate_username.domain.codec import to_value
    from ultimate_username.registry import SiteRegistry
    from ultimate_username.selection import prepared_registry, select_services, service_key

    parser = argparse.ArgumentParser()
    parser.add_argument("--project", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    registry = SiteRegistry.from_json(
        (args.project / "data/catalog.json").read_text(encoding="utf-8")
    )
    raw_groups = Counter(service_key(e.definition) for e in registry.entries if e.definition)
    prepared = prepared_registry(registry)
    plan = select_services(prepared, "JanKowalski")
    historical = {}
    for filename in ("proba.json", "Sampler51_test.json"):
        rows = json.loads((args.project / "results" / filename).read_text(encoding="utf-8"))
        historical[filename] = {
            "username": rows[0]["username"]["raw"],
            "selected_emitted": len(rows),
            "tested": sum(bool(r["attempts"]) for r in rows),
            "request_attempts": sum(len(r["attempts"]) for r in rows),
            "http_responses": sum(a.get("status") is not None for r in rows for a in r["attempts"]),
            "not_tested": sum(not r["attempts"] for r in rows),
            "not_tested_reasons": Counter(
                r["detection"]["state"] for r in rows if not r["attempts"]
            ),
            "tested_verdicts": Counter(r["detection"]["verdict"] for r in rows if r["attempts"]),
            "tested_states": Counter(r["detection"]["state"] for r in rows if r["attempts"]),
        }
    conflict_path = args.project / "data/conflicts.json"
    conflicts = json.loads(conflict_path.read_text(encoding="utf-8"))
    output = {
        "registry_definitions": len(registry.entries),
        "canonical_profile_template_groups": len(raw_groups),
        "alternative_definitions_in_all_groups": sum(n - 1 for n in raw_groups.values()),
        "groups_with_multiple_definitions": sum(n > 1 for n in raw_groups.values()),
        "grouping_rule": (
            "Exact profile host+path+query template, trailing slash normalized; "
            "reviewed www alias only for GitHub. "
            "Not an assertion about all real-world organizations/services."
        ),
        "historical_import_conflicts_type": type(conflicts).__name__,
        "historical_import_conflicts_count": len(conflicts),
        "original_revision": registry.revision,
        "prepared_revision": prepared.revision,
        "current_plan": to_value(plan),
        "historical": historical,
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(output, ensure_ascii=False, indent=2), encoding="utf-8")
    print(json.dumps({k: v for k, v in output.items() if k not in ("current_plan", "historical")}))
    print(
        json.dumps(
            {
                "enabled": plan.enabled,
                "valid": plan.valid,
                "compatible": plan.compatible,
                "selected": len(plan.selected),
                "exclusions": Counter(r for _, r in plan.excluded),
                "first_5": plan.selected[:5],
            }
        )
    )


if __name__ == "__main__":
    main()
