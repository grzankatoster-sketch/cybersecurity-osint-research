"""Offline identity scoring of a saved results.json: no network, no images.

Lets weights and the threshold be tuned on stored runs (``--weights`` takes a JSON object with
IdentityConfig field overrides). Input: a JSON array of SearchResult objects (the CLI ``--output``
file), an object with a ``results`` array, or NDJSON.

    python tools/identity_offline.py --results run.json --seed-name "Noel Fixtur" --out id.json
"""

from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Sequence
from dataclasses import replace
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from ultimate_username.domain.codec import from_value  # noqa: E402
from ultimate_username.domain.json_types import parse_json  # noqa: E402
from ultimate_username.domain.models import JSONValue, SearchResult  # noqa: E402
from ultimate_username.identity import (  # noqa: E402
    IdentityConfig,
    IdentitySeed,
    identity_document,
    score_identities,
)


def load_results(path: Path) -> list[SearchResult]:
    text = path.read_text(encoding="utf-8-sig")
    items: list[JSONValue]
    try:
        data = parse_json(text)
    except ValueError:
        items = [parse_json(line) for line in text.splitlines() if line.strip()]
    else:
        if isinstance(data, dict) and isinstance(data.get("results"), list):
            data = data["results"]
        if not isinstance(data, list):
            raise ValueError("Expected a JSON array of SearchResult objects")
        items = data
    return [from_value(SearchResult, item, f"results[{i}]") for i, item in enumerate(items)]


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Offline identity scoring of a results.json")
    parser.add_argument("--results", type=Path, required=True)
    parser.add_argument("--seed-name", default="")
    parser.add_argument("--seed-url", action="append", default=[])
    parser.add_argument("--weights", type=Path, help="JSON with IdentityConfig overrides")
    parser.add_argument("--threshold", type=float, help="overrides the threshold from --weights")
    parser.add_argument("--out", required=True, help="output JSON path; - writes to stdout")
    arguments = parser.parse_args(argv)
    try:
        config = IdentityConfig.load(arguments.weights) if arguments.weights else IdentityConfig()
        if arguments.threshold is not None:
            config = replace(config, threshold=arguments.threshold)
        results = load_results(arguments.results)
        seed = IdentitySeed(arguments.seed_name, tuple(arguments.seed_url))
        seed_used = None if seed.empty else seed
        document = identity_document(
            score_identities(results, seed_used, None, config),
            config=config,
            seed=seed_used,
            results=results,
        )
        document["source"] = str(arguments.results)
        document["results_loaded"] = len(results)
        document["config"] = dict(config.to_mapping())
        text = json.dumps(document, ensure_ascii=False, indent=2, allow_nan=False) + "\n"
        if arguments.out == "-":
            sys.stdout.write(text)
        else:
            Path(arguments.out).write_text(text, encoding="utf-8")
    except (OSError, ValueError) as exc:
        print(f"identity_offline: {exc}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
