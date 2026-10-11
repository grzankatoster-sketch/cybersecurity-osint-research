# ruff: noqa: E402
"""Comparable field scoring; raw values retained so normalization can be reviewed."""

import argparse
import json
import logging
import re
import sys
import time
import types
from datetime import datetime
from decimal import Decimal
from pathlib import Path

from donor_runtime import guard, load

ROOT = Path(__file__).resolve().parents[2] / "artifacts/enrichment"
p = argparse.ArgumentParser()
p.add_argument("--after", action="store_true")
args = p.parse_args()
sys.path.insert(0, str(ROOT.parents[1] / "src" if args.after else ROOT / "baseline-src.zip"))
from ultimate_username.domain.codec import from_value
from ultimate_username.domain.models import ExtractionRule, TransportResponse
from ultimate_username.extraction import extract

if args.after:
    pass

main, wrapper = load()
guard()
aliases = {
    "uid": "user_id",
    "fullname": "display_name",
    "image": "avatar_url",
    "image_bg": "banner_url",
    "follower_count": "followers",
    "following_count": "following",
    "posts_count": "posts",
    "blog_url": "website",
    "is_verified": "verified",
}


def normalize(k, v):
    if k in ("followers", "following", "posts", "public_repos_count", "public_gists_count"):
        try:
            return int(v)
        except (TypeError, ValueError):
            if isinstance(v, str):
                match = re.fullmatch(r"(\d+(?:\.\d+)?)([KMB])", v, re.I)
                if match:
                    number = (
                        Decimal(match[1])
                        * {"K": 1000, "M": 1000000, "B": 1000000000}[match[2].upper()]
                    )
                    if number == number.to_integral_value():
                        return int(number)
    if (
        k in ("verified", "is_looking_for_job", "is_nsfw")
        and isinstance(v, str)
        and v.lower() in ("true", "false")
    ):
        return v.lower() == "true"
    if k == "user_id":
        return str(v)
    if k == "created_at":
        try:
            return datetime.fromisoformat(v.replace("Z", "+00:00")).isoformat()
        except (ValueError, TypeError):
            pass
    return v


def score(raw, expected, errors, elapsed):
    actual = {
        aliases.get(k, k): normalize(aliases.get(k, k), v)
        for k, v in raw.items()
        if not k.startswith("_")
    }
    correct = {
        k: v
        for k, v in actual.items()
        if k in expected and type(v) is type(expected[k]) and v == expected[k]
    }
    return dict(
        raw=raw,
        actual=actual,
        correct=len(correct),
        returned=len(actual),
        wrong=len(actual) - len(correct),
        missing=len(expected) - len(correct),
        empty=sum(v in ("", None) for v in actual.values()),
        errors=errors,
        seconds=elapsed,
    )


results = []
for c in json.loads((ROOT / "cases.json").read_text(encoding="utf-8")):
    response = TransportResponse(
        c["url"],
        c["status"],
        c["body"].encode(),
        (
            (
                "Content-Type",
                "application/json" if c["kind"] == "json" else "text/html; charset=utf-8",
            ),
        ),
        c["url"],
    )
    errors = []
    started = time.perf_counter()
    try:
        raw = main.extract(c["body"])
    except Exception as e:
        raw = {}
        errors = [type(e).__name__]
    elapsed = time.perf_counter() - started
    # Maigret wrapper is called only on CLAIMED; simulate that shared status gate.
    gated = c["status"] == 200
    wrapped = (
        wrapper(c["body"], logging.getLogger("audit"), types.SimpleNamespace(name=c["id"]))
        if gated
        else {}
    )
    if not gated:
        raw = {}
        errors = []
    if wrapped != raw:
        raise AssertionError((c["id"], wrapped, raw))
    row = dict(
        id=c["id"],
        expected=c["expected"],
        response_bytes=len(response.body),
        network_seconds=0,
        network="NONE: in-memory controlled fixture",
        kind=c["kind"],
        detection_gate=gated,
        maigret=score(raw, c["expected"], errors, elapsed),
    )
    started = time.perf_counter()
    if args.after:
        from ultimate_username.domain.models import (
            DetectionResult,
            DetectionSpec,
            Rule,
            SiteDefinition,
            Verdict,
        )
        from ultimate_username.enrichment import enrich

        site = SiteDefinition(
            c["id"], c["id"], c["url"], DetectionSpec(Rule("status", statuses=(200,)))
        )
        detection = DetectionResult(Verdict.FOUND) if gated else DetectionResult()
        metadata = enrich(response, c["username"], site, detection)
        raw = {
            f.name: list(f.value) if isinstance(f.value, tuple) else f.value
            for f in metadata.fields + metadata.extra_fields
        }
        errors = list(metadata.errors)
        row["extraction_sources"] = [
            {
                "name": f.name,
                "extractor": f.extractor,
                "evidence": f.evidence,
                "quality": f.quality.value,
            }
            for f in metadata.fields + metadata.extra_fields
        ]
        row["metadata_state"] = metadata.state.value
        row["ultimate_after"] = score(raw, c["expected"], errors, time.perf_counter() - started)
    else:
        rules = tuple(from_value(ExtractionRule, r) for r in c["rules"])
        result = extract(response, c["username"], rules) if gated else None
        raw = {f.name: f.value() for f in result.fields} if result else {}
        if c["id"] == "discourse" and "bio" in raw:
            raw["description"] = raw.pop("bio")
        row["ultimate_before"] = score(
            raw,
            c["expected"],
            [e.message for e in result.errors] if result else [],
            time.perf_counter() - started,
        )
    results.append(row)
out = ROOT / ("after.json" if args.after else "before.json")
out.write_text(json.dumps(results, ensure_ascii=False, indent=2), encoding="utf-8")
for model in ("maigret", "ultimate_after" if args.after else "ultimate_before"):
    print(
        model,
        {
            k: sum(r[model][k] for r in results)
            for k in ("returned", "correct", "wrong", "missing", "empty")
        },
        "errors",
        sum(bool(r[model]["errors"]) for r in results),
    )
