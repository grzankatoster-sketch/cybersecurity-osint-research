"""Bramka E: pokrycie pól tożsamości na trafieniach Ultimate dla par dev z etykietą ACCOUNT_EXISTS.

Pole tożsamości: display_name, bio, description, location, avatar_url, website, external_links (po filtrach silnika).
Wynik: odsetek trafień EXISTS z ≥1 polem, liczności per pole i per ekstraktor, oraz próbka 40 pól (ziarno)
do ręcznej weryfikacji precyzji → <run>/field_sample.jsonl.

Użycie: .uee-tools\\Scripts\\python.exe bench\\field_coverage.py --run bench\\results\\<run> [--labels dev_v1.jsonl]
"""
from __future__ import annotations

import argparse
import json
import random
import sys
from collections import Counter
from pathlib import Path

BENCH = Path(__file__).resolve().parent
sys.path[:0] = [str(BENCH)]

import compare  # noqa: E402
import evaluate  # noqa: E402

IDENTITY = ("display_name", "bio", "description", "location", "avatar_url", "website", "external_links")
HIT = {"FOUND", "PROBABLE"}


def fields_of(result: dict) -> list[dict]:
    pm = result.get("profile_metadata") or {}
    out = []
    raw = pm.get("fields") or {}
    items = raw.items() if isinstance(raw, dict) else ((f.get("name"), f) for f in raw)
    for name, cand in items:
        if name in IDENTITY and cand:
            out.append({"name": name, "value": cand.get("value"), "extractor": cand.get("extractor"),
                        "quality": cand.get("quality"), "source_url": cand.get("source_url")})
    return out


def main(argv=None) -> int:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--run", type=Path, required=True)
    ap.add_argument("--labels", type=Path, default=BENCH / "ground_truth" / "dev_v1.jsonl")
    ap.add_argument("--sample", type=int, default=40)
    ap.add_argument("--seed", type=int, default=20261011)
    args = ap.parse_args(argv)
    items = [it for it in evaluate.load_holdout(args.labels) if it["label"] == "ACCOUNT_EXISTS"]
    cache: dict[str, list] = {}
    hits = with_field = 0
    per_field, per_extractor, pool = Counter(), Counter(), []
    for it in items:
        nick = it["nick"]
        if nick not in cache:
            p = args.run / "raw" / nick / "ultimate" / "results.json"
            cache[nick] = json.loads(p.read_text("utf-8")) if p.exists() else []
        rows = [r for r in cache[nick] if compare.hostkey(r["profile_url"]) == it["host"]
                and r["detection"]["verdict"] in HIT]
        if not rows:
            continue
        hits += 1
        fs = [f for r in rows for f in fields_of(r)]
        if fs:
            with_field += 1
        for f in fs:
            per_field[f["name"]] += 1
            per_extractor[f["extractor"]] += 1
            pool.append({"id": it["id"], "host": it["host"], "nick": nick, **f})
    rng = random.Random(args.seed)
    sample = rng.sample(pool, min(args.sample, len(pool)))
    (args.run / "field_sample.jsonl").write_text("".join(json.dumps(x, ensure_ascii=False) + "\n" for x in sample),
                                                 encoding="utf-8")
    res = {"exists_pairs": len(items), "exists_hits": hits, "hits_with_identity_field": with_field,
           "share_of_hits": round(with_field / hits, 3) if hits else None,
           "share_of_exists": round(with_field / len(items), 3), "fields": dict(per_field),
           "extractors": dict(per_extractor.most_common()), "pool": len(pool), "sample": len(sample)}
    (args.run / "field_coverage.json").write_text(json.dumps(res, ensure_ascii=False, indent=1), encoding="utf-8")
    print(json.dumps(res, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
