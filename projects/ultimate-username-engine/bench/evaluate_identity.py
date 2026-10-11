"""Ocena identity_score offline (F4) na zapisanym przebiegu: widok TARGET z etykiet IDENTITY.

Pozytyw = EXISTS i TARGET; negatyw = ABSENT albo EXISTS i HOMONYM (EXISTS/UNKNOWN pomijane, jak w evaluate.py).
Predykcja TARGET = Ultimate ma trafienie (FOUND/PROBABLE) na hoście I identity daje TARGET_LIKELY dla tego hosta.
Seed: imię osoby docelowej per nick (SEEDS), wyłączany przez --no-seed. Przedziały Wilsona 95%.

Użycie (moduł identity z PYTHONPATH, np. worktree faza-4):
    .uee-tools\\Scripts\\python.exe bench\\evaluate_identity.py --run bench\\results\\<run> \\
        --labels bench\\ground_truth\\dev_v1.jsonl [--no-seed] [--threshold 0.5] [--weights w.json]
"""
from __future__ import annotations

import argparse
import importlib.util
import json
import math
import sys
from collections import defaultdict
from pathlib import Path

BENCH = Path(__file__).resolve().parent
sys.path[:0] = [str(BENCH)]

import compare  # noqa: E402
import evaluate  # noqa: E402

SEEDS = {"PublicRefA": "Ingrid Testova", "publicrefb": "Casey Fixton",
         "PublicRefCh": "Noel Fixtur", "vexalune": "Alune Orvo"}
HIT = {"FOUND", "PROBABLE"}


def wilson(k: int, n: int, z: float = 1.96) -> tuple[float, float]:
    if n == 0:
        return (0.0, 1.0)
    p = k / n
    d = 1 + z * z / n
    c = (p + z * z / (2 * n)) / d
    h = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / d
    return (max(0.0, c - h), min(1.0, c + h))


def load_offline():
    import ultimate_username

    tools = Path(ultimate_username.__file__).resolve().parents[2] / "tools" / "identity_offline.py"
    spec = importlib.util.spec_from_file_location("identity_offline", tools)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def assess(run: Path, nicks: set[str], seeds: bool, config) -> dict[tuple[str, str], dict]:
    from ultimate_username.identity import IdentitySeed, score_identities

    off = load_offline()
    out: dict[tuple[str, str], dict] = {}
    for nick in sorted(nicks):
        for base in (run / "raw" / nick / "ultimate", run / "raw_extra" / nick):
            if (base / "results.json").exists():
                results = off.load_results(base / "results.json")
                break
        else:
            continue
        seed = IdentitySeed(name=SEEDS.get(nick, "")) if seeds else None
        scored = score_identities(results, seed, None, config)
        for r in results:
            a = scored.get(off.result_key(r) if hasattr(off, "result_key") else r.profile_url)
            if a is None:
                from ultimate_username.identity import result_key
                a = scored.get(result_key(r))
            if a is None:
                continue
            key = (nick, compare.hostkey(r.profile_url))
            cur = out.get(key)
            if cur is None or a.score > cur["score"]:
                out[key] = {"score": a.score, "decision": a.decision.value,
                            "signals": [s.kind for s in a.signals]}
    return out


def main(argv=None) -> int:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--run", type=Path, required=True)
    ap.add_argument("--labels", type=Path, required=True)
    ap.add_argument("--no-seed", action="store_true")
    ap.add_argument("--threshold", type=float)
    ap.add_argument("--weights", type=Path)
    ap.add_argument("--quiet", action="store_true")
    args = ap.parse_args(argv)
    from ultimate_username.identity import DEFAULT_CONFIG, IdentityConfig

    config = IdentityConfig.load(args.weights) if args.weights else DEFAULT_CONFIG
    if args.threshold is not None:
        config = IdentityConfig.from_mapping({**{k: getattr(config, k) for k in config.__dataclass_fields__},
                                              "threshold": args.threshold})
    verdicts = evaluate.load_verdicts(args.run)
    items = [it for it in evaluate.load_holdout(args.labels) if it["label"] != "UNVERIFIABLE"]
    view = [(it, evaluate.target_view(it)) for it in items]
    view = [(it, pos) for it, pos in view if pos is not None]
    scores = assess(args.run, {it["nick"] for it, _ in view}, not args.no_seed, config)
    tp = fp = fn = tn = 0
    rows = []
    for it, pos in view:
        hit = evaluate.prediction(verdicts, "ultimate", it["nick"], it["host"]) in HIT
        a = scores.get((it["nick"], it["host"]), {"score": 0.0, "decision": "-", "signals": []})
        pred = hit and a["decision"] == "TARGET_LIKELY"
        tp += pos and pred
        fp += (not pos) and pred
        fn += pos and not pred
        tn += (not pos) and not pred
        if pos or hit:
            rows.append(f'{it["id"]:7} {it["nick"]:14} {it["host"]:28} {"TARGET " if pos else "NEG    "} '
                        f'hit={int(hit)} {a["score"]:.2f} {a["decision"]:16} {",".join(a["signals"])[:80]}')
    p = tp / (tp + fp) if tp + fp else float("nan")
    r = tp / (tp + fn) if tp + fn else float("nan")
    res = {"n": len(view), "positives": tp + fn, "TP": tp, "FP": fp, "FN": fn, "TN": tn, "P": p, "R": r,
           "P_ci95": wilson(tp, tp + fp), "R_ci95": wilson(tp, tp + fn), "seed": not args.no_seed,
           "threshold": config.threshold}
    print(json.dumps(res, ensure_ascii=False))
    if not args.quiet:
        print("\n".join(rows))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
