"""Szybki pomiar Ultimate tylko na definicjach hostów z etykietami (dev ∪ holdout), do iteracji.

Dla każdego nicka z plików etykiet: definicje katalogu, których host profilu == host pary (jak run_pairs.site_ids_for),
jeden przebieg CLI `search --mode exhaustive --site ...` → <run>/raw/<nick>/ultimate/results.json.
Potem: `assemble_run.py --run <run> --osint-from <punkt zero>` i `evaluate.py`.
Uwaga: mniej żądań niż pełny skan, więc mniej limitów (lekki optymizm). Bramki końcowe liczymy na pełnym przebiegu.

Użycie: .uee-tools\\Scripts\\python.exe bench\\run_labeled.py --run bench\\results\\<tag> --labels a.jsonl b.jsonl
"""
from __future__ import annotations

import argparse
import json
import sys
from collections import defaultdict
from pathlib import Path

BENCH = Path(__file__).resolve().parent
ROOT = BENCH.parent
sys.path[:0] = [str(BENCH)]

import run_pairs  # noqa: E402


def main(argv=None) -> int:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--run", type=Path, required=True)
    ap.add_argument("--labels", type=Path, nargs="+", required=True)
    args = ap.parse_args(argv)
    catalog = {s["id"]: s for s in json.loads((ROOT / "ULTIMATE_USERNAME_ENGINE" / "data" / "catalog.json").read_text("utf-8"))}
    hosts: dict[str, set[str]] = defaultdict(set)
    for path in args.labels:
        for it in run_pairs.load_pairs(path):
            hosts[it["nick"]].add(it["host"])
    for nick, hs in sorted(hosts.items()):
        ids = sorted({sid for h in hs for sid in run_pairs.site_ids_for(catalog, h, nick)})
        out = (args.run / "raw" / nick / "ultimate").resolve()
        out.mkdir(parents=True, exist_ok=True)
        code = run_pairs.run_cli(nick, ids, out)
        print(f"{nick}: {len(hs)} hostów, {len(ids)} definicji, kod {code}", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
