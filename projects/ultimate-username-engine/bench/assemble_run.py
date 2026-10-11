"""Składa verdicts.json przebiegu `compare.py --only ultimate` z werdyktami OSINT z wcześniejszych przebiegów.

OSINT się nie zmienia, więc jego werdykty bierzemy z punktu zero (verdicts.json i verdicts_extra.json podanych przebiegów).
Potem (opcjonalnie) raport kodów powodu Ultimate na parach z etykietami: dla każdej pary zbiera
(werdykt, pierwszy kod powodu) definicji na hoście i liczy etykiety. Daje precyzję każdej reguły z jednego przebiegu.

Użycie (z katalogu OSINTCHYBANOWY):
    .uee-tools\\Scripts\\python.exe bench\\assemble_run.py --run bench\\results\\<tag> \\
        --osint-from bench\\results\\2026-10-10 [--reasons bench\\ground_truth\\dev_v1.jsonl]
"""
from __future__ import annotations

import argparse
import json
import sys
from collections import Counter, defaultdict
from pathlib import Path

BENCH = Path(__file__).resolve().parent
sys.path[:0] = [str(BENCH)]

import compare  # noqa: E402
import evaluate  # noqa: E402


def osint_verdicts(sources: list[Path]) -> dict[str, dict]:
    out: dict[str, dict] = {}
    for src in sources:
        for name in ("verdicts.json", "verdicts_extra.json"):
            p = src / name
            if p.exists():
                for nick, engines in json.loads(p.read_text("utf-8"))["nicks"].items():
                    if "osint" in engines:
                        out.setdefault(nick, engines["osint"])
    return out


def assemble(run: Path, sources: list[Path]) -> dict:
    osint = osint_verdicts(sources)
    data: dict = {"source": f"{run.name}/raw (ultimate) + osint z {[s.name for s in sources]}",
                  "order": list(evaluate.ORDER), "nicks": {}}
    for nick_dir in sorted(p for p in (run / "raw").iterdir() if p.is_dir()):
        data["nicks"][nick_dir.name] = {
            "ultimate": evaluate.aggregate(compare.ultimate_rows(nick_dir / "ultimate")),
            "osint": osint.get(nick_dir.name, {}),
        }
    (run / "verdicts.json").write_text(json.dumps(data, ensure_ascii=False, separators=(",", ":"), sort_keys=True),
                                       encoding="utf-8")
    return data


def reason_report(run: Path, labels: Path) -> dict:
    items = evaluate.load_holdout(labels)
    by_nick = defaultdict(list)
    for it in items:
        by_nick[it["nick"]].append(it)
    table: dict[str, Counter] = defaultdict(Counter)
    examples: dict[str, list[str]] = defaultdict(list)
    for nick, its in by_nick.items():
        for base in (run / "raw" / nick / "ultimate", run / "raw_extra" / nick):
            if (base / "results.json").exists():
                results = json.loads((base / "results.json").read_text("utf-8"))
                break
        else:
            continue
        idx = defaultdict(list)
        for r in results:
            idx[compare.hostkey(r["profile_url"])].append(r)
        for it in its:
            for r in idx[it["host"]]:
                d = r["detection"]
                key = f'{d["verdict"]}/{(d.get("reasons") or ["-"])[0]}'
                table[key][it["label"]] += 1
                if len(examples[key]) < 6:
                    examples[key].append(f'{it["id"]}:{it["host"]}={it["label"][:6]}')
    return {k: {"labels": dict(v), "examples": examples[k]} for k, v in sorted(table.items())}


def main(argv=None) -> int:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--run", type=Path, required=True)
    ap.add_argument("--osint-from", type=Path, nargs="+", default=[])
    ap.add_argument("--reasons", type=Path)
    args = ap.parse_args(argv)
    if args.osint_from:
        data = assemble(args.run, args.osint_from)
        print("verdicts.json:", {n: (len(e["ultimate"]), len(e["osint"])) for n, e in data["nicks"].items()})
    if args.reasons:
        rep = reason_report(args.run, args.reasons)
        out = args.run / f"reasons_{args.reasons.stem}.json"
        out.write_text(json.dumps(rep, ensure_ascii=False, indent=1), encoding="utf-8")
        for k, v in rep.items():
            print(f"{k:60} {v['labels']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
