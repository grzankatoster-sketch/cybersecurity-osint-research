"""Raporty HTML (F5.5) dla nicków z przebiegu bench, bez nowych żądań.

Dla każdego nicka: <run>/raw/<nick>/ultimate/results.analyst.json + identity policzone offline
(tools/identity_offline.py na results.json, seed z bench/evaluate_identity.SEEDS) → <run>/reports/<nick>.analyst.json,
potem `ultimate_username report ... --html <run>/reports/<nick>.html`.

Użycie: .uee-tools\\Scripts\\python.exe bench\\make_reports.py --run bench\\results\\<run> [--weights w.json] [nicki...]
"""
from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path

BENCH = Path(__file__).resolve().parent
ROOT = BENCH.parent
sys.path[:0] = [str(BENCH)]

from evaluate_identity import SEEDS  # noqa: E402

TOOL = ROOT / "ULTIMATE_USERNAME_ENGINE" / "tools" / "identity_offline.py"


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--run", type=Path, required=True)
    ap.add_argument("--weights", type=Path)
    ap.add_argument("nicks", nargs="*", default=["Sampler51", "PublicRefA", "publicrefb"])
    args = ap.parse_args(argv)
    out_dir = args.run / "reports"
    out_dir.mkdir(exist_ok=True)
    for nick in args.nicks:
        raw = args.run / "raw" / nick / "ultimate"
        doc = json.loads((raw / "results.analyst.json").read_text("utf-8"))
        ident = out_dir / f"{nick}.identity.json"
        cmd = [sys.executable, str(TOOL), "--results", str(raw / "results.json"), "--out", str(ident)]
        if SEEDS.get(nick):
            cmd += ["--seed-name", SEEDS[nick]]
        if args.weights:
            cmd += ["--weights", str(args.weights)]
        subprocess.run(cmd, check=True)
        doc["identity"] = json.loads(ident.read_text("utf-8"))
        target = out_dir / f"{nick}.analyst.json"
        target.write_text(json.dumps(doc, ensure_ascii=False), encoding="utf-8")
        html = out_dir / f"{nick}.html"
        subprocess.run([sys.executable, "-m", "ultimate_username", "report", str(target), "--html", str(html)], check=True)
        print(nick, html, html.stat().st_size)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
