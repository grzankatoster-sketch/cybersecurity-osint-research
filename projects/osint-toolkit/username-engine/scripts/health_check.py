"""Kontrola stanu bazy -> data/health.json. Uruchamiaj po każdym build_db.py (ok. 5–8 min).

python scripts/health_check.py [--db data/sites.json] [--out data/health.json]
"""
from __future__ import annotations

import argparse
import asyncio
import sys
import time
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from username_engine.health import check_health, save_health  # noqa: E402
from username_engine.http import Fetcher  # noqa: E402
from username_engine.sources import load_db  # noqa: E402

LABELS = {"ok": "sprawne", "dead": "martwe (DNS)", "blocked": "zablokowane", "false_positive": "fałszywe trafienia",
          "stale": "przestarzałe (znane konto = brak)", "unstable": "niestabilne (timeout/5xx)"}


def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--db", default=str(ROOT / "data" / "sites.json"))
    p.add_argument("--out", default=str(ROOT / "data" / "health.json"))
    a = p.parse_args()
    sites = load_db(a.db)
    counts: Counter = Counter()
    started = time.monotonic()

    def on_done(name: str, state: str) -> None:
        counts[state] += 1
        done = sum(counts.values())
        if done % 100 == 0 or done == len(sites):
            print(f"  [{done}/{len(sites)}] {time.monotonic() - started:.0f} s  " +
                  ", ".join(f"{k}: {v}" for k, v in counts.most_common()), flush=True)

    async def run():
        async with Fetcher() as f:
            return await check_health(sites, f, on_done=on_done)

    print(f"Kontrola {len(sites)} serwisów (losowa nazwa + znane konto)...")
    health = asyncio.run(run())
    save_health(health, a.out)
    print("\nWynik:")
    for state, n in Counter(v["state"] for v in health.values()).most_common():
        print(f"  {LABELS.get(state, state)}: {n}")
    print(f"Zapisano: {a.out}  (skan pomija: martwe, zablokowane, fałszywe trafienia; --include-broken = wszystkie)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
