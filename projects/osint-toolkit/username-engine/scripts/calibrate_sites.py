"""Kalibracja nowych serwisów: kandydaci (JSON) -> zweryfikowane reguły w resources/custom_sites.json.

Reguła trafia do bazy TYLKO gdy na żywo: znane konto = FOUND (pewność >= 0.6) i losowa nazwa = NOT_FOUND.
Najpierw próbujemy reguły „kod + kontrola losowej nazwy”; gdy nie rozróżnia, szukamy znacznika profilu
obecnego na stronie znanego konta, a nieobecnego na stronie losowej nazwy.

python scripts/calibrate_sites.py kandydaci.json [--merge]   (--merge: dopisz do istniejących własnych reguł)
"""
from __future__ import annotations

import argparse
import asyncio
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from username_engine.engine import check_site, random_name  # noqa: E402
from username_engine.http import Fetcher  # noqa: E402
from username_engine.models import Site, Status  # noqa: E402

CUSTOM = ROOT / "src" / "username_engine" / "resources" / "custom_sites.json"
PROFILE_MARKERS = ('"@type":"Person"', '"@type": "Person"', '"ProfilePage"', 'og:type" content="profile',
                   "og:type' content='profile", 'profile:username', '"profile_id"', 'itemtype="http://schema.org/Person"',
                   'itemtype="https://schema.org/Person"')


def to_site(c: dict) -> Site:
    tags = list(dict.fromkeys([*(c.get("tags") or []), c.get("group") or "", (c.get("country") or "").lower()]))
    return Site(name=c["name"], url=c["url"], probe_url=c.get("probe_url") or None, check_type="status_code",
                tags=[t for t in tags if t], known=[c["known"]] if c.get("known") else [])


async def verify(site: Site, fetcher: Fetcher) -> tuple[bool, str]:
    known = await check_site(site, site.known[0], fetcher, control="all")
    rnd = await check_site(site, random_name(), fetcher, control="all")
    ok = known.status is Status.FOUND and known.confidence >= 0.6 and rnd.status is Status.NOT_FOUND
    return ok, f"znane: {known.status.value} {known.confidence:.2f} ({known.reason}); losowa: {rnd.status.value} ({rnd.reason})"


async def find_marker(site: Site, fetcher: Fetcher) -> str | None:
    k = await fetcher.fetch("GET", site.request_url(site.known[0]))
    r = await fetcher.fetch("GET", site.request_url(random_name()))
    if k.status is None or r.status is None:
        return None
    for m in PROFILE_MARKERS:
        if m in k.text and m not in r.text:
            return m
    return None


async def calibrate(cands: list[dict]) -> tuple[list[dict], list[dict]]:
    accepted, rejected = [], []
    async with Fetcher(timeout=20, per_host=1, retries=1) as f:
        sem = asyncio.Semaphore(8)

        async def one(c: dict):
            if not c.get("known") or "{username}" not in c.get("url", "") or c.get("login_wall"):
                rejected.append({"name": c.get("name"), "why": "brak znanego konta / wzorca / wymaga logowania"})
                return
            site = to_site(c)
            async with sem:
                ok, why = await verify(site, f)
                if not ok:
                    marker = await find_marker(site, f)
                    if marker:
                        site.check_type, site.e_strings = "message", [marker]
                        ok, why = await verify(site, f)
                        why = f"znacznik {marker!r}: {why}"
            if ok:
                accepted.append({**site.to_dict(), "source": "custom", "calibrated": why})
                print(f"[OK]  {site.name}: {why}", flush=True)
            else:
                rejected.append({"name": site.name, "why": why})
                print(f"[--]  {site.name}: {why}", flush=True)

        await asyncio.gather(*(one(c) for c in cands))
    return accepted, rejected


def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("candidates")
    p.add_argument("--merge", action="store_true")
    a = p.parse_args()
    cands = json.loads(Path(a.candidates).read_text(encoding="utf-8"))
    accepted, rejected = asyncio.run(calibrate(cands))
    existing = json.loads(CUSTOM.read_text(encoding="utf-8")).get("sites", []) if (a.merge and CUSTOM.exists()) else []
    names = {s["name"] for s in accepted}
    sites = [s for s in existing if s["name"] not in names] + sorted(accepted, key=lambda s: s["name"].lower())
    CUSTOM.parent.mkdir(parents=True, exist_ok=True)
    CUSTOM.write_text(json.dumps({"meta": {"note": "reguły zweryfikowane na żywo: scripts/calibrate_sites.py"},
                                  "sites": sites}, ensure_ascii=False, indent=1), encoding="utf-8")
    rej = CUSTOM.with_name("custom_rejected.json")
    rej.write_text(json.dumps(rejected, ensure_ascii=False, indent=1), encoding="utf-8")
    print(f"\nPrzyjęte: {len(accepted)}, odrzucone: {len(rejected)} -> {CUSTOM.name} (+ {rej.name})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
