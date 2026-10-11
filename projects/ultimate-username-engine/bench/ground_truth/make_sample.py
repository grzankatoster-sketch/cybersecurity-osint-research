"""Losuje próbkę holdout v1 z punktu zero (bench/results/2026-10-10/verdicts.json).

Pomija hosty serwisów strojonych (tuned_services.json). Ziarno stałe: SEED.
Wynik: sample_v1.json (pule, liczności, ziarno) i to_label_v1.jsonl, czyli lista do oznaczenia BEZ werdyktów silników
(nick, host, URL-e kandydatów z obu katalogów). Uruchomienie powtórne daje identyczną próbkę.
"""
from __future__ import annotations

import json
import random
from pathlib import Path

GT = Path(__file__).resolve().parent
RUN = GT.parent / "results" / "2026-10-10"
SEED = 20261010
HIT = {"FOUND", "PROBABLE"}
# grupa -> (limit, rozdział): "prop" = proporcjonalnie do puli każdego nicka, "all" = wszystko, "pooled" = losowo z puli łącznej
GROUPS = {
    "only_osint": (90, "prop"),
    "only_ultimate": (None, "all"),
    "both_hit": (20, "pooled"),
    "ult_unknown_osint_notfound": (30, "pooled"),
    "both_notfound": (15, "pooled"),
}


def group_of(cu: str, co: str) -> str | None:
    if co in HIT and cu not in HIT:
        return "only_osint"
    if cu in HIT and co not in HIT:
        return "only_ultimate"
    if cu in HIT and co in HIT:
        return "both_hit"
    if cu == "UNKNOWN" and co == "NOT_FOUND":
        return "ult_unknown_osint_notfound"
    if cu == "NOT_FOUND" and co == "NOT_FOUND":
        return "both_notfound"
    return None


def tuned(host: str, tuned_hosts: set[str]) -> bool:
    return any(host == t or host.endswith("." + t) for t in tuned_hosts)


def proportional(sizes: dict[str, int], limit: int) -> dict[str, int]:
    total = sum(sizes.values())
    if total <= limit:
        return dict(sizes)
    quota = {k: limit * n / total for k, n in sizes.items()}
    alloc = {k: int(q) for k, q in quota.items()}
    for k in sorted(quota, key=lambda k: (alloc[k] - quota[k], k))[: limit - sum(alloc.values())]:
        alloc[k] += 1
    return alloc


def main() -> None:
    verdicts = json.loads((RUN / "verdicts.json").read_text("utf-8"))
    tuned_hosts = {h for s in json.loads((GT / "tuned_services.json").read_text("utf-8"))["services"] for h in s["hosts"]}
    pools: dict[str, dict[str, list[str]]] = {g: {} for g in GROUPS}
    excluded: dict[str, list[str]] = {}
    for nick, d in sorted(verdicts["nicks"].items()):
        u, o = d["ultimate"], d["osint"]
        for g in GROUPS:
            pools[g][nick] = []
        for host in sorted(set(u) | set(o)):
            g = group_of(u.get(host, {}).get("category", "MISSING"), o.get(host, {}).get("category", "MISSING"))
            if g is None:
                continue
            if tuned(host, tuned_hosts):
                excluded.setdefault(g, []).append(f"{nick}:{host}")
                continue
            pools[g][nick].append(host)
    rng = random.Random(SEED)
    chosen: list[tuple[str, str, str]] = []
    for g, (limit, mode) in GROUPS.items():
        if mode == "all":
            chosen += [(g, n, h) for n, hs in pools[g].items() for h in hs]
        elif mode == "prop":
            alloc = proportional({n: len(hs) for n, hs in pools[g].items()}, limit)
            for n, hs in pools[g].items():
                chosen += [(g, n, h) for h in sorted(rng.sample(hs, alloc[n]))]
        else:
            flat = [(n, h) for n, hs in pools[g].items() for h in hs]
            chosen += [(g, n, h) for n, h in sorted(rng.sample(flat, min(limit, len(flat))))]
    items = []
    for i, (g, n, h) in enumerate(chosen, 1):
        urls = sorted({verdicts["nicks"][n][e][h]["url"] for e in ("ultimate", "osint") if h in verdicts["nicks"][n][e]})
        items.append({"id": f"h1-{i:03d}", "nick": n, "host": h, "group": g, "candidate_urls": urls})
    meta = {
        "seed": SEED, "source_run": "bench/results/2026-10-10/verdicts.json", "groups": {
            g: {"limit": lim, "mode": mode, "pool_after_exclusion": {n: len(hs) for n, hs in pools[g].items()},
                "excluded_tuned": excluded.get(g, []),
                "sampled": {n: sum(1 for x in chosen if x[0] == g and x[1] == n) for n in pools[g]}}
            for g, (lim, mode) in GROUPS.items()},
        "total": len(items),
    }
    (GT / "sample_v1.json").write_text(json.dumps(meta, ensure_ascii=False, indent=2), encoding="utf-8")
    (GT / "to_label_v1.jsonl").write_text("".join(json.dumps(x, ensure_ascii=False) + "\n" for x in items), encoding="utf-8")
    for g, m in meta["groups"].items():
        print(g, "pula:", m["pool_after_exclusion"], "wylosowano:", m["sampled"], "wykluczone strojone:", len(m["excluded_tuned"]))
    print("razem", len(items))


if __name__ == "__main__":
    main()
