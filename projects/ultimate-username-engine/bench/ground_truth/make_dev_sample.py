"""Losuje próbkę DEV v1 (do strojenia) z punktu zero (bench/results/2026-10-10/verdicts.json).

Pula: pary (nick, host) z verdicts.json z pominięciem hostów holdoutu i serwisów strojonych
(dev_excluded_hosts.json: holdout_hosts + tuned_hosts) oraz pustego hosta. Ziarno stałe: SEED.
Jeden host występuje w próbce najwyżej raz (pierwsza grupa wygrywa), żeby dev nie był zdominowany przez serwis.

Dla Ultimate liczone jest `rule_says` (co powiedziały reguły katalogu na zarejestrowanej odpowiedzi, przed bramką
modelu dowodu) i `rule_type` (jak rootcause_unknown.rule_type):
  FOUND            present TRUE i absent nie-TRUE (na hoście z wieloma definicjami: wystarczy jedna)
  ABSENT_FIRED     present TRUE i absent TRUE (reguły sprzeczne)
  NOT_PRESENT      present FALSE
  NO_PRESENT_RULE  definicja bez reguły present
  None             brak danych (brak wyniku Ultimate na hoście albo brak oceny reguł)

Grupy (pierwsza pasująca wygrywa, w tej kolejności):
  only_osint, only_ultimate, both_hit, rulefound_all_nicks, ult_unknown_rulefound_osint_notfound,
  ult_unknown_osint_notfound, both_notfound.

Wynik (--out, domyślnie ten katalog):
  dev_sample_v1.json     meta: pule, liczności, items (id -> grupa, rule_says, rule_type)
  to_label_dev_v1.jsonl  {"id","nick","host","candidate_urls"} BEZ grupy i werdyktów, kolejność przetasowana ziarnem
Uruchomienie powtórne daje identyczny wynik.
"""
from __future__ import annotations

import argparse
import json
import random
import sys
from pathlib import Path

GT = Path(__file__).resolve().parent
BENCH = GT.parent
ROOT = BENCH.parent
sys.path[:0] = [str(BENCH)]

import compare  # noqa: E402
from rootcause_unknown import fired, rule_type  # noqa: E402

RUN = BENCH / "results" / "2026-10-10"
SEED = 20261011
HIT = {"FOUND", "PROBABLE"}
STATUS_ONLY = "status-only"
# grupa -> tryb: "prop" (proporcjonalnie do puli nicka), "all", "pooled", "hosts" (host-level), "strat" (warstwowo wg rule_type)
GROUPS = {
    "only_osint": "prop",
    "only_ultimate": "all",
    "both_hit": "pooled",
    "rulefound_all_nicks": "hosts",
    "ult_unknown_rulefound_osint_notfound": "strat",
    "ult_unknown_osint_notfound": "pooled",
    "both_notfound": "pooled",
}
LIMITS = {
    "only_osint": 45, "only_ultimate": None, "both_hit": 15, "rulefound_all_nicks": 10,
    "ult_unknown_rulefound_osint_notfound": 25, "ult_unknown_osint_notfound": 20, "both_notfound": 10,
}
STATUS_ONLY_CAP = 12
RULE_PRIORITY = ("FOUND", "ABSENT_FIRED", "NOT_PRESENT", "NO_PRESENT_RULE")


def is_excluded(host: str, excluded: set[str]) -> bool:
    return not host or any(host == x or host.endswith("." + x) for x in excluded)


def proportional(sizes: dict[str, int], limit: int) -> dict[str, int]:
    total = sum(sizes.values())
    if total <= limit:
        return dict(sizes)
    quota = {k: limit * n / total for k, n in sizes.items()}
    alloc = {k: int(q) for k, q in quota.items()}
    for k in sorted(quota, key=lambda k: (alloc[k] - quota[k], k))[: limit - sum(alloc.values())]:
        alloc[k] += 1
    return alloc


# --------------------------------------------------------------------------- co powiedziała reguła

def one_definition(r: dict, site: dict | None) -> tuple[str | None, str]:
    """(rule_says, rule_type) jednej definicji; rule_says None = brak danych."""
    if not site:
        return None, "brak w katalogu"
    det = site["detection"]
    rtype = rule_type(det)
    if not det.get("present"):
        return "NO_PRESENT_RULE", rtype
    states = {e["rule_id"]: e["state"] for e in r["detection"].get("evidence") or []}
    pres = fired(det["present"], states, "present")
    if pres is None:
        return None, rtype
    if not pres:
        return "NOT_PRESENT", rtype
    return ("ABSENT_FIRED" if fired(det.get("absent"), states, "absent") else "FOUND"), rtype


def host_rule_info(results: list[dict], catalog: dict[str, dict]) -> dict[str, tuple[str | None, str | None]]:
    """host (bez www) -> (rule_says, rule_type); przy wielu definicjach wygrywa najsilniejsze rule_says."""
    best: dict[str, tuple[str | None, str | None]] = {}
    for r in results:
        host = compare.hostkey(r["profile_url"])
        says, rtype = one_definition(r, catalog.get(r["site_id"]))
        if says is None:
            best.setdefault(host, (None, None))
            continue
        cur = best.get(host)
        if cur is None or cur[0] is None or RULE_PRIORITY.index(says) < RULE_PRIORITY.index(cur[0]):
            best[host] = (says, rtype)
    return best


# --------------------------------------------------------------------------- losowanie

def build_sample(verdicts: dict, rule_info: dict, excluded: set[str], seed: int = SEED, limits: dict | None = None):
    """-> (private: id -> {nick, host, group, rule_says, rule_type}, to_label: list, meta: dict). Czysta funkcja."""
    lim = {**LIMITS, **(limits or {})}
    rng = random.Random(seed)
    nicks = sorted(verdicts["nicks"])

    def cat(nick: str, engine: str, host: str) -> str:
        return verdicts["nicks"][nick][engine].get(host, {}).get("category", "MISSING")

    def info(nick: str, host: str) -> tuple[str | None, str | None]:
        return rule_info.get(nick, {}).get(host, (None, None))

    # klasyfikacja par (grupy 1-3 i 5-7 na poziomie pary; grupa 4 na poziomie hosta)
    all_hosts = sorted({h for n in nicks for e in ("ultimate", "osint") for h in verdicts["nicks"][n][e]
                        if not is_excluded(h, excluded)})
    pairs: dict[str, dict[str, list[tuple[str, str]]]] = {g: {} for g in GROUPS}  # grupa -> nick -> [(nick, host)]
    cats = {}
    for n in nicks:
        for h in all_hosts:
            cu, co = cat(n, "ultimate", h), cat(n, "osint", h)
            cats[(n, h)] = (cu, co)
    rulefound_hosts = [h for h in all_hosts if all(
        cats[(n, h)][0] == "UNKNOWN" and info(n, h)[0] == "FOUND" for n in nicks)]
    rf_set = set(rulefound_hosts)

    def classify(n: str, h: str) -> str | None:
        cu, co = cats[(n, h)]
        if co in HIT and cu not in HIT:
            return "only_osint"
        if cu in HIT and co not in HIT:
            return "only_ultimate"
        if cu in HIT and co in HIT:
            return "both_hit"
        if h in rf_set and cu == "UNKNOWN":
            return None  # należy do puli rulefound_all_nicks (host-level)
        if cu == "UNKNOWN" and co == "NOT_FOUND":
            return "ult_unknown_rulefound_osint_notfound" if info(n, h)[0] == "FOUND" else "ult_unknown_osint_notfound"
        if cu == "NOT_FOUND" and co == "NOT_FOUND":
            return "both_notfound"
        return None

    for n in nicks:
        for g in GROUPS:
            pairs[g][n] = []
        for h in all_hosts:
            g = classify(n, h)
            if g:
                pairs[g][n].append((n, h))

    used: set[str] = set()
    chosen: list[tuple[str, str, str]] = []  # (grupa, nick, host)
    stats: dict[str, dict] = {}

    def take(g: str, n: str, h: str) -> None:
        used.add(h)
        chosen.append((g, n, h))

    def fresh(seq):
        return [(n, h) for n, h in seq if h not in used]

    def pooled(g: str, limit: int, seq: list[tuple[str, str]]) -> int:
        flat = list(seq)
        rng.shuffle(flat)
        got = 0
        for n, h in flat:
            if got >= limit:
                break
            if h not in used:
                take(g, n, h)
                got += 1
        return got

    for g, mode in GROUPS.items():
        limit = lim[g]
        pool_pairs = sum(len(v) for v in pairs[g].values())
        st: dict = {"mode": mode, "limit": limit, "pool_pairs": pool_pairs,
                    "pool_by_nick": {n: len(v) for n, v in pairs[g].items()}}
        before = len(chosen)
        if mode == "prop":
            alloc = proportional({n: len(v) for n, v in pairs[g].items()}, limit)
            st["allocation"] = alloc
            for n in sorted(nicks, key=lambda n: (len(pairs[g][n]), n)):  # najmniejsze pule najpierw
                avail = sorted(fresh(pairs[g][n]))
                for _, h in rng.sample(avail, min(alloc[n], len(avail))):
                    take(g, n, h)
            short = limit - (len(chosen) - before)
            if short > 0:  # unikalność hostów mogła zabrać część puli nicka: dolosuj z reszty
                pooled(g, short, sorted(p for v in pairs[g].values() for p in v))
        elif mode == "all":
            by_host: dict[str, list[str]] = {}
            for n in nicks:
                for _, h in pairs[g][n]:
                    if h not in used:
                        by_host.setdefault(h, []).append(n)
            st["pool_hosts"] = len(by_host)
            for h in sorted(by_host):
                take(g, rng.choice(by_host[h]), h)
        elif mode == "pooled":
            pooled(g, limit, sorted(p for v in pairs[g].values() for p in v))
        elif mode == "hosts":
            avail = sorted(h for h in rulefound_hosts if h not in used)
            st["pool_hosts"] = len(rulefound_hosts)
            st["pool_hosts_free"] = len(avail)
            for h in sorted(rng.sample(avail, min(limit, len(avail)))):
                take(g, rng.choice(nicks), h)
        else:  # strat: do STATUS_ONLY_CAP par status-only, reszta pozostałe typy; braki uzupełnia druga warstwa
            flat = sorted(p for v in pairs[g].values() for p in v)
            rng.shuffle(flat)
            status = [p for p in flat if info(*p)[1] == STATUS_ONLY]
            other = [p for p in flat if info(*p)[1] != STATUS_ONLY]
            st["pool_status_only"], st["pool_other_types"] = len(status), len(other)
            got = 0
            for n, h in status:
                if got >= min(STATUS_ONLY_CAP, limit):
                    break
                if h not in used:
                    take(g, n, h)
                    got += 1
            for n, h in other:
                if got >= limit:
                    break
                if h not in used:
                    take(g, n, h)
                    got += 1
            for n, h in status:  # braki innych typów: uzupełnij status-only
                if got >= limit:
                    break
                if h not in used:
                    take(g, n, h)
                    got += 1
        new = chosen[before:]
        st["sampled"] = len(new)
        st["sampled_by_nick"] = {n: sum(1 for x in new if x[1] == n) for n in nicks}
        if g == "ult_unknown_rulefound_osint_notfound":
            st["sampled_status_only"] = sum(1 for x in new if info(x[1], x[2])[1] == STATUS_ONLY)
        stats[g] = st

    order = list(range(len(chosen)))
    rng.shuffle(order)
    private, to_label, items = {}, [], []
    for i, k in enumerate(order, 1):
        g, n, h = chosen[k]
        urls = sorted({verdicts["nicks"][n][e][h]["url"] for e in ("ultimate", "osint") if h in verdicts["nicks"][n][e]})
        says, rtype = info(n, h)
        ident = f"d1-{i:03d}"
        private[ident] = {"nick": n, "host": h, "group": g, "rule_says": says, "rule_type": rtype}
        to_label.append({"id": ident, "nick": n, "host": h, "candidate_urls": urls})
        items.append({"id": ident, "group": g, "rule_says": says, "rule_type": rtype})
    meta = {"seed": seed, "source_run": "bench/results/2026-10-10/verdicts.json",
            "excluded_hosts_count": len(excluded), "pool_hosts_after_exclusion": len(all_hosts),
            "groups": stats, "total": len(to_label), "items": items}
    return private, to_label, meta


# --------------------------------------------------------------------------- dane z dysku

def load_catalog(path: Path) -> dict[str, dict]:
    return {s["id"]: s for s in json.loads(path.read_text("utf-8-sig"))}


def collect_rule_info(run: Path, catalog: dict[str, dict], nicks) -> dict:
    out = {}
    for n in nicks:
        results = json.loads((run / "raw" / n / "ultimate" / "results.json").read_text("utf-8"))
        out[n] = host_rule_info(results, catalog)
    return out


def main(argv=None) -> None:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--run", type=Path, default=RUN)
    ap.add_argument("--catalog", type=Path, default=ROOT / "ULTIMATE_USERNAME_ENGINE" / "data" / "catalog.json")
    ap.add_argument("--excluded", type=Path, default=GT / "dev_excluded_hosts.json")
    ap.add_argument("--out", type=Path, default=GT)
    # część B (nicki dev): inny prefiks id, sufiks plików, hosty już użyte w dev_v1 wykluczone, własne limity
    ap.add_argument("--id-prefix", default="d1")
    ap.add_argument("--suffix", default="")
    ap.add_argument("--exclude-labeled", type=Path, help="jsonl z etykietami; jego hosty są wykluczane")
    ap.add_argument("--limits", help='JSON z limitami grup, np. {"only_osint": 30}')
    ap.add_argument("--seed", type=int, default=SEED)
    args = ap.parse_args(argv)
    verdicts = json.loads((args.run / "verdicts.json").read_text("utf-8"))
    ex = json.loads(args.excluded.read_text("utf-8"))
    excluded = set(ex["holdout_hosts"]) | set(ex["tuned_hosts"])
    if args.exclude_labeled:
        excluded |= {json.loads(x)["host"] for x in args.exclude_labeled.read_text("utf-8").splitlines() if x.strip()}
    limits = {**LIMITS, **json.loads(args.limits)} if args.limits else None
    rules = collect_rule_info(args.run, load_catalog(args.catalog), sorted(verdicts["nicks"]))
    private, to_label, meta = build_sample(verdicts, rules, excluded, seed=args.seed, limits=limits)
    if args.id_prefix != "d1":
        ren = {it["id"]: args.id_prefix + it["id"][2:] for it in to_label}
        for x in to_label + meta["items"]:
            x["id"] = ren[x["id"]]
    meta["source_run"] = str(args.run).replace("\\", "/") + "/verdicts.json"
    args.out.mkdir(parents=True, exist_ok=True)
    (args.out / f"dev_sample_v1{args.suffix}.json").write_text(json.dumps(meta, ensure_ascii=False, indent=2), encoding="utf-8")
    (args.out / f"to_label_dev_v1{args.suffix}.jsonl").write_text(
        "".join(json.dumps(x, ensure_ascii=False) + "\n" for x in to_label), encoding="utf-8")
    for g, st in meta["groups"].items():
        extra = {k: st[k] for k in ("pool_hosts", "pool_status_only", "pool_other_types", "sampled_status_only") if k in st}
        print(f"{g}: pula par {st['pool_pairs']} {extra} limit {st['limit']} -> wylosowano {st['sampled']} {st['sampled_by_nick']}")
    print("razem", meta["total"])


if __name__ == "__main__":
    main()
