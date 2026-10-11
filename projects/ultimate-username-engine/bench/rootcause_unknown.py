"""Przyczyny UNKNOWN w Ultimate dla kont, które istnieją (holdout: ACCOUNT_EXISTS, Ultimate = UNKNOWN).

Użycie (z katalogu OSINTCHYBANOWY):
    .uee-tools\\Scripts\\python.exe bench\\rootcause_unknown.py --run bench\\results\\2026-10-10 [--no-live]

Dla każdego przypadku:
- typ reguły w katalogu (z liści drzew detection.present / detection.absent: `status` albo `message`);
- powód z wyniku Ultimate (detection.reasons), ostatni status HTTP, przekierowanie (final_url ≠ probe_url);
- (bez --no-live) pomiar żądania kontrolnego: GET probe_url dla prawdziwej nazwy i dla losowej nazwy kontrolnej,
  porównanie statusu, finalnego URL i tytułu (po usunięciu nazwy). „Rozróżnia” = różni się co najmniej jedno z nich.
Logika detekcji nie jest wywoływana ani zmieniana. Wynik: <run>/rootcause_unknown.{json,md}.
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from collections import Counter, defaultdict
from pathlib import Path

BENCH = Path(__file__).resolve().parent
ROOT = BENCH.parent
sys.path[:0] = [str(BENCH), str(BENCH / "ground_truth")]

import compare  # noqa: E402
import evaluate  # noqa: E402

CONTROL = "uee{}zq7x3"


def leaves(rule: dict | None) -> list[str]:
    if not rule:
        return []
    if rule["strategy"] in ("any", "all"):
        return [x for ch in rule.get("children") or [] for x in leaves(ch)]
    return [rule["strategy"]]


def rule_type(detection: dict) -> str:
    p, a = set(leaves(detection["present"])), set(leaves(detection["absent"]))
    if not p:
        return "brak reguły present" + (" (absent: " + "+".join(sorted(a)) + ")" if a else "")
    if p | a == {"status"}:
        return "status-only"
    if p == {"status"}:
        return "present status, absent message"
    if not a:
        return "present message, brak absent"
    if a == {"status"}:
        return "present message, absent status"
    return "message (present i absent)"


def fired(rule: dict | None, states: dict[str, str], path: str) -> bool | None:
    """Wynik drzewa reguły (any/all) z liści w evidence; None = brak reguły albo brak oceny."""
    if not rule:
        return None
    if rule["strategy"] in ("any", "all"):
        kids = [fired(ch, states, f"{path}.{i}") for i, ch in enumerate(rule.get("children") or [])]
        kids = [k for k in kids if k is not None]
        if not kids:
            return None
        return any(kids) if rule["strategy"] == "any" else all(kids)
    state = states.get(path)
    return None if state is None else state == "TRUE"


def rule_outcome(evidence: list[dict], detection: dict) -> str:
    """Co powiedziały reguły katalogu na tej odpowiedzi (przed bramką modelu dowodu)."""
    states = {e["rule_id"]: e["state"] for e in evidence}
    pres = fired(detection["present"], states, "present")
    absn = fired(detection["absent"], states, "absent")
    if pres is None:
        return "brak oceny present"
    if not pres:
        return "present nie trafia"
    if absn:
        return "sprzeczne (present i absent TRUE)"
    return "reguła mówi FOUND (present TRUE, absent FALSE/brak)"


def norm_title(title: str, name: str) -> str:
    return re.sub(re.escape(name), "<N>", title, flags=re.I).strip().lower()


def control_probe(url: str, nick: str) -> dict:
    import fetch_page

    ctrl_name = CONTROL.format(len(nick))
    out = {}
    for tag, name in (("real", nick), ("control", ctrl_name)):
        target = re.sub(re.escape(nick), name, url, flags=re.I)
        final, status, raw, err = fetch_page.http_get(target)
        title, text = fetch_page.visible_text(raw)
        out[tag] = {"url": target, "final_url": re.sub(re.escape(name), "<N>", final, flags=re.I), "status": status,
                    "title": norm_title(title, name)[:120], "text_len": len(text), "error": err}
    r, c = out["real"], out["control"]
    if r["status"] is None or c["status"] is None:
        verdict = "brak odpowiedzi"
    elif r["status"] in (403, 429, 503) and c["status"] == r["status"]:
        verdict = "blokada"
    else:
        diff = [k for k in ("status", "final_url", "title") if r[k] != c[k]]
        gap = abs(r["text_len"] - c["text_len"])
        weak = gap > max(200, 0.2 * max(r["text_len"], c["text_len"]))
        out["differs_on"] = diff + (["length"] if weak else [])
        verdict = "rozróżnia" if diff else "rozróżnia (tylko długość)" if weak else "nie rozróżnia"
    out["verdict"] = verdict
    return out


def main() -> int:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--run", type=Path, required=True)
    ap.add_argument("--holdout", type=Path, default=BENCH / "ground_truth" / "holdout_v1.jsonl")
    ap.add_argument("--no-live", action="store_true")
    args = ap.parse_args()
    verdicts = evaluate.load_verdicts(args.run)
    items = evaluate.load_holdout(args.holdout)
    cases = [it for it in items if it["label"] == "ACCOUNT_EXISTS"
             and evaluate.prediction(verdicts, "ultimate", it["nick"], it["host"]) == "UNKNOWN"]
    other = Counter(evaluate.prediction(verdicts, "ultimate", it["nick"], it["host"])
                    for it in items if it["label"] == "ACCOUNT_EXISTS")
    catalog = {s["id"]: s for s in json.loads((ROOT / "ULTIMATE_USERNAME_ENGINE" / "data" / "catalog.json").read_text("utf-8"))}
    by_nick = defaultdict(list)
    for it in cases:
        by_nick[it["nick"]].append(it)
    rows = []
    for nick, its in by_nick.items():
        results = json.loads((args.run / "raw" / nick / "ultimate" / "results.json").read_text("utf-8"))
        idx = defaultdict(list)
        for r in results:
            idx[compare.hostkey(r["profile_url"])].append(r)
        for it in its:
            defs = [r for r in idx[it["host"]] if r["detection"]["verdict"] == "UNKNOWN" and r["detection"]["state"] == "OK"]
            for r in defs:
                site = catalog.get(r["site_id"], {})
                last = r["attempts"][-1] if r.get("attempts") else {}
                row = {"id": it["id"], "nick": nick, "host": it["host"], "identity": it["identity"], "site_id": r["site_id"],
                       "rule_type": rule_type(site["detection"]) if site else "brak w katalogu",
                       "method": site.get("method", "?"), "reasons": r["detection"]["reasons"],
                       "rule_outcome": rule_outcome(r["detection"]["evidence"], site["detection"]) if site else "brak w katalogu",
                       "response_class": r["detection"]["response_class"], "last_status": last.get("status"),
                       "redirected": compare.hostkey(r.get("final_url") or "") != compare.hostkey(r["probe_url"])
                       or (r.get("final_url") or "").rstrip("/") != r["probe_url"].rstrip("/"),
                       "probe_url": r["probe_url"]}
                if not args.no_live and row["method"] == "GET":
                    row["control"] = control_probe(r["probe_url"], nick)
                rows.append(row)
    # jeden wiersz na przypadek (pierwsza definicja) do liczenia przyczyn; wszystkie definicje w JSON
    first = {}
    for row in rows:
        first.setdefault(row["id"], row)
    prim = list(first.values())
    summary = {
        "cases_exists_ultimate_unknown": len(cases), "definitions": len(rows),
        "ultimate_predictions_among_exists": dict(other),
        "by_rule_type": dict(Counter(r["rule_type"] for r in prim).most_common()),
        "by_reason": dict(Counter("+".join(r["reasons"]) for r in prim).most_common()),
        "by_rule_outcome": dict(Counter(r["rule_outcome"] for r in prim).most_common()),
        "by_last_status": dict(Counter(str(r["last_status"]) for r in prim).most_common()),
        "redirected": sum(r["redirected"] for r in prim),
        "control_by_rule_type": {},
    }
    if not args.no_live:
        tab, tab2 = defaultdict(Counter), defaultdict(Counter)
        for r in prim:
            v = r.get("control", {}).get("verdict", "nie badano (nie-GET)")
            tab[r["rule_type"]][v] += 1
            tab2[r["rule_outcome"]][v] += 1
        summary["control_by_rule_type"] = {k: dict(v) for k, v in tab.items()}
        summary["control_by_rule_outcome"] = {k: dict(v) for k, v in tab2.items()}
    (args.run / "rootcause_unknown.json").write_text(json.dumps({"summary": summary, "rows": rows}, ensure_ascii=False, indent=1),
                                                    encoding="utf-8")
    lines = [f"# Przyczyny UNKNOWN w Ultimate dla ACCOUNT_EXISTS ({args.run.name}, {args.holdout.name})", "",
             f"Przypadki: {len(cases)} (definicji: {len(rows)}). Werdykty Ultimate dla wszystkich EXISTS: {dict(other)}.", "",
             "| Typ reguły | Przypadki | Żądanie kontrolne: rozróżnia / tylko długość / nie / blokada / brak odp. / nie badano |",
             "|---|---:|---|"]
    for rt, n in summary["by_rule_type"].items():
        c = summary["control_by_rule_type"].get(rt, {})
        lines.append(f"| {rt} | {n} | {c.get('rozróżnia', 0)} / {c.get('rozróżnia (tylko długość)', 0)} / "
                     f"{c.get('nie rozróżnia', 0)} / {c.get('blokada', 0)} / "
                     f"{c.get('brak odpowiedzi', 0)} / {c.get('nie badano (nie-GET)', 0)} |")
    lines += ["", "## Co powiedziały reguły katalogu (przed bramką modelu dowodu)", "",
              "| Wynik reguł | Przypadki | Kontrola: rozróżnia / tylko długość / nie / nie badano |", "|---|---:|---|"]
    for ro, n in summary["by_rule_outcome"].items():
        c = summary.get("control_by_rule_outcome", {}).get(ro, {})
        lines.append(f"| {ro} | {n} | {c.get('rozróżnia', 0)} / {c.get('rozróżnia (tylko długość)', 0)} / "
                     f"{c.get('nie rozróżnia', 0)} / {c.get('nie badano (nie-GET)', 0)} |")
    lines += ["", f"Powody Ultimate: {summary['by_reason']}", f"Ostatni status HTTP: {summary['by_last_status']}",
              f"Przekierowane: {summary['redirected']}", "", "## Przypadki", "",
              "| id | nick:host | typ reguły | wynik reguł | powód | status | kontrola |", "|---|---|---|---|---|---:|---|"]
    for r in prim:
        ctl = r.get("control", {})
        lines.append(f"| {r['id']} | {r['nick']}:{r['host']} | {r['rule_type']} | {r['rule_outcome']} | {'+'.join(r['reasons'])} | "
                     f"{r['last_status']} | "
                     f"{ctl.get('verdict', '—')} {ctl.get('differs_on', '')} |")
    md = "\n".join(lines) + "\n"
    (args.run / "rootcause_unknown.md").write_text(md, encoding="utf-8")
    print(md)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
