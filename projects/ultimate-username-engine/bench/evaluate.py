"""Ocena obu silników na zamrożonym holdoucie (bench/ground_truth/holdout_v1.jsonl).

Użycie (z katalogu OSINTCHYBANOWY):
    .uee-tools\\Scripts\\python.exe bench\\evaluate.py --run bench\\results\\2026-10-10
    ... --holdout bench\\ground_truth\\holdout_v1.jsonl   (domyślnie)
    ... --rebuild-verdicts                               (przelicz verdicts.json z raw/)

Werdykty silników: <run>/verdicts.json (zwarty, w gicie). Jeśli go nie ma, powstaje z <run>/raw/
tą samą normalizacją co bench/compare.py (ultimate_rows, osint_rows). Wiele definicji na jednym hoście
składa się w jeden werdykt według kolejności FOUND > PROBABLE > NOT_FOUND > UNKNOWN > BLOCKED > ERROR > SKIPPED
(tak samo jak „trafienie” w compare.py). Brak hosta w katalogu silnika = MISSING.

Semantyka (jak w bench/recall_report.py):
- trafienie = FOUND lub PROBABLE; jawna decyzja = FOUND, PROBABLE lub NOT_FOUND;
- TP = EXISTS i trafienie; FP = ABSENT i trafienie; FN = EXISTS bez trafienia (także UNKNOWN i inne wstrzymania);
- UNVERIFIABLE jest wyłączone z P/R i raportowane osobno;
- widok TARGET: pozytyw = EXISTS i IDENTITY=TARGET, negatyw = ABSENT albo EXISTS i HOMONYM;
  EXISTS z IDENTITY=UNKNOWN jest w tym widoku pomijane.
Wynik: <run>/evaluation_<holdout>.json i .md. Próbka jest warstwowa, więc P/R dotyczą próbki, nie całego katalogu.
"""
from __future__ import annotations

import argparse
import json
import sys
from collections import Counter
from pathlib import Path

BENCH = Path(__file__).resolve().parent
sys.path.insert(0, str(BENCH))

ENGINES = ("ultimate", "osint")
ORDER = ("FOUND", "PROBABLE", "NOT_FOUND", "UNKNOWN", "BLOCKED", "ERROR", "SKIPPED")
HIT = {"FOUND", "PROBABLE"}
DECIDED = {"FOUND", "PROBABLE", "NOT_FOUND"}
LABELS = ("ACCOUNT_EXISTS", "ACCOUNT_ABSENT", "UNVERIFIABLE")
IDENTITIES = ("TARGET", "HOMONYM", "UNKNOWN")


def aggregate(rows: list[dict]) -> dict[str, dict]:
    """Host -> {category, url} z najsilniejszego wiersza (kolejność ORDER)."""
    best: dict[str, dict] = {}
    for r in rows:
        cur = best.get(r["key"])
        if cur is None or ORDER.index(r["category"]) < ORDER.index(cur["category"]):
            best[r["key"]] = {"category": r["category"], "url": r["url"], "raw": r["raw"]}
    return best


def build_verdicts(run: Path) -> dict:
    import compare  # noqa: PLC0415 - tylko przy budowie z raw/

    out: dict = {"source": f"{run.name}/raw via bench/compare.py", "order": list(ORDER), "nicks": {}}
    for nick_dir in sorted(p for p in (run / "raw").iterdir() if p.is_dir()):
        out["nicks"][nick_dir.name] = {
            "ultimate": aggregate(compare.ultimate_rows(nick_dir / "ultimate")),
            "osint": aggregate(compare.osint_rows(nick_dir / "osint")),
        }
    return out


def merge_extra(data: dict, extra: dict) -> dict:
    """Scala werdykty dodatkowe (bench/run_pairs.py); dopisuje tylko brakujące nicki/hosty, nic nie nadpisuje."""
    for nick, engines in extra.get("nicks", {}).items():
        for engine, hosts in engines.items():
            slot = data["nicks"].setdefault(nick, {}).setdefault(engine, {})
            for host, v in hosts.items():
                slot.setdefault(host, v)
    return data


def load_verdicts(run: Path, rebuild: bool = False) -> dict:
    path = run / "verdicts.json"
    if rebuild or not path.exists():
        data = build_verdicts(run)
        path.write_text(json.dumps(data, ensure_ascii=False, separators=(",", ":"), sort_keys=True), encoding="utf-8")
    else:
        data = json.loads(path.read_text("utf-8"))
    extra = run / "verdicts_extra.json"
    if extra.exists():  # w pamięci; verdicts.json na dysku zostaje bez zmian
        merge_extra(data, json.loads(extra.read_text("utf-8")))
    return data


def load_holdout(path: Path) -> list[dict]:
    items = [json.loads(line) for line in path.read_text("utf-8").splitlines() if line.strip()]
    for it in items:
        assert it["label"] in LABELS, it
        assert it["identity"] in IDENTITIES, it
    return items


def prediction(verdicts: dict, engine: str, nick: str, host: str) -> str:
    hit = verdicts["nicks"].get(nick, {}).get(engine, {}).get(host)
    return hit["category"] if hit else "MISSING"


def score(items: list[dict], preds: list[str], positive) -> dict:
    """positive(item) -> True/False/None (None = poza oceną)."""
    tp, fp, fn, tn = [], [], [], []
    for it, p in zip(items, preds):
        truth = positive(it)
        if truth is None:
            continue
        ref = f"{it['nick']}:{it['host']}"
        if truth and p in HIT:
            tp.append(ref)
        elif truth:
            fn.append((ref, p))
        elif p in HIT:
            fp.append((ref, p))
        else:
            tn.append((ref, p))
    n = len(tp) + len(fp) + len(fn) + len(tn)
    pos = len(tp) + len(fn)
    decided = sum(1 for it, p in zip(items, preds) if positive(it) is not None and p in DECIDED)
    pos_preds = [p for it, p in zip(items, preds) if positive(it)]
    return {
        "n": n, "positives": pos, "negatives": n - pos,
        "tp": len(tp), "fp": len(fp), "fn": len(fn), "tn": len(tn),
        "precision": round(len(tp) / (len(tp) + len(fp)), 3) if tp or fp else None,
        "recall": round(len(tp) / pos, 3) if pos else None,
        "coverage": round(decided / n, 3) if n else None,
        "unknown_among_positives": round(pos_preds.count("UNKNOWN") / pos, 3) if pos else None,
        "positives_by_prediction": dict(Counter(pos_preds)),
        "fn_explicit_not_found": sorted(r for r, p in fn if p == "NOT_FOUND"),
        "fn_abstain": sorted(f"{r} ({p})" for r, p in fn if p != "NOT_FOUND"),
        "fp_hosts": sorted(f"{r} ({p})" for r, p in fp),
    }


def exists_view(it: dict) -> bool | None:
    return None if it["label"] == "UNVERIFIABLE" else it["label"] == "ACCOUNT_EXISTS"


def target_view(it: dict) -> bool | None:
    if it["label"] == "UNVERIFIABLE":
        return None
    if it["label"] == "ACCOUNT_ABSENT":
        return False
    return {"TARGET": True, "HOMONYM": False}.get(it["identity"])


def evaluate(verdicts: dict, items: list[dict]) -> dict:
    result: dict = {
        "holdout_size": len(items),
        "labels": dict(Counter(it["label"] for it in items)),
        "identity_among_exists": dict(Counter(it["identity"] for it in items if it["label"] == "ACCOUNT_EXISTS")),
        "groups": {}, "engines": {},
    }
    for g in sorted({it["group"] for it in items}):
        sub = [it for it in items if it["group"] == g]
        result["groups"][g] = {"n": len(sub), "labels": dict(Counter(it["label"] for it in sub)),
                               "target": sum(1 for it in sub if it["label"] == "ACCOUNT_EXISTS" and it["identity"] == "TARGET")}
    for engine in ENGINES:
        preds = [prediction(verdicts, engine, it["nick"], it["host"]) for it in items]
        unver = [(f"{it['nick']}:{it['host']}", p) for it, p in zip(items, preds) if it["label"] == "UNVERIFIABLE"]
        per_group = {}
        for g in result["groups"]:
            idx = [i for i, it in enumerate(items) if it["group"] == g]
            s = score([items[i] for i in idx], [preds[i] for i in idx], exists_view)
            per_group[g] = {k: s[k] for k in ("n", "tp", "fp", "fn", "tn", "precision", "recall", "coverage")}
        result["engines"][engine] = {
            "exists": score(items, preds, exists_view),
            "target": score(items, preds, target_view),
            "per_group": per_group,
            "unverifiable_predictions": dict(Counter(p for _, p in unver)),
        }
    return result


def fmt(v) -> str:
    return "—" if v is None else (f"{v:.3f}".replace(".", ",") if isinstance(v, float) else str(v))


def render_md(res: dict, holdout_name: str, run_name: str) -> str:
    lines = [f"# Ocena na holdoucie `{holdout_name}` (werdykty: `{run_name}`)", "",
             f"Holdout: {res['holdout_size']} par (nick, host). Etykiety: {res['labels']}. "
             f"IDENTITY wśród EXISTS: {res['identity_among_exists']}.", "",
             "| Widok | Silnik | n | TP | FP | FN | TN | P | R | Pokrycie | UNKNOWN wśród pozytywów |",
             "|---|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|"]
    for view in ("exists", "target"):
        for engine in ENGINES:
            s = res["engines"][engine][view]
            lines.append(f"| {view} | {engine} | {s['n']} | {s['tp']} | {s['fp']} | {s['fn']} | {s['tn']} | "
                         f"{fmt(s['precision'])} | {fmt(s['recall'])} | {fmt(s['coverage'])} | {fmt(s['unknown_among_positives'])} |")
    lines += ["", "## Według grupy próbki (widok exists)", "",
              "| Grupa | n | etykiety | Ultimate TP/FP/FN | OSINT TP/FP/FN |", "|---|---:|---|---|---|"]
    for g, info in res["groups"].items():
        u, o = res["engines"]["ultimate"]["per_group"][g], res["engines"]["osint"]["per_group"][g]
        lines.append(f"| {g} | {info['n']} | {info['labels']} | {u['tp']}/{u['fp']}/{u['fn']} | {o['tp']}/{o['fp']}/{o['fn']} |")
    for engine in ENGINES:
        e = res["engines"][engine]
        lines += ["", f"## {engine}", "",
                  f"- Werdykty dla prawdziwych kont (EXISTS): {e['exists']['positives_by_prediction']}",
                  f"- FP ({len(e['exists']['fp_hosts'])}): {', '.join(e['exists']['fp_hosts']) or '—'}",
                  f"- FN jawne NOT_FOUND ({len(e['exists']['fn_explicit_not_found'])}): {', '.join(e['exists']['fn_explicit_not_found']) or '—'}",
                  f"- FN przez wstrzymanie ({len(e['exists']['fn_abstain'])}): {', '.join(e['exists']['fn_abstain']) or '—'}",
                  f"- Widok TARGET, FP (homonim albo brak konta) ({len(e['target']['fp_hosts'])}): {', '.join(e['target']['fp_hosts']) or '—'}",
                  f"- UNVERIFIABLE, werdykty silnika: {e['unverifiable_predictions'] or '—'}"]
    lines += ["", "Uwaga: próbka jest warstwowa (nadreprezentacja rozbieżności), więc P/R opisują próbkę, a nie cały katalog.", ""]
    return "\n".join(lines)


def main(argv=None) -> int:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--run", type=Path, required=True)
    ap.add_argument("--holdout", type=Path, default=BENCH / "ground_truth" / "holdout_v1.jsonl",
                    help="plik etykiet dowolnej nazwy (np. dev_v1.jsonl); wynik: evaluation_<nazwa>.json/.md")
    ap.add_argument("--rebuild-verdicts", action="store_true")
    args = ap.parse_args(argv)
    verdicts = load_verdicts(args.run, args.rebuild_verdicts)
    res = evaluate(verdicts, load_holdout(args.holdout))
    stem = "evaluation_" + args.holdout.stem
    (args.run / f"{stem}.json").write_text(json.dumps(res, ensure_ascii=False, indent=2), encoding="utf-8")
    md = render_md(res, args.holdout.name, args.run.name)
    (args.run / f"{stem}.md").write_text(md, encoding="utf-8")
    print(md)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
