"""Raport recall fazy 2: P/R/F1/pokrycie na zamrożonym zbiorze 43 przypadków, z jawnym ryzykiem przeuczenia.

Liczy metryki od nowa z ultimate-validation.json, v1-validation-replay.json, old-validation.json
i validation-ground-truth.json (semantyka jak w ../recall_metrics.py, które przy imporcie nadpisuje artefakty,
więc nie jest importowane), porównuje z metrics.json i sprawdza, czy kod kanoniczny = kod zamrożony.
Użycie: .uee-tools\\Scripts\\python.exe bench\\recall_report.py [--date 2026-10-10]
"""
from __future__ import annotations

import argparse
import hashlib
import json
from collections import Counter
from datetime import date
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
ART = ROOT / "recall_phase2_work/artifacts/recall-phase2-2026-10-09"
CANON = ROOT / "ULTIMATE_USERNAME_ENGINE"
# Serwisy z ręcznym adapterem właściciela profilu z 2026-10-09 (detection_quality_work, odpowiedzi dla Sampler51),
# niezmieniane w fazie 2.
ADAPTER_SITES = {"GitHub", "Kick", "Chess", "FACEIT", "GOG", "Pinterest"}
# Serwisy strojone w fazie 2: OpenSea/ChaturBate (fixture'y Sampler51 w tests/recall_detection),
# Engadget/Mcbans (rule-fix-calibration.json, inne nazwy niż walidacyjne).
RULE_FIX_SITES = {"OpenSea", "ChaturBate", "Engadget", "Mcbans"}


def load(name: str):
    return json.loads((ART / name).read_text("utf-8"))


def metrics(decide, cases):
    labelled = [c for c in cases if c["label"] in ("EXISTS", "DOES_NOT_EXIST")]
    n = Counter()
    for c in labelled:
        positive = decide(c["case_index"]) in ("FOUND", "PROBABLE")
        actual = c["label"] == "EXISTS"
        n["TP" if actual and positive else "FN" if actual else "FP" if positive else "TN"] += 1
    tp, fp, tn, fn = (n[k] for k in ("TP", "FP", "TN", "FN"))
    div = lambda a, b: round(a / b, 4) if b else None
    decisive = sum(decide(c["case_index"]) in ("FOUND", "PROBABLE", "NOT_FOUND") for c in cases)
    return {"TP": tp, "FP": fp, "TN": tn, "FN": fn, "labelled": len(labelled), "total": len(cases),
            "precision": div(tp, tp + fp), "recall": div(tp, tp + fn), "F1": div(2 * tp, 2 * tp + fp + fn),
            "decision_coverage": div(decisive, len(cases)), "abstentions": len(cases) - decisive}


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--date", default=date.today().isoformat())
    out_dir = ROOT / "bench/results" / ap.parse_args().date
    truth = load("validation-ground-truth.json")["cases"]
    v2, v1, old = load("ultimate-validation.json"), load("v1-validation-replay.json"), load("old-validation.json")
    deciders = {
        "V2 (kanoniczna)": lambda i: v2["results"][i]["result"]["detection"]["verdict"],
        "V1 (przed fazą 2)": lambda i: v1["results"][i]["detection"]["verdict"],
        "OSINT (stary)": lambda i: old["results"][i]["result"]["status"],
    }
    # Strojenie: (serwis, nazwa) użyte w kalibracji / fixture'ach testów.
    tuned_pairs = {(c["site"].split(" [")[0], c["username"]) for c in load("rule-fix-calibration.json")}
    tuned_pairs |= {(c["site"] if isinstance(c["site"], str) else c["site"]["name"], c["username"])
                    for c in json.loads((CANON / "tests/recall_detection/cases.json").read_text("utf-8"))}
    calibration_sites = {c["site"] for c in load("calibration-replay.json")}
    rows = []
    for c in truth:
        i, site = c["case_index"], c["site"]
        rows.append({"case": i, "site": site, "username": c["username"], "label": c["label"],
                     "v2": deciders["V2 (kanoniczna)"](i), "v1": deciders["V1 (przed fazą 2)"](i),
                     "osint": deciders["OSINT (stary)"](i),
                     "name_used_in_tuning": (site, c["username"]) in tuned_pairs,
                     "site_tuned": "adapter 10-09" if site in ADAPTER_SITES else "faza 2" if site in RULE_FIX_SITES
                     else "kalibracja" if site in calibration_sites else "nie"})
    adapter = [c for c in truth if c["site"] in ADAPTER_SITES]
    phase2 = [c for c in truth if c["site"] in RULE_FIX_SITES]
    groups = {"wszystkie 43": truth, f"strojone tylko 10-09 ({len(adapter)})": adapter,
              f"strojone w fazie 2 ({len(phase2)})": phase2}
    result = {e: {g: metrics(d, cs) for g, cs in groups.items()} for e, d in deciders.items()}
    reference = load("metrics.json")["validation"]
    h = lambda p: hashlib.sha256(p.read_bytes()).hexdigest()
    frozen = load("validation-freeze.json")
    drift = [k for k, v in frozen["ultimate"].items() if h(CANON / k.replace(chr(92), "/")) != v]
    report = {
        "dataset": {"cases": len(truth), "labels": dict(Counter(c["label"] for c in truth)),
                    "sites": sorted({c["site"] for c in truth})},
        "metrics": result,
        "matches_codex_metrics_json": all(
            result[e]["wszystkie 43"][k] == round(reference[r][k], 4)
            for e, r in (("V2 (kanoniczna)", "ultimate"), ("V1 (przed fazą 2)", "v1"), ("OSINT (stary)", "old"))
            for k in ("precision", "recall", "F1", "decision_coverage")),
        "overfitting": {
            "validation_names_used_in_tuning": sum(r["name_used_in_tuning"] for r in rows),
            "validation_sites_tuned": f"{sum(r['site_tuned'] != 'nie' for r in rows)}/{len(rows)}",
            "independent_site_holdout_cases": sum(r["site_tuned"] == "nie" for r in rows),
            "canonical_source_equals_frozen": not drift, "frozen_files": len(frozen["ultimate"]),
            "freeze_utc": frozen["utc"], "validation_started_utc": v2["started_utc"],
            "labels_assigned": "ręcznie po obejrzeniu odpowiedzi (indeksy zaszyte w recall_metrics.py)",
        },
        "cases": rows,
    }
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / "recall_v2.json").write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
    print(json.dumps({k: v for k, v in report.items() if k != "cases"}, ensure_ascii=False, indent=1))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
