"""Test evaluate.py na małych danych sztucznych (bez sieci i bez raw/)."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import evaluate  # noqa: E402


def item(host, label, identity="UNKNOWN", group="g1", nick="n"):
    return {"nick": nick, "host": host, "group": group, "label": label, "identity": identity}


VERDICTS = {"nicks": {"n": {
    "ultimate": {"a.com": {"category": "FOUND"}, "b.com": {"category": "UNKNOWN"}, "c.com": {"category": "PROBABLE"},
                 "d.com": {"category": "NOT_FOUND"}, "e.com": {"category": "NOT_FOUND"}, "f.com": {"category": "FOUND"}},
    "osint": {"a.com": {"category": "FOUND"}, "b.com": {"category": "FOUND"}, "c.com": {"category": "NOT_FOUND"},
              "d.com": {"category": "FOUND"}, "f.com": {"category": "BLOCKED"}},
}}}

ITEMS = [
    item("a.com", "ACCOUNT_EXISTS", "TARGET"),
    item("b.com", "ACCOUNT_EXISTS", "TARGET"),
    item("c.com", "ACCOUNT_EXISTS", "HOMONYM", group="g2"),
    item("d.com", "ACCOUNT_ABSENT", group="g2"),
    item("e.com", "ACCOUNT_EXISTS", "UNKNOWN", group="g2"),
    item("f.com", "UNVERIFIABLE"),
]


def test_aggregate_prefers_strongest_category():
    rows = [{"key": "x.com", "category": "UNKNOWN", "url": "u1", "raw": ""},
            {"key": "x.com", "category": "PROBABLE", "url": "u2", "raw": ""},
            {"key": "x.com", "category": "NOT_FOUND", "url": "u3", "raw": ""}]
    assert evaluate.aggregate(rows)["x.com"]["category"] == "PROBABLE"


def test_exists_view_metrics():
    res = evaluate.evaluate(VERDICTS, ITEMS)
    u = res["engines"]["ultimate"]["exists"]
    # f.com UNVERIFIABLE wyłączone; pozytywy: a, b, c, e; negatyw: d
    assert (u["n"], u["positives"]) == (5, 4)
    assert (u["tp"], u["fp"], u["fn"], u["tn"]) == (2, 0, 2, 1)
    assert u["precision"] == 1.0 and u["recall"] == 0.5
    assert u["coverage"] == 0.8  # a, c, d, e jawne; b UNKNOWN
    assert u["unknown_among_positives"] == 0.25
    assert u["fn_explicit_not_found"] == ["n:e.com"]
    assert u["fn_abstain"] == ["n:b.com (UNKNOWN)"]
    o = res["engines"]["osint"]["exists"]
    assert (o["tp"], o["fp"], o["fn"], o["tn"]) == (2, 1, 2, 0)
    assert o["fp_hosts"] == ["n:d.com (FOUND)"]
    assert o["fn_abstain"] == ["n:e.com (MISSING)"]
    assert res["engines"]["osint"]["unverifiable_predictions"] == {"BLOCKED": 1}


def test_target_view_counts_homonym_as_negative_and_skips_unknown_identity():
    res = evaluate.evaluate(VERDICTS, ITEMS)
    t = res["engines"]["ultimate"]["target"]
    # oceniane: a (T), b (T), c (HOMONYM -> neg), d (ABSENT -> neg); e (identity UNKNOWN) pominięte
    assert (t["n"], t["positives"]) == (4, 2)
    assert (t["tp"], t["fp"], t["fn"], t["tn"]) == (1, 1, 1, 1)
    assert t["fp_hosts"] == ["n:c.com (PROBABLE)"]


def test_per_group_and_markdown():
    res = evaluate.evaluate(VERDICTS, ITEMS)
    assert res["groups"]["g1"] == {"n": 3, "labels": {"ACCOUNT_EXISTS": 2, "UNVERIFIABLE": 1}, "target": 2}
    assert res["engines"]["ultimate"]["per_group"]["g2"]["tp"] == 1
    md = evaluate.render_md(res, "h.jsonl", "run")
    assert "| exists | ultimate | 5 | 2 | 0 | 2 | 1 |" in md
