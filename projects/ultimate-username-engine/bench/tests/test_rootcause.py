"""Test ewaluacji drzewa reguł w rootcause_unknown.py (dane sztuczne)."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import rootcause_unknown as rc  # noqa: E402


def leaf(strategy="message"):
    return {"strategy": strategy, "children": []}


def node(kind, *kids):
    return {"strategy": kind, "children": list(kids)}


def ev(**states):
    return [{"rule_id": k.replace("_", "."), "state": v} for k, v in states.items()]


def test_all_node_needs_every_leaf():
    det = {"present": leaf(), "absent": node("all", leaf("status"), leaf())}
    # absent.0 (status 200) TRUE, absent.1 (komunikat) FALSE -> absent nie zadziałał
    assert rc.rule_outcome(ev(present="TRUE", absent_0="TRUE", absent_1="FALSE"), det).startswith("reguła mówi FOUND")
    assert rc.rule_outcome(ev(present="TRUE", absent_0="TRUE", absent_1="TRUE"), det).startswith("sprzeczne")


def test_any_node_and_missing_present():
    det = {"present": node("any", leaf(), leaf()), "absent": leaf()}
    assert rc.rule_outcome(ev(present_0="FALSE", present_1="FALSE", absent="FALSE"), det) == "present nie trafia"
    assert rc.rule_outcome(ev(present_0="FALSE", present_1="TRUE", absent="FALSE"), det).startswith("reguła mówi FOUND")
    assert rc.rule_outcome(ev(absent="FALSE"), {"present": None, "absent": leaf()}) == "brak oceny present"


def test_rule_type():
    assert rc.rule_type({"present": leaf("status"), "absent": leaf("status")}) == "status-only"
    assert rc.rule_type({"present": None, "absent": leaf()}) == "brak reguły present (absent: message)"
    assert rc.rule_type({"present": leaf(), "absent": node("all", leaf("status"), leaf())}) == "message (present i absent)"
