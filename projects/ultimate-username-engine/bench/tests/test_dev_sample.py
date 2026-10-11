"""Test make_dev_sample.py na danych sztucznych (bez sieci, bez prawdziwych raw/)."""
import json
import sys
from pathlib import Path

BENCH = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(BENCH), str(BENCH / "ground_truth")]

import make_dev_sample as mds  # noqa: E402

NICKS = ("A", "B", "C")
STATUS = "status-only"
MSG = "message (present i absent)"


def entry(cat, host, nick):
    return {"category": cat, "raw": "", "url": f"https://{host}/u/{nick}"}


def synthetic():
    """verdicts + rule_info z kontrolowanymi pulami grup."""
    nicks = {n: {"ultimate": {}, "osint": {}} for n in NICKS}
    rules = {n: {} for n in NICKS}

    def put(host, nick, cu, co, rule=None, rtype=STATUS):
        if cu is not None:
            nicks[nick]["ultimate"][host] = entry(cu, host, nick)
        if co is not None:
            nicks[nick]["osint"][host] = entry(co, host, nick)
        rules[nick][host] = (rule, rtype if rule else None)

    for i in range(80):  # only_osint: pule nicków 80/40/20
        for n, size in zip(NICKS, (80, 40, 20)):
            if i < size:
                put(f"oo{i}.com", n, "NOT_FOUND", "FOUND", "NOT_PRESENT")
    for i in range(10):  # only_ultimate: te same hosty dla wszystkich nicków (ma zostać 10 hostów)
        for n in NICKS:
            put(f"uo{i}.com", n, "FOUND", "NOT_FOUND", "FOUND")
    for i in range(30):
        for n in NICKS:
            put(f"bh{i}.com", n, "PROBABLE", "FOUND", "FOUND")
    for i in range(15):  # reguła FOUND dla wszystkich nicków, Ultimate UNKNOWN
        for n in NICKS:
            put(f"ra{i}.com", n, "UNKNOWN", "NOT_FOUND", "FOUND")
    for i in range(60):  # reguła FOUND tylko dla A; 30 status-only, 30 inne
        put(f"rf{i}.com", "A", "UNKNOWN", "NOT_FOUND", "FOUND", STATUS if i < 30 else MSG)
        put(f"rf{i}.com", "B", "UNKNOWN", "NOT_FOUND", "NOT_PRESENT")
    for i in range(40):
        for n in NICKS:
            put(f"un{i}.com", n, "UNKNOWN", "NOT_FOUND", "NOT_PRESENT")
    for i in range(40):
        for n in NICKS:
            put(f"bn{i}.com", n, "NOT_FOUND", "NOT_FOUND", "NOT_PRESENT")
    # wykluczone: host dokładny, subdomena wykluczonego, host pusty
    for n in NICKS:
        put("bad.com", n, "NOT_FOUND", "FOUND", "NOT_PRESENT")
        put("x.bad.com", n, "FOUND", "NOT_FOUND", "FOUND")
        put("", n, "FOUND", "FOUND", "FOUND")
        put("notbad.com", n, "NOT_FOUND", "FOUND", "NOT_PRESENT")  # tylko sufiks tekstowy, nie subdomena
    return {"nicks": nicks}, rules


def build(seed=mds.SEED):
    verdicts, rules = synthetic()
    return mds.build_sample(verdicts, rules, {"bad.com"}, seed=seed)


def test_excluded_empty_and_suffix_hosts():
    assert mds.is_excluded("bad.com", {"bad.com"})
    assert mds.is_excluded("x.bad.com", {"bad.com"})
    assert not mds.is_excluded("notbad.com", {"bad.com"})
    assert mds.is_excluded("", set())


def test_deterministic_and_seed_sensitive():
    a, b = build(), build()
    assert a == b
    assert json.dumps(a[1]) == json.dumps(b[1])
    assert build(seed=1)[1] != a[1]


def test_exclusions_applied():
    private, to_label, meta = build()
    hosts = [x["host"] for x in to_label]
    assert "" not in hosts
    assert not any(h == "bad.com" or h.endswith(".bad.com") for h in hosts)
    assert meta["groups"]["only_ultimate"]["pool_by_nick"] == {n: 10 for n in NICKS}


def test_to_label_is_blind():
    private, to_label, meta = build()
    assert [set(x) for x in to_label] == [{"id", "nick", "host", "candidate_urls"}] * len(to_label)
    assert [x["id"] for x in to_label] == [f"d1-{i:03d}" for i in range(1, len(to_label) + 1)]
    text = json.dumps(to_label)
    for banned in ("group", "FOUND", "NOT_FOUND", "UNKNOWN", "rule_says", "only_osint"):
        assert banned not in text
    # kolejność przetasowana: grupy nie idą blokami w kolejności definicji
    groups = [private[x["id"]]["group"] for x in to_label]
    order = list(mds.GROUPS)
    assert groups != sorted(groups, key=order.index)
    assert [x["candidate_urls"] for x in to_label][0]


def test_hosts_unique():
    _, to_label, _ = build()
    hosts = [x["host"] for x in to_label]
    assert len(hosts) == len(set(hosts))


def test_group_sizes():
    private, to_label, meta = build()
    counts = {g: sum(1 for p in private.values() if p["group"] == g) for g in mds.GROUPS}
    assert counts["only_osint"] == 45
    assert counts["only_ultimate"] == 10  # jeden wiersz na host
    assert counts["both_hit"] == 15
    assert counts["rulefound_all_nicks"] == 10
    assert counts["ult_unknown_rulefound_osint_notfound"] == 25
    assert counts["ult_unknown_osint_notfound"] == 20
    assert counts["both_notfound"] == 10
    assert meta["total"] == len(to_label) == sum(counts.values())
    assert meta["groups"]["only_osint"]["sampled_by_nick"] == {"A": 25, "B": 13, "C": 7} or \
        sum(meta["groups"]["only_osint"]["sampled_by_nick"].values()) == 45


def test_only_osint_proportional():
    private, to_label, meta = build()
    by_nick = meta["groups"]["only_osint"]["sampled_by_nick"]
    assert sum(by_nick.values()) == 45
    assert by_nick["A"] > by_nick["B"] > by_nick["C"]  # 80/40/20


def test_rulefound_all_nicks_group():
    private, to_label, meta = build()
    items = {x["id"]: x for x in to_label}
    rows = [(items[i], p) for i, p in private.items() if p["group"] == "rulefound_all_nicks"]
    assert len(rows) == 10
    for it, p in rows:
        assert it["host"].startswith("ra")
        assert p["rule_says"] == "FOUND"


def test_group5_stratified_and_rule_fields():
    private, to_label, meta = build()
    items = {x["id"]: x for x in to_label}
    g5 = [(items[i], p) for i, p in private.items() if p["group"] == "ult_unknown_rulefound_osint_notfound"]
    assert all(p["rule_says"] == "FOUND" and it["nick"] == "A" and it["host"].startswith("rf") for it, p in g5)
    assert sum(1 for _, p in g5 if p["rule_type"] == STATUS) == 12
    assert sum(1 for _, p in g5 if p["rule_type"] != STATUS) == 13
    # grupa 6 nie zawiera par z regułą FOUND
    g6 = [p for p in private.values() if p["group"] == "ult_unknown_osint_notfound"]
    assert all(p["rule_says"] != "FOUND" for p in g6)


def test_group5_fills_when_other_types_scarce():
    verdicts, rules = synthetic()
    for i in range(30, 60):  # wszystkie rf -> status-only; "inne" znikają
        rules["A"][f"rf{i}.com"] = ("FOUND", STATUS)
    _, to_label, meta = mds.build_sample(verdicts, rules, {"bad.com"})
    assert meta["groups"]["ult_unknown_rulefound_osint_notfound"]["sampled"] == 25


def test_meta_has_pools_and_counts():
    private, to_label, meta = build()
    assert meta["seed"] == mds.SEED
    assert set(meta["groups"]) == set(mds.GROUPS)
    g = meta["groups"]["both_hit"]
    assert g["limit"] == 15 and g["sampled"] == 15 and g["pool_pairs"] == 90
    assert meta["groups"]["rulefound_all_nicks"]["pool_hosts"] == 15
    # meta zawiera id -> grupa / rule_says / rule_type
    assert {i["id"] for i in meta["items"]} == {x["id"] for x in to_label}
    assert all({"id", "group", "rule_says", "rule_type"} <= set(i) for i in meta["items"])


# ---------------------------------------------------------------- host_rule_info


def leaf(strategy="message"):
    return {"strategy": strategy, "children": []}


def res(site, url, states, state="OK", verdict="UNKNOWN"):
    ev = [{"rule_id": k, "state": v} for k, v in states.items()]
    return {"site_id": site, "profile_url": url, "detection": {"verdict": verdict, "state": state, "evidence": ev}}


def test_host_rule_info():
    catalog = {
        "s1": {"detection": {"present": leaf("status"), "absent": leaf("status")}},
        "s2": {"detection": {"present": leaf(), "absent": leaf()}},
        "s3": {"detection": {"present": None, "absent": leaf()}},
        "s4": {"detection": {"present": leaf(), "absent": None}},
        "s5": {"detection": {"present": leaf(), "absent": leaf()}},
    }
    results = [
        res("s1", "https://www.a.com/u/n", {"present": "TRUE", "absent": "FALSE"}),
        res("s2", "https://b.com/u/n", {"present": "FALSE", "absent": "FALSE"}),
        res("s3", "https://c.com/u/n", {"absent": "FALSE"}),
        res("s4", "https://d.com/u/n", {"present": "TRUE"}),
        res("s2", "https://e.com/u/n", {"present": "TRUE", "absent": "TRUE"}),
        res("s5", "https://f.com/u/n", {}, state="BLOCKED"),
        res("nie-ma", "https://g.com/u/n", {"present": "TRUE"}),
        # druga definicja na hoście a.com: FOUND wygrywa z NOT_PRESENT
        res("s2", "https://a.com/x/n", {"present": "FALSE", "absent": "FALSE"}),
    ]
    info = mds.host_rule_info(results, catalog)
    assert info["a.com"] == ("FOUND", "status-only")
    assert info["b.com"] == ("NOT_PRESENT", "message (present i absent)")
    assert info["c.com"][0] == "NO_PRESENT_RULE"
    assert info["d.com"] == ("FOUND", "present message, brak absent")
    assert info["e.com"][0] == "ABSENT_FIRED"
    assert info["f.com"][0] is None
    assert "g.com" not in info or info["g.com"][0] is None


def test_main_end_to_end(tmp_path):
    run = tmp_path / "run"
    for nick in ("n1", "n2", "n3"):
        d = run / "raw" / nick / "ultimate"
        d.mkdir(parents=True)
        rows = [res("s1", f"https://h{i}.com/{nick}", {"present": "TRUE", "absent": "FALSE"}) for i in range(8)]
        (d / "results.json").write_text(json.dumps(rows), "utf-8")
    verdicts = {"nicks": {n: {"ultimate": {f"h{i}.com": entry("UNKNOWN", f"h{i}.com", n) for i in range(8)},
                              "osint": {f"h{i}.com": entry("NOT_FOUND", f"h{i}.com", n) for i in range(8)}}
                          for n in ("n1", "n2", "n3")}}
    (run / "verdicts.json").write_text(json.dumps(verdicts), "utf-8")
    catalog = tmp_path / "catalog.json"
    catalog.write_text(json.dumps([{"id": "s1", "detection": {"present": leaf("status"), "absent": leaf("status")}}]), "utf-8")
    excl = tmp_path / "excl.json"
    excl.write_text(json.dumps({"holdout_hosts": ["h0.com"], "tuned_hosts": []}), "utf-8")
    out1, out2 = tmp_path / "o1", tmp_path / "o2"
    for out in (out1, out2):
        mds.main(["--run", str(run), "--catalog", str(catalog), "--excluded", str(excl), "--out", str(out)])
    assert (out1 / "to_label_dev_v1.jsonl").read_bytes() == (out2 / "to_label_dev_v1.jsonl").read_bytes()
    assert (out1 / "dev_sample_v1.json").read_bytes() == (out2 / "dev_sample_v1.json").read_bytes()
    lines = [json.loads(x) for x in (out1 / "to_label_dev_v1.jsonl").read_text("utf-8").splitlines()]
    assert lines and all(x["host"] != "h0.com" for x in lines)
    meta = json.loads((out1 / "dev_sample_v1.json").read_text("utf-8"))
    assert meta["groups"]["rulefound_all_nicks"]["pool_hosts"] == 7
