"""Test run_pairs.py (pomiar Ultimate dla nicków spoza verdicts.json) i scalania verdicts_extra w evaluate.py.

Bez sieci: CLI Ultimate jest podmieniane atrapą, która zapisuje sztuczny results.json.
"""
import json
import sys
from pathlib import Path

BENCH = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(BENCH))

import evaluate  # noqa: E402
import run_pairs  # noqa: E402

CATALOG = [
    {"id": "s:a1", "profile_url": "https://www.a.com/u/{username}"},
    {"id": "s:a2", "profile_url": "https://a.com/profile?name={username}"},
    {"id": "s:b1", "profile_url": "https://{username}.b.com/"},
    {"id": "s:c1", "profile_url": "https://c.com/{username}"},
]


def result(site, url, verdict="FOUND", state="OK"):
    return {"site_id": site, "profile_url": url, "canonical_service": None,
            "detection": {"verdict": verdict, "state": state, "evidence": []}, "attempts": [{"n": 1}]}


def setup(tmp_path):
    run = tmp_path / "run"
    run.mkdir()
    base = {"nicks": {"known": {"ultimate": {"a.com": {"category": "NOT_FOUND", "raw": "x", "url": "u"}}, "osint": {}}}}
    (run / "verdicts.json").write_text(json.dumps(base), "utf-8")
    catalog = tmp_path / "catalog.json"
    catalog.write_text(json.dumps(CATALOG), "utf-8")
    pairs = tmp_path / "pairs.jsonl"
    rows = [{"nick": "known", "host": "a.com", "candidate_urls": []},
            {"nick": "newnick", "host": "a.com", "candidate_urls": ["https://a.com/u/newnick"]},
            {"nick": "newnick", "host": "newnick.b.com", "candidate_urls": []},
            {"nick": "newnick", "host": "nope.org", "candidate_urls": []}]
    pairs.write_text("".join(json.dumps(r) + "\n" for r in rows), "utf-8")
    return run, catalog, pairs


def fake_cli(calls):
    def run_cli(nick, site_ids, out_dir):
        calls.append((nick, tuple(site_ids)))
        out_dir.mkdir(parents=True, exist_ok=True)
        rows = []
        for sid in site_ids:
            tpl = next(c["profile_url"] for c in CATALOG if c["id"] == sid)
            rows.append(result(sid, tpl.replace("{username}", nick), "FOUND" if sid == "s:a1" else "NOT_FOUND"))
        (out_dir / "results.json").write_text(json.dumps(rows), "utf-8")
        return 1  # kod 1 = część serwisów z błędem, normalne

    return run_cli


def test_hostkey_matching_and_site_ids():
    cat = {s["id"]: s for s in CATALOG}
    assert run_pairs.site_ids_for(cat, "a.com", "newnick") == ["s:a1", "s:a2"]
    assert run_pairs.site_ids_for(cat, "newnick.b.com", "newnick") == ["s:b1"]
    assert run_pairs.site_ids_for(cat, "b.com", "newnick") == []
    assert run_pairs.site_ids_for(cat, "nope.org", "newnick") == []


def test_cli_argv_like_compare():
    argv = run_pairs.cli_argv("n", ["s:1", "s:2"], Path("out"))
    assert argv[:2] == ["search", "n"]
    assert argv[argv.index("--mode") + 1] == "exhaustive"
    assert argv[argv.index("--enrich") + 1] == "basic"
    assert [argv[i + 1] for i, x in enumerate(argv) if x == "--site"] == ["s:1", "s:2"]
    assert "--output" in argv and "--journal" in argv


def test_runs_only_missing_nicks_and_writes_extra(tmp_path, monkeypatch):
    run, catalog, pairs = setup(tmp_path)
    calls = []
    monkeypatch.setattr(run_pairs, "run_cli", fake_cli(calls))
    assert run_pairs.main(["--pairs", str(pairs), "--run", str(run), "--catalog", str(catalog)]) == 0
    assert calls == [("newnick", ("s:a1", "s:a2", "s:b1"))]  # known pominięty; nope.org bez definicji
    extra = json.loads((run / "verdicts_extra.json").read_text("utf-8"))
    u = extra["nicks"]["newnick"]["ultimate"]
    assert set(u) == {"a.com", "newnick.b.com"}
    assert u["a.com"]["category"] == "FOUND"  # FOUND > NOT_FOUND (jak aggregate w evaluate)
    assert u["a.com"]["url"].startswith("https://") and "raw" in u["a.com"]
    assert u["newnick.b.com"]["category"] == "NOT_FOUND"
    assert "known" not in extra["nicks"]
    assert (run / "raw_extra" / "newnick" / "results.json").exists()
    # verdicts.json nietknięty
    assert "newnick" not in json.loads((run / "verdicts.json").read_text("utf-8"))["nicks"]


def test_rerun_is_idempotent_and_merges(tmp_path, monkeypatch):
    run, catalog, pairs = setup(tmp_path)
    calls = []
    monkeypatch.setattr(run_pairs, "run_cli", fake_cli(calls))
    argv = ["--pairs", str(pairs), "--run", str(run), "--catalog", str(catalog)]
    run_pairs.main(argv)
    first = (run / "verdicts_extra.json").read_bytes()
    run_pairs.main(argv)
    assert len(calls) == 1  # nic nowego do zmierzenia
    assert (run / "verdicts_extra.json").read_bytes() == first
    # nowa para dla tego samego nicka na innym hoście: dopisana, stare wpisy zostają
    CATALOG_C = {"nick": "newnick", "host": "c.com", "candidate_urls": []}
    with pairs.open("a", encoding="utf-8") as f:
        f.write(json.dumps(CATALOG_C) + "\n")
    run_pairs.main(argv)
    assert calls[-1] == ("newnick", ("s:c1",))
    u = json.loads((run / "verdicts_extra.json").read_text("utf-8"))["nicks"]["newnick"]["ultimate"]
    assert set(u) == {"a.com", "newnick.b.com", "c.com"}


def test_evaluate_merges_extra_only_missing(tmp_path):
    run = tmp_path / "run"
    run.mkdir()
    base = {"nicks": {"known": {"ultimate": {"a.com": {"category": "NOT_FOUND"}}, "osint": {}}}}
    extra = {"nicks": {"known": {"ultimate": {"a.com": {"category": "FOUND"}, "z.com": {"category": "FOUND"}}},
                       "new": {"ultimate": {"a.com": {"category": "FOUND"}}}}}
    (run / "verdicts.json").write_text(json.dumps(base), "utf-8")
    (run / "verdicts_extra.json").write_text(json.dumps(extra), "utf-8")
    v = evaluate.load_verdicts(run)
    assert evaluate.prediction(v, "ultimate", "known", "a.com") == "NOT_FOUND"  # nie nadpisuje
    assert evaluate.prediction(v, "ultimate", "known", "z.com") == "FOUND"
    assert evaluate.prediction(v, "ultimate", "new", "a.com") == "FOUND"
    assert evaluate.prediction(v, "osint", "new", "a.com") == "MISSING"
    # plik verdicts.json na dysku nie jest zanieczyszczony
    assert "new" not in json.loads((run / "verdicts.json").read_text("utf-8"))["nicks"]


def test_evaluate_accepts_any_label_file_name(tmp_path):
    run = tmp_path / "run"
    run.mkdir()
    (run / "verdicts.json").write_text(json.dumps({"nicks": {"n": {"ultimate": {"a.com": {"category": "FOUND"}}, "osint": {}}}}), "utf-8")
    labels = tmp_path / "dev_v1.jsonl"
    labels.write_text(json.dumps({"id": "d1-001", "nick": "n", "host": "a.com", "group": "g",
                                  "label": "ACCOUNT_EXISTS", "identity": "TARGET"}) + "\n", "utf-8")
    assert evaluate.main(["--run", str(run), "--holdout", str(labels)]) == 0
    res = json.loads((run / "evaluation_dev_v1.json").read_text("utf-8"))
    assert res["engines"]["ultimate"]["exists"]["tp"] == 1
