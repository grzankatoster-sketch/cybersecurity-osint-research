import asyncio
import json

from username_engine import cli
from username_engine.classify import classify, matched_evidence
from username_engine.engine import check_site
from username_engine.models import Response, Result, Site, Status
from username_engine.sources import save_db


class FakeFetcher:
    def __init__(self, handler):
        self.handler = handler
        self.calls = []

    async def fetch(self, method, url, headers=None, body=None):
        self.calls.append(url)
        return self.handler(url)


def run(coro):
    return asyncio.run(coro)


SITE = Site("Multi", "https://multi.example/{username}",
            e_strings=["profile-card", "", "followers", "user-bio"], m_strings=["no such user"])
PAGE = "<div class=profile-card>alice</div><span>12 followers</span>"


def _handler(url):
    return Response(200, PAGE if url.endswith("/alice") else "no such user", final_url=url)


def test_matched_evidence_returns_exactly_matched_strings_in_rule_order():
    resp = Response(200, PAGE, final_url="https://multi.example/alice")
    assert matched_evidence(SITE, resp) == ["profile-card", "followers"]


def test_matched_evidence_skips_empty_dedups_and_handles_no_response():
    s = Site("D", "https://d.example/{username}", e_strings=["a1", "a1", "", "zz"])
    assert matched_evidence(s, Response(200, "xx a1 yy")) == ["a1"]
    assert matched_evidence(s, Response(None, error="timeout")) == []
    assert matched_evidence(Site("W", "https://w/{username}"), Response(200, "anything")) == []


def test_check_site_found_has_all_evidence_and_unchanged_decision():
    f = FakeFetcher(_handler)
    r = run(check_site(SITE, "alice", f))
    assert r.status is Status.FOUND
    assert r.evidence == ["profile-card", "followers"]
    # pewność i uzasadnienie dokładnie takie jak z classify (z tą samą kontrolą)
    resp = _handler("https://multi.example/alice")
    ctrl = _handler("https://multi.example/zzzzcontrol")
    status, conf, reason = classify(SITE, resp, "alice", ctrl, "zzzzcontrol")
    assert (r.status, r.confidence, r.reason) == (status, conf, reason)


def test_evidence_empty_for_not_found_and_unreliable_rule():
    f = FakeFetcher(_handler)
    nf = run(check_site(SITE, "bob", f))
    assert nf.status is Status.NOT_FOUND and nf.evidence == []
    # reguła pasuje też do losowej nazwy -> ERROR, bez dowodów
    every = FakeFetcher(lambda url: Response(200, "<div class=profile-card>x</div>", final_url=url))
    err = run(check_site(SITE, "alice", every))
    assert err.status is Status.ERROR and err.evidence == []


def test_weak_rule_found_has_no_evidence_and_to_dict_omits_key():
    weak = Site("Weak", "https://weak.example/{username}", check_type="status_code")
    f = FakeFetcher(lambda url: Response(200, "ok", final_url=url))
    r = run(check_site(weak, "alice", f, control="none"))
    assert r.status is Status.FOUND and r.evidence == []
    assert "evidence" not in r.to_dict()


def test_result_to_dict_includes_evidence_when_present():
    r = Result("S", "https://s/a", Status.FOUND, 0.97, "tekst", 200, {}, ["a", "b"])
    assert r.to_dict()["evidence"] == ["a", "b"]
    assert Result("S", "https://s/a", Status.FOUND, 0.9, "t").evidence == []


def test_cli_json_output_contains_evidence(tmp_path, monkeypatch):
    db = tmp_path / "sites.json"
    save_db([SITE], db)

    class CliFetcher:
        def __init__(self, *a, **k): pass
        async def __aenter__(self): return self
        async def __aexit__(self, *e): pass
        async def fetch(self, method, url, headers=None, body=None):
            return _handler(url)

    monkeypatch.setattr(cli, "Fetcher", CliFetcher)
    out_dir = tmp_path / "wyniki"
    assert cli.main(["alice", "--db", str(db), "--no-variants", "--results-dir", str(out_dir), "--json", "w.json"]) == 0
    (out,) = out_dir.glob("*/w.json")
    data = json.loads(out.read_text(encoding="utf-8"))
    (row,) = data["results"]["alice"]
    assert row["status"] == "FOUND" and row["evidence"] == ["profile-card", "followers"]
