import asyncio
import json

from username_engine import cli
from username_engine.health import (BLOCKED, DEAD, FALSE_POSITIVE, OK, STALE, UNSTABLE, check_health,
                                    filter_healthy, judge, load_health, save_health)
from username_engine.http import DNS_ERROR, Fetcher
from username_engine.models import Response, Result, Site, Status
from username_engine.sources import save_db


def R(status, conf=0.0, reason=""):
    return Result("S", "u", status, conf, reason)


def test_judge_states():
    assert judge(R(Status.ERROR, reason=DNS_ERROR), None)[0] == DEAD
    assert judge(R(Status.ERROR, reason="blokada anty-bot (x)"), None)[0] == BLOCKED
    assert judge(R(Status.ERROR, reason="dostęp zabroniony (403)"), None)[0] == BLOCKED
    assert judge(R(Status.ERROR, reason="timeout"), None)[0] == UNSTABLE
    assert judge(R(Status.FOUND, 0.9, "tekst"), None)[0] == FALSE_POSITIVE
    assert judge(R(Status.FOUND, 0.45, "tylko kod"), None)[0] == OK          # słabe trafienia i tak ukryte
    assert judge(R(Status.NOT_FOUND), R(Status.NOT_FOUND, reason="kod 404"))[0] == STALE
    assert judge(R(Status.NOT_FOUND), R(Status.FOUND, 0.9))[0] == OK
    # losowa nazwa -> logowanie, ale znane konto wykrywane: serwis sprawny, nie pomijać
    assert judge(R(Status.ERROR, reason="wymaga logowania (x)"), R(Status.FOUND, 0.9))[0] == OK
    assert judge(R(Status.ERROR, reason="wymaga logowania (x)"), R(Status.ERROR, reason="x"))[0] == BLOCKED


class Fake:
    async def fetch(self, method, url, headers=None, body=None):
        if "dead.com" in url:
            return Response(None, error=DNS_ERROR)
        if "fp.com" in url:
            return Response(200, "avatar", final_url=url)                # pasuje do każdej nazwy
        if "ok.com" in url:
            return Response(200, "avatar", final_url=url) if url.endswith("/blue") else Response(404, "", final_url=url)
        return Response(403, "<title>Just a moment...</title>", final_url=url)


def test_check_health_end_to_end(tmp_path):
    sites = [Site("Dead", "https://dead.com/{username}", e_strings=["avatar"]),
             Site("Fp", "https://fp.com/{username}", e_strings=["avatar"]),
             Site("Ok", "https://ok.com/{username}", e_strings=["avatar"], known=["blue"]),
             Site("Cf", "https://cf.com/{username}", e_strings=["avatar"])]
    health = asyncio.run(check_health(sites, Fake()))
    assert {k: v["state"] for k, v in health.items()} == {"Dead": DEAD, "Fp": FALSE_POSITIVE, "Ok": OK, "Cf": BLOCKED}
    p = tmp_path / "health.json"
    save_health(health, p)
    assert load_health(p)["Fp"]["state"] == FALSE_POSITIVE
    kept, skipped = filter_healthy(sites, load_health(p))
    assert [s.name for s in kept] == ["Ok"] and sum(skipped.values()) == 3


def test_load_health_missing_file_is_empty(tmp_path):
    assert load_health(tmp_path / "nope.json") == {}


def test_dns_error_not_retried():
    calls = {"n": 0}

    async def go():
        f = Fetcher(retries=3, jitter=False)

        async def once(*a, **k):
            calls["n"] += 1
            return Response(None, error=DNS_ERROR)
        f._once = once
        return await f.fetch("GET", "http://x.invalid/")

    r = asyncio.run(go())
    assert r.error == DNS_ERROR and calls["n"] == 1


def test_cli_skips_broken_sites(tmp_path, monkeypatch, capsys):
    db = tmp_path / "sites.json"
    save_db([Site("Good", "https://good.com/{username}", e_strings=["avatar"]),
             Site("Bad", "https://bad.com/{username}", e_strings=["avatar"])], db)
    (tmp_path / "health.json").write_text(json.dumps({"sites": {"Bad": {"state": "dead", "reason": ""}}}),
                                          encoding="utf-8")
    seen = []

    class F:
        def __init__(self, *a, **k): pass
        async def __aenter__(self): return self
        async def __aexit__(self, *e): pass
        async def fetch(self, method, url, headers=None, body=None):
            seen.append(url)
            return Response(200, "avatar", final_url=url)

    monkeypatch.setattr(cli, "Fetcher", F)
    assert cli.main(["alice", "--db", str(db)]) == 0
    assert "Pominięto 1" in capsys.readouterr().out and all("bad.com" not in u for u in seen)
    seen.clear()
    assert cli.main(["alice", "--db", str(db), "--include-broken"]) == 0
    assert any("bad.com" in u for u in seen)
