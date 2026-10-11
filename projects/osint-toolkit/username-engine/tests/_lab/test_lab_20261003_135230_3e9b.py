from urllib.parse import parse_qs, urlsplit

from username_engine import cli
from username_engine.dorks import cdx_query_url, wayback_targets
from username_engine.models import Response, Site
from username_engine.sources import save_db


def _cdx_target(u: str) -> str:
    return parse_qs(urlsplit(u).query)["url"][0]


def test_cdx_query_url_keeps_query_string():
    u = cdx_query_url("https://q.com/profile.php?user=alice")
    assert _cdx_target(u) == "q.com/profile.php?user=alice"
    qs = parse_qs(urlsplit(u).query)
    assert qs["filter"] == ["statuscode:200"] and qs["output"] == ["json"]


def test_cdx_query_url_keeps_multi_param_query():
    u = cdx_query_url("https://q.com/u?lang=pl&name=alice")
    assert _cdx_target(u) == "q.com/u?lang=pl&name=alice"


def test_cdx_query_url_drops_fragment():
    assert _cdx_target(cdx_query_url("https://a.com/alice#about")) == "a.com/alice"
    assert _cdx_target(cdx_query_url("https://a.com/p?u=alice#top")) == "a.com/p?u=alice"


def test_cdx_query_url_plain_path_unchanged():
    assert _cdx_target(cdx_query_url("https://www.github.com/alice")) == "www.github.com/alice"


def test_wayback_targets_skips_username_only_in_fragment():
    sites = [Site("Hash", "https://h.com/#!/{username}", tags=["social"]),
             Site("Hash2", "https://h2.com/app#/user/{username}", tags=["social"]),
             Site("Path", "https://a.com/{username}", tags=["social"])]
    assert wayback_targets(sites, "alice", {"social"}) == ["https://a.com/alice"]


def test_wayback_targets_skipped_fragment_sites_do_not_use_limit():
    sites = [Site("Hash", "https://h.com/#!/{username}"),
             Site("Path", "https://a.com/{username}")]
    assert wayback_targets(sites, "alice", None, limit=1) == ["https://a.com/alice"]


def test_wayback_targets_keeps_query_subdomain_and_path_with_fragment():
    sites = [Site("Q", "https://q.com/profile.php?user={username}"),
             Site("Sub", "https://{username}.blog.com/"),
             Site("PathFrag", "https://p.com/{username}#posts")]
    assert wayback_targets(sites, "alice", None) == [
        "https://q.com/profile.php?user=alice", "https://alice.blog.com/", "https://p.com/alice#posts"]


def test_cli_wayback_queries_exact_profile_and_skips_fragment_profiles(tmp_path, monkeypatch, capsys):
    db = tmp_path / "sites.json"
    save_db([Site("Qs", "https://q.com/profile.php?user={username}", e_strings=["avatar"], tags=["forum"]),
             Site("Hs", "https://h.com/#!/{username}", e_strings=["avatar"], tags=["forum"])], db)
    archive_targets = []
    snapshot = ('[["timestamp","original","statuscode"],'
                '["20200101000000","http://example/","200"]]')

    class FakeFetcher:
        def __init__(self, *a, **k): pass
        async def __aenter__(self): return self
        async def __aexit__(self, *e): pass
        async def fetch(self, method, url, headers=None, body=None):
            if "web.archive.org" in url:
                target = _cdx_target(url)
                archive_targets.append(target)
                # archiwum ma zrzuty i dokładnego profilu, i ogólnych stron (profile.php, strona główna)
                if target in ("q.com/profile.php?user=alice", "q.com/profile.php") or target.startswith("h.com"):
                    return Response(200, snapshot, final_url=url)
                return Response(200, "[]", final_url=url)
            return Response(200, "nic", final_url=url)

    monkeypatch.setattr(cli, "Fetcher", FakeFetcher)
    monkeypatch.setattr(cli, "WAYBACK_TAGS", {"forum"})
    assert cli.main(["alice", "--db", str(db), "--no-variants", "--include-broken", "--wayback"]) == 0
    out = capsys.readouterr().out
    assert archive_targets == ["q.com/profile.php?user=alice"]
    assert "Archiwum: sprawdzam 1 profili" in out
    assert "[A] https://q.com/profile.php?user=alice" in out
    assert not any(line.startswith("[A]") and "h.com" in line for line in out.splitlines())
