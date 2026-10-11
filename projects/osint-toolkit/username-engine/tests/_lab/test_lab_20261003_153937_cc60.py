from username_engine import cli
from username_engine.models import Response, Site
from username_engine.sources import save_db, site_tags


def test_site_tags_infers_pl_from_profile_domain():
    assert "pl" in site_tags(Site("Filmweb", "https://www.filmweb.pl/user/{username}", tags=["hobby"]))
    assert "pl" in site_tags(Site("Firma", "https://forum.firma.com.pl/u/{username}"))
    assert "pl" in site_tags(Site("Blog", "https://{username}.blog.pl/"))
    assert "pl" in site_tags(Site("Port", "https://example.pl:8443/{username}"))


def test_site_tags_keeps_existing_tags_and_order():
    s = Site("Filmweb", "https://www.filmweb.pl/user/{username}", tags=["hobby", "movies"])
    assert site_tags(s)[:2] == ["hobby", "movies"]


def test_site_tags_no_duplicate_and_case_insensitive():
    s = Site("Wykop", "https://wykop.pl/ludzie/{username}", tags=["social", "PL"])
    assert [t.lower() for t in site_tags(s)].count("pl") == 1


def test_site_tags_does_not_mutate_site():
    s = Site("Filmweb", "https://www.filmweb.pl/user/{username}", tags=["hobby"])
    site_tags(s)
    assert s.tags == ["hobby"]


def test_site_tags_ignores_non_pl_hosts():
    for url in ("https://pl.example.com/{username}", "https://example.plus/{username}",
                "https://example.com/pl/{username}", "https://example.com/{username}?lang=pl"):
        assert "pl" not in [t.lower() for t in site_tags(Site("X", url, tags=["social"]))], url


def test_select_sites_pl_includes_untagged_pl_domain():
    sites = [Site("Filmweb", "https://www.filmweb.pl/user/{username}", tags=["hobby"]),
             Site("Gh", "https://github.com/{username}", tags=["coding"]),
             Site("Wykop", "https://wykop.pl/ludzie/{username}", tags=["social", "pl"]),
             Site("Tagged", "https://example.com/{username}", tags=["pl"])]
    assert [s.name for s in cli.select_sites(sites, "pl", None)] == ["Filmweb", "Wykop", "Tagged"]
    assert [s.name for s in cli.select_sites(sites, "pl", 1)] == ["Filmweb"]


def test_select_sites_other_tags_unchanged():
    sites = [Site("Filmweb", "https://www.filmweb.pl/user/{username}", tags=["hobby"]),
             Site("Gh", "https://github.com/{username}", tags=["coding"])]
    assert [s.name for s in cli.select_sites(sites, "coding", None)] == ["Gh"]
    assert [s.name for s in cli.select_sites(sites, None, None)] == ["Filmweb", "Gh"]


def test_cli_tags_pl_scans_untagged_pl_site(tmp_path, monkeypatch, capsys):
    db = tmp_path / "sites.json"
    save_db([Site("Filmweb", "https://www.filmweb.pl/user/{username}", e_strings=["avatar"], tags=["hobby"]),
             Site("Gh", "https://gh.com/{username}", e_strings=["avatar"], tags=["coding"])], db)
    asked = []

    class FakeFetcher:
        def __init__(self, *a, **k): pass
        async def __aenter__(self): return self
        async def __aexit__(self, *e): pass
        async def fetch(self, method, url, headers=None, body=None):
            asked.append(url)
            return Response(200, "avatar" if url.endswith("/alice") else "nic", final_url=url)

    monkeypatch.setattr(cli, "Fetcher", FakeFetcher)
    assert cli.main(["alice", "--db", str(db), "--tags", "pl", "--no-variants"]) == 0
    out = capsys.readouterr().out
    assert "sprawdzam 1 serwisów" in out
    assert "[+]" in out and "filmweb.pl/user/alice" in out
    assert not any("gh.com" in u for u in asked)
