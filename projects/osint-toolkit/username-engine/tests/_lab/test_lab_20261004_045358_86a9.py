from username_engine.dorks import wayback_targets
from username_engine.models import Site
from username_engine.sources import site_tags


def test_wayback_targets_pl_tag_includes_pl_domains_like_tags_filter():
    sites = [
        Site("Filmweb", "https://www.filmweb.pl/user/{username}", tags=["hobby"]),
        Site("Firma", "https://forum.firma.com.pl/u/{username}"),
        Site("Other", "https://other.com/{username}", tags=["hobby"]),
    ]
    # spójność z filtrem --tags: te serwisy mają tag 'pl' wywiedziony z domeny
    assert "pl" in site_tags(sites[0]) and "pl" in site_tags(sites[1])
    got = wayback_targets(sites, "alice", {"pl"})
    assert got == ["https://www.filmweb.pl/user/alice", "https://forum.firma.com.pl/u/alice"]


def test_wayback_targets_pl_domain_counts_with_mixed_tag_set():
    sites = [Site("Wykop", "https://wykop.pl/ludzie/{username}", tags=["news"])]
    assert wayback_targets(sites, "bob", {"social", "pl"}) == ["https://wykop.pl/ludzie/bob"]


def test_wayback_targets_non_pl_without_matching_tag_still_skipped():
    sites = [Site("Other", "https://example.com/{username}", tags=["hobby"])]
    assert wayback_targets(sites, "bob", {"pl"}) == []
