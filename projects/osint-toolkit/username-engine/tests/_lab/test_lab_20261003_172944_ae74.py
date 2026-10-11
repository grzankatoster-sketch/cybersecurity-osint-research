from username_engine.models import Site
from username_engine.sources import merge, site_key


def test_site_key_distinguishes_templates_differing_only_in_query():
    a = Site("ForumA", "https://forum.example.pl/index.php?action=profile;user={username}", source="wmn")
    b = Site("ForumB", "https://forum.example.pl/index.php?page=members&name={username}", source="maigret")
    assert site_key(a) != site_key(b)


def test_merge_keeps_distinct_services_with_username_in_query():
    a = Site("ForumA", "https://forum.example.pl/index.php?action=profile;user={username}",
             tags=["forum"], source="wmn")
    b = Site("ForumB", "https://forum.example.pl/index.php?page=members&name={username}",
             tags=["pl"], source="maigret")
    merged = merge([a], [b])
    urls = sorted(s.url for s in merged)
    assert urls == sorted([a.url, b.url])
    kept_a = [s for s in merged if s.url == a.url][0]
    assert kept_a.tags == ["forum"]  # tagi innego serwisu nie doklejone


def test_merge_still_dedupes_same_query_template_across_scheme_www_slash():
    a = Site("F", "https://www.forum.example.pl/members/?username={username}", tags=["forum"], source="wmn")
    b = Site("F2", "http://forum.example.pl/members?username={username}", tags=["pl"], source="maigret")
    merged = merge([a], [b])
    assert len(merged) == 1
    assert set(merged[0].tags) == {"forum", "pl"}
