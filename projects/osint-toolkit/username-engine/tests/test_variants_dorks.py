from urllib.parse import parse_qs, urlsplit

import pytest

from username_engine.dorks import (build_queries, cdx_query_url, parse_cdx, search_links, wayback_targets)
from username_engine.models import Site
from username_engine.variants import ascii_fold, generate


def test_ascii_fold_polish():
    assert ascii_fold("Łukasz Żółć") == "lukasz zolc"


def test_person_variants_order_and_content():
    v = generate("Jan Kowalski", limit=50)
    assert v[0] == "jankowalski"
    for expected in ("jan.kowalski", "jan_kowalski", "kowalski.jan", "jkowalski", "j.kowalski", "kowalskij"):
        assert expected in v
    assert len(v) == len(set(v))


def test_single_name_variants_and_years_and_leet():
    v = generate("Alice", years=[1990, 90], leet=True, limit=50)
    assert v[0] == "alice"
    assert {"alice1990", "alice_90", "4l1c3", "alice_"} <= set(v)


def test_name_with_number_gets_separator_variants():
    v = generate("Sampler51", limit=9)
    assert v[:4] == ["sampler51", "sampler.51", "sampler_51", "sampler-51"]
    assert "sampler" in v and "51sampler" in v
    assert not any(x.startswith("g.") or x == "51.g" for x in v)      # liczba nie jest „nazwiskiem”


def test_camel_case_split_and_typed_form_first():
    assert generate("JanKowalski", limit=3) == ["jankowalski", "jan.kowalski", "jan_kowalski"]
    assert generate("jan.kowalski90", limit=2)[0] == "jan.kowalski90"


def test_limit_is_hard():
    assert len(generate("Jan Maria Kowalski", years=[1, 2, 3], leet=True, limit=5)) == 5
    assert generate("jan", limit=0) == []


def test_invalid_chars_dropped():
    assert generate("!!!") == []
    assert all(c.isalnum() or c in "._-" for n in generate("ann@ smith") for c in n)


def test_queries_contain_phrase_and_site_groups():
    q = build_queries(["jkowalski", "jan.kowalski"])
    assert q[0] == '("jkowalski" OR "jan.kowalski")'
    assert any("site:wykop.pl" in x for x in q)
    assert all(x.count("site:") <= 10 for x in q)


def test_search_links_encode_query():
    links = search_links(['"a b"'], engines=("google",))
    assert links[0]["url"] == "https://www.google.com/search?q=%22a+b%22"


def test_cdx_query_url_params():
    u = cdx_query_url("https://www.github.com/alice")
    qs = parse_qs(urlsplit(u).query)
    assert qs["url"] == ["www.github.com/alice"]
    assert qs["filter"] == ["statuscode:200"] and qs["output"] == ["json"]


def test_parse_cdx_rows_and_empty():
    text = ('[["timestamp","original","statuscode"],'
            '["20190102030405","https://github.com/alice","200"]]')
    snaps = parse_cdx(text)
    assert len(snaps) == 1 and snaps[0].date == "2019-01-02"
    assert snaps[0].archive_url == "https://web.archive.org/web/20190102030405/https://github.com/alice"
    assert parse_cdx("") == [] and parse_cdx("[]") == []


def test_parse_cdx_garbage_is_error_not_empty():
    with pytest.raises(ValueError):
        parse_cdx("<html>Temporarily Offline</html>")


def test_wayback_targets_filter():
    sites = [Site("A", "https://a.com/{username}", tags=["social"]),
             Site("B", "https://b.com/{username}", tags=["forum"]),
             Site("C", "https://c.com/{username}", method="POST", tags=["social"])]
    assert wayback_targets(sites, "alice", {"social"}) == ["https://a.com/alice"]
    assert len(wayback_targets(sites, "alice", None, limit=1)) == 1
