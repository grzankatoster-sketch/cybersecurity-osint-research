from username_engine.models import Site
from username_engine.sources import from_wmn, merge


WMN = {"sites": [
    {"name": "HubAlpha", "uri_check": "https://api.hub.example.com/api/v1/check",
     "post_body": '{"community":"alpha","user":"{account}"}',
     "headers": {"Content-Type": "application/json"},
     "e_code": 200, "e_string": '"exists":true', "m_code": 200, "m_string": '"exists":false',
     "cat": "social", "known": ["alice"]},
    {"name": "HubBeta", "uri_check": "https://api.hub.example.com/api/v1/check",
     "post_body": '{"community":"beta","user":"{account}"}',
     "headers": {"Content-Type": "application/json"},
     "e_code": 200, "e_string": '"exists":true', "m_code": 200, "m_string": '"exists":false',
     "cat": "gaming", "known": ["bob"]},
]}


def test_merge_keeps_distinct_post_rules_on_shared_endpoint():
    sites = from_wmn(WMN)
    assert len(sites) == 2
    merged = merge(sites)
    bodies = sorted(s.body for s in merged)
    # dwie rozne reguly (inna tresc zapytania) nie sa duplikatami - zadna nie moze zniknac
    assert bodies == sorted([
        '{"community":"alpha","user":"{username}"}',
        '{"community":"beta","user":"{username}"}',
    ])
    names = [s.name for s in merged]
    assert len(names) == len({n.lower() for n in names})


def test_merge_does_not_glue_tags_of_other_post_rule():
    merged = merge(from_wmn(WMN))
    alpha = [s for s in merged if s.body and '"alpha"' in s.body]
    assert len(alpha) == 1
    assert alpha[0].tags == ["social"]


def test_merge_post_rules_across_sources_kept_but_true_duplicates_still_merge():
    a = Site("HubAlpha", "https://api.hub.example.com/api/v1/check", method="POST",
             body='{"community":"alpha","user":"{username}"}', source="wmn")
    b = Site("HubBeta", "https://api.hub.example.com/api/v1/check", method="POST",
             body='{"community":"beta","user":"{username}"}', source="maigret")
    assert len(merge([a], [b])) == 2
    # prawdziwy duplikat (ten sam adres profilu z {username}) nadal scalany
    c = Site("GH", "https://github.com/{username}", probe_url="https://api.github.com/users/{username}", source="wmn")
    d = Site("GitHub", "https://www.github.com/{username}/", source="maigret")
    assert len(merge([c], [d])) == 1
