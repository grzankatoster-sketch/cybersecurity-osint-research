"""E2 steps 2, 3, 5: embedded SPA state with owner binding, looser JSON-LD binding, JSON bodies."""

import html
import json
import time
from urllib.parse import quote

import pytest

from ultimate_username.domain.metadata import EvidenceQuality
from ultimate_username.domain.models import (
    DetectionResult,
    DetectionSpec,
    Rule,
    SiteDefinition,
    TransportResponse,
    Verdict,
)
from ultimate_username.embedded_state import EmbeddedStateExtractor
from ultimate_username.enrichment import (
    EXTRACTORS,
    ExtractionContext,
    ParsedDocument,
    enrich,
)

HTML = (("Content-Type", "text/html; charset=utf-8"),)
JSON = (("Content-Type", "application/json"),)
SITE = SiteDefinition(
    "social",
    "Social",
    "https://social.example/u/{username}",
    DetectionSpec(Rule("status", statuses=(200,))),
)
PROFILE = {
    "username": "alice",
    "displayName": "Alice Smith",
    "bio": "Chess coach and endgame nerd",
    "country": "Norway",
    "avatarUrl": "https://cdn.example.net/u/9f3a/alice.jpg",
    "followers": 1200,
    "createdAt": 1600000000,
    "links": ["https://alice.dev", "https://github.com/alice"],
}
ONLY = (EmbeddedStateExtractor(),)


def page(body, nick="alice", headers=HTML):
    url = f"https://social.example/u/{nick}"
    return TransportResponse(url, 200, body.encode(), headers, url)


def run(body, nick="alice", extractors=ONLY, headers=HTML):
    return enrich(
        page(body, nick, headers), nick, SITE, DetectionResult(Verdict.FOUND), extractors=extractors
    )


def values(result):
    return {f.name: f.value for f in result.fields + result.extra_fields}


def deep(profile):
    """Nesting no explicit container list reaches."""
    return {"a": {"b": [{"c": {"payload": profile}}]}}


def script(data, attrs='type="application/json"'):
    return f"<html><body><script {attrs}>{json.dumps(data)}</script></body></html>"


EXPECTED = {
    "display_name": "Alice Smith",
    "bio": "Chess coach and endgame nerd",
    "location": "Norway",
    "avatar_url": "https://cdn.example.net/u/9f3a/alice.jpg",
    "followers": 1200,
    "created_at": "2020-09-13T12:26:40+00:00",
    "external_links": ("https://alice.dev", "https://github.com/alice"),
}


def assert_profile(result):
    got = values(result)
    for key, value in EXPECTED.items():
        assert got[key] == value, key


# ---------------------------------------------------------------- every source on its own


def test_application_json_script_without_id():
    assert_profile(run(script(deep(PROFILE))))


def test_next_data_script():
    assert_profile(run(script(deep(PROFILE), 'id="__NEXT_DATA__" type="application/json"')))


def test_window_assignment_state():
    body = f"<script>window.__INITIAL_STATE__ = {json.dumps(deep(PROFILE))};</script>"
    assert_profile(run(body))


def test_window_initials_without_spaces_and_trailing_code():
    body = f"<script>var x=1;window.initials={json.dumps(deep(PROFILE))};window.y=2;</script>"
    assert_profile(run(body))


def test_json_parse_string_state():
    literal = json.dumps(json.dumps(deep(PROFILE)))
    assert_profile(run(f"<script>window.__STATE__ = JSON.parse({literal});</script>"))


def test_script_with_url_encoded_json():
    body = f'<script id="initialData">{quote(json.dumps(deep(PROFILE)))}</script>'
    assert_profile(run(body))


def test_json_typed_script_with_url_encoded_json():
    body = f'<script type="application/json">{quote(json.dumps(deep(PROFILE)))}</script>'
    result = run(body)
    assert_profile(result)
    assert result.parser_failures == 0


def test_data_attribute_with_escaped_quotes():
    attr = html.escape(json.dumps(deep(PROFILE)), quote=True)
    assert_profile(run(f'<div id="app" data-initial-data="{attr}"></div>'))


def test_data_attribute_with_url_encoded_json():
    attr = quote(json.dumps(deep(PROFILE)))
    assert_profile(run(f'<div data-store="{attr}"></div>'))


def test_data_attribute_double_escaped():
    attr = html.escape(html.escape(json.dumps(deep(PROFILE))), quote=True)
    assert_profile(run(f'<div data-props="{attr}"></div>'))


def test_json_response_body_deep_object():
    result = run(json.dumps(deep(PROFILE)), headers=JSON)
    assert_profile(result)
    assert any(c.evidence.startswith("response") for c in result.candidates)


def test_plain_script_without_state_is_ignored():
    body = "<script>window.analytics = {id: 1}; var s = {'username': 'alice'};</script>"
    assert values(run(body)) == {}


# ---------------------------------------------------------------- owner binding


def test_owner_keys_other_than_username_bind_the_owner():
    for key in ("login", "screen_name", "handle", "slug", "acct", "nickname", "user_name"):
        profile = {key: "alice", "displayName": "Alice Smith", "bio": "Chess coach and nerd"}
        got = values(run(script(deep(profile))))
        assert got.get("display_name") == "Alice Smith", key


def test_unique_id_and_leading_at_bind_the_owner():
    got = values(run(script(deep({"uniqueId": "alice", "fullName": "Alice Smith"}))))
    assert got["display_name"] == "Alice Smith"
    got = values(run(script(deep({"acct": "@alice", "fullName": "Alice Smith"}))))
    assert got["display_name"] == "Alice Smith"


def test_case_only_difference_stays_unbound_on_generic_platforms():
    # Same policy as the explicit extractors: only owner_matches decides about case.
    assert values(run(script(deep({"username": "ALICE", "displayName": "Alice Smith"})))) == {}


def test_object_naming_two_different_owners_is_not_an_owner():
    data = deep({"username": "alice", "login": "mallory", "displayName": "Alice Smith"})
    assert values(run(script(data))) == {}


def test_already_contradicted_owner_binding_is_not_overridden():
    data = {
        "props": {"pageProps": {"user": {"username": "mallory", "displayName": "Mallory"}}},
        "deep": deep({"username": "alice", "displayName": "Alice Smith"}),
    }
    assert values(run(script(data), extractors=EXTRACTORS)).get("display_name") != "Alice Smith"


def test_name_binds_only_when_equal_to_nick_and_is_then_an_echo():
    result = run(script(deep({"name": "alice", "bio": "Chess coach and nerd"})))
    assert values(result)["bio"] == "Chess coach and nerd"
    assert "display_name" not in values(result)
    other = run(script(deep({"name": "Alice Smith", "bio": "Chess coach and nerd"})))
    assert values(other) == {}


def test_name_other_than_nick_is_display_name_of_a_bound_owner():
    got = values(run(script(deep({"username": "alice", "name": "Alice Smith"}))))
    assert got["display_name"] == "Alice Smith"


def test_nickname_equal_to_nick_is_not_a_display_name():
    got = values(
        run(script(deep({"username": "alice", "nickname": "alice", "name": "Alice Smith"})))
    )
    assert got["display_name"] == "Alice Smith"


def test_other_users_objects_are_ignored():
    data = {
        "me": {"username": "alice", "displayName": "Alice Smith", "bio": "Chess coach and nerd"},
        "followers": [
            {"username": "bob", "displayName": "Bob Builder", "bio": "Builds things all day"},
            {"username": "carol", "displayName": "Carol Danvers"},
        ],
        "related": {"deep": {"username": "dave", "displayName": "Dave"}},
    }
    got = values(run(script(data)))
    assert got["display_name"] == "Alice Smith"
    assert got["bio"] == "Chess coach and nerd"


def test_no_owner_object_gives_nothing():
    data = {"followers": [{"username": "bob", "displayName": "Bob Builder"}]}
    result = run(script(data))
    assert values(result) == {}
    assert "AMBIGUOUS_OWNER" not in result.diagnostics


def test_conflicting_owner_objects_are_ambiguous():
    data = {
        "a": {"username": "alice", "displayName": "Alice Smith", "bio": "Chess coach and nerd"},
        "b": {"username": "alice", "displayName": "Alice Other", "bio": "Totally different person"},
    }
    result = run(script(data))
    assert values(result) == {}
    assert "AMBIGUOUS_OWNER" in result.diagnostics


def test_identical_and_compatible_owner_objects_are_merged():
    full = {"username": "alice", "displayName": "Alice Smith", "bio": "Chess coach and nerd"}
    data = {
        "a": full,
        "b": [dict(full)],
        "post": {"author": {"username": "alice", "name": "Alice Smith"}},
    }
    got = values(run(script(data)))
    assert got["display_name"] == "Alice Smith"
    assert got["bio"] == "Chess coach and nerd"


def test_owner_object_without_usable_fields_does_not_make_things_ambiguous():
    data = {
        "routeParameters": {"username": "alice"},
        "user": {"username": "alice", "displayName": "Alice Smith"},
    }
    result = run(script(data))
    assert values(result)["display_name"] == "Alice Smith"
    assert "AMBIGUOUS_OWNER" not in result.diagnostics


def test_values_come_only_from_the_owner_object_not_its_neighbours():
    data = {
        "owner": {"username": "alice", "displayName": "Alice Smith"},
        "bio": "Top-level bio that belongs to nobody in particular",
        "location": "Nowhere",
    }
    got = values(run(script(data)))
    assert got == {"display_name": "Alice Smith"}


def test_website_and_link_shapes():
    profile = {
        "username": "alice",
        "website": "https://alice.dev",
        "socials": [{"url": "https://twitter.com/alice"}, {"href": "https://t.me/alice"}, "nope"],
    }
    got = values(run(script(deep(profile))))
    assert got["website"] == "https://alice.dev"
    assert got["external_links"] == ("https://twitter.com/alice", "https://t.me/alice")


def test_created_at_accepts_epoch_millis_and_iso_but_not_prose():
    base = {"username": "alice"}
    millis = values(run(script(deep({**base, "created": 1600000000000}))))
    assert millis["created_at"] == "2020-09-13T12:26:40+00:00"
    iso = values(run(script(deep({**base, "joined": "2019-03-04T10:00:00Z"}))))
    assert iso["created_at"] == "2019-03-04T10:00:00+00:00"
    assert "created_at" not in values(run(script(deep({**base, "joined": "2 years ago"}))))
    assert "created_at" not in values(run(script(deep({**base, "created": True}))))


def test_avatar_can_be_an_object_with_url():
    got = values(
        run(
            script(deep({"username": "alice", "picture": {"url": "https://cdn.example.net/p.jpg"}}))
        )
    )
    assert got["avatar_url"] == "https://cdn.example.net/p.jpg"


def test_extracted_fields_are_medium_quality_below_explicit_extractors():
    result = run(script(deep(PROFILE)))
    cands = [c for c in result.candidates if c.extractor == "EmbeddedStateExtractor"]
    assert cands and all(c.quality == EvidenceQuality.MEDIUM and c.priority == 25 for c in cands)
    assert all(c.source_url == "https://social.example/u/alice" for c in cands)
    assert any("script" in c.evidence for c in cands)


def test_does_not_override_json_ld_or_the_explicit_container_extractor():
    # The explicit container extractor (priority 10) and JSON-LD (20) stay ahead of this one.
    person = {
        "@type": "Person",
        "alternateName": "alice",
        "name": "LdName",
        "url": "https://social.example/u/alice",
    }
    state = json.dumps(deep({"username": "alice", "displayName": "StateName"}))
    body = (
        f'<script type="application/ld+json">{json.dumps(person)}</script>'
        f"<script>window.__S__ = {state};</script>"
    )
    result = run(body, extractors=EXTRACTORS)
    assert values(result)["display_name"] == "LdName"
    assert "display_name" in result.conflicts
    explicit = {"props": {"pageProps": {"user": {"username": "alice", "displayName": "Explicit"}}}}
    body = f'<script type="application/json">{json.dumps(explicit)}</script>' + body
    assert values(run(body, extractors=EXTRACTORS))["display_name"] == "Explicit"


# ---------------------------------------------------------------- limits


def test_two_megabyte_state_is_parsed_fast():
    filler = [{"username": f"user{i}", "bio": "x" * 40, "id": i} for i in range(21500)]
    data = {"users": filler, "me": {"username": "alice", "displayName": "Alice Smith"}}
    text = json.dumps(data)
    assert 1_800_000 < len(text) < 2 * 1024 * 1024
    response = page(f"<html><script type='application/json'>{text}</script></html>")
    started = time.perf_counter()
    document = ParsedDocument(response)
    context = ExtractionContext(response, "alice", SITE)
    EmbeddedStateExtractor().extract(document, context)
    elapsed = time.perf_counter() - started
    assert any(c.value == "Alice Smith" for c in context.candidates)
    assert elapsed < 0.5, elapsed


def test_two_megabyte_window_state_is_parsed_fast():
    data = {"pad": "x" * 2_000_000, "me": {"username": "alice", "displayName": "Alice Smith"}}
    response = page(f"<html><script>window.__S__ = {json.dumps(data)};</script></html>")
    started = time.perf_counter()
    document = ParsedDocument(response)
    context = ExtractionContext(response, "alice", SITE)
    EmbeddedStateExtractor().extract(document, context)
    assert [c.value for c in context.candidates] == ["Alice Smith"]
    assert time.perf_counter() - started < 0.5


def test_oversized_state_is_skipped():
    big = json.dumps(
        {"me": {"username": "alice", "displayName": "Alice Smith"}, "pad": "x" * 2_200_000}
    )
    response = page(f"<script>window.__BIG__ = {big};</script>")
    document = ParsedDocument(response)
    context = ExtractionContext(response, "alice", SITE)
    EmbeddedStateExtractor().extract(document, context)
    assert context.candidates == []


def test_very_deep_nesting_does_not_crash_or_hang():
    deep_text = "[" * 5000 + "]" * 5000
    body = (
        f"<script>window.__DEEP__ = {deep_text};</script>"
        f"<script type='application/json'>{deep_text}</script>"
    )
    started = time.perf_counter()
    result = run(body)
    assert time.perf_counter() - started < 1.0
    assert values(result) == {}


def test_depth_beyond_the_limit_hides_the_owner():
    nested: dict = {"username": "alice", "displayName": "Alice Smith"}
    for _ in range(40):
        nested = {"x": nested}
    assert values(run(script(nested))) == {}


def test_object_count_limit_stops_the_walk():
    many = [{"i": i} for i in range(60000)]
    data = {"many": many, "late": {"username": "alice", "displayName": "Alice Smith"}}
    assert "display_name" not in values(run(script(data)))


def test_hostile_script_text_is_linear():
    body = "<script>" + "window.a=" * 20000 + "{" * 30000 + "</script>"
    started = time.perf_counter()
    run(body)
    assert time.perf_counter() - started < 1.0


# ---------------------------------------------------------------- JSON-LD binding (step 3)


def ld_page(person, nick="alice"):
    return f'<script type="application/ld+json">{json.dumps(person)}</script>'


def test_json_ld_person_with_url_equal_to_profile_url_is_bound():
    person = {
        "@type": "Person",
        "url": "https://social.example/u/alice",
        "name": "Alice Smith",
        "description": "Chess coach and endgame nerd",
        "image": "https://cdn.example.net/u/9f3a/alice.jpg",
    }
    got = values(run(ld_page(person), extractors=EXTRACTORS))
    assert got["display_name"] == "Alice Smith"
    assert got["avatar_url"] == "https://cdn.example.net/u/9f3a/alice.jpg"


def test_json_ld_person_bound_by_id_or_trailing_nick_path():
    for key, url in (
        ("@id", "https://social.example/u/alice#me"),
        ("@id", "https://social.example/people/alice/"),
        ("url", "https://www.social.example/@alice"),
    ):
        person = {"@type": "Person", key: url, "name": "Alice Smith"}
        got = values(run(ld_page(person), extractors=EXTRACTORS))
        assert got.get("display_name") == "Alice Smith", url


def test_json_ld_profile_page_main_entity_inherits_binding():
    data = {
        "@type": "ProfilePage",
        "url": "https://social.example/u/alice",
        "mainEntity": {"@type": "Person", "name": "Alice Smith", "sameAs": ["https://alice.dev"]},
    }
    got = values(run(ld_page(data), extractors=EXTRACTORS))
    assert got["display_name"] == "Alice Smith"
    assert got["external_links"] == ("https://alice.dev",)


@pytest.mark.parametrize(
    "person",
    [
        {"@type": "Person", "url": "https://social.example/u/bob", "name": "Bob Builder"},
        {"@type": "Person", "url": "https://social.example/about", "name": "Staff Writer"},
        {"@type": "Person", "url": "https://elsewhere.example/alice", "name": "Other Alice"},
        {"@type": "Person", "name": "No Url At All"},
        {"@type": "Organization", "url": "https://social.example/u/alice", "name": "Acme Inc"},
        {
            "@type": "ProfilePage",
            "url": "https://social.example/u/bob",
            "mainEntity": {"@type": "Person", "name": "Bob Builder"},
        },
    ],
)
def test_json_ld_negative_cases(person):
    assert values(run(ld_page(person), extractors=EXTRACTORS)) == {}


def test_json_ld_template_person_is_filtered_as_echo():
    person = {
        "@type": "Person",
        "url": "https://social.example/u/alice",
        "name": "alice",
        "image": "https://cdn.example.net/og/alice.jpg",
    }
    result = run(ld_page(person), extractors=EXTRACTORS)
    assert "display_name" not in values(result)
    assert "avatar_url" not in values(result)
    assert "NICK_ECHO" in result.diagnostics
