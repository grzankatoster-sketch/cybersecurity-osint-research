"""E2 step 1: template / nick-echo / default-image / control-equal values never become fields."""

import json
import time

import pytest

from ultimate_username.domain.models import (
    DetectionResult,
    DetectionSpec,
    Rule,
    SiteDefinition,
    TransportResponse,
    Verdict,
)
from ultimate_username.enrichment import enrich
from ultimate_username.enrichment_filters import (
    control_digest,
    filter_reason,
    response_digests,
)

HEADERS = (("Content-Type", "text/html; charset=utf-8"),)
SITE_URL = "https://www.kwai.com/@{username}"


def make_site(name="Kwai"):
    return SiteDefinition("kwai", name, SITE_URL, DetectionSpec(Rule("status", statuses=(200,))))


def run(body, nick="alice", name="Kwai", **kwargs):
    final = f"https://www.kwai.com/@{nick}"
    response = TransportResponse(final, 200, body.encode(), HEADERS, final)
    return enrich(response, nick, make_site(name), DetectionResult(Verdict.FOUND), **kwargs)


def values(result):
    return {f.name: f.value for f in result.fields + result.extra_fields}


def json_page(profile, nick="alice"):
    body = (
        '<html><head><title>Kwai</title></head><body><script type="application/json">'
        + json.dumps({"props": {"pageProps": {"user": {"username": nick, **profile}}}})
        + "</script></body></html>"
    )
    return body


# ---------------------------------------------------------------- filter_reason (pure)


@pytest.mark.parametrize(
    "value",
    [
        "alice",
        "Alice",
        "@alice",
        "@Alice",
        "alice's profile",
        "Alice’s Profile",
        "alice on Kwai",
        "Alice (@alice)",
        "profile of alice",
        "A.l_i-c-e",
    ],
)
def test_nick_echo_is_rejected(value):
    assert filter_reason("display_name", value, "alice", "Kwai", "https://www.kwai.com/@alice") == (
        "NICK_ECHO"
    )


@pytest.mark.parametrize(
    "value", ["Alice Smith", "Alice Wonderland", "alice and bob's channel", "I am alice"]
)
def test_real_names_are_kept(value):
    assert (
        filter_reason("display_name", value, "alice", "Kwai", "https://www.kwai.com/@alice") == ""
    )


def test_echo_also_applies_to_bio_location_and_website_text():
    for field in ("bio", "description", "location"):
        assert filter_reason(field, "@alice", "alice", "Kwai", "https://kwai.com/@alice") == (
            "NICK_ECHO"
        )
    assert filter_reason("website", "alice", "alice", "Kwai", "https://kwai.com/@alice") == (
        "NICK_ECHO"
    )


def test_short_nick_is_matched_by_whole_words_only():
    assert filter_reason("display_name", "Ann Lee", "a", "Kwai", "https://kwai.com/@a") == ""
    assert filter_reason("display_name", "a", "a", "Kwai", "https://kwai.com/@a") == "NICK_ECHO"


@pytest.mark.parametrize(
    "value",
    [
        "You can view and join @alice right away.",
        "Join alice on Kwai",
        "Check out alice's profile",
        "Check out Alice Smith's page on the web",
        "alice is on Kwai",
        "Download the app to see more",
        "Sign up to see alice's posts",
        "Alice's profile on Kwai",
        "Create your own page",
        "Link in bio",
        "link in bio!",
        "Dołącz do Kwai, aby zobaczyć profil",
        "Únete a Kwai para ver el perfil",
        "Rejoignez Kwai",
        "Registriere dich bei Kwai",
        "Присоединяйтесь к Kwai",
        "If you have Telegram, you can contact @alice right away.",
    ],
)
def test_template_phrases_are_rejected(value):
    assert filter_reason("bio", value, "alice", "Kwai", "https://www.kwai.com/@alice") == (
        "TEMPLATE_VALUE"
    )


def test_real_bio_mentioning_join_or_sign_up_inside_long_text_survives():
    bio = (
        "Chess coach, author of three books on endgames, streamer on weekends and father of two. "
        "My students often say they sign up for the lessons because of the humor and clear plans."
    )
    assert filter_reason("bio", bio, "alice", "Kwai", "https://www.kwai.com/@alice") == ""


@pytest.mark.parametrize(
    "url",
    [
        "https://cdn.example.net/images/nophoto.png",
        "https://cdn.example.net/assets/missing.png",
        "https://cdn.example.net/avatars/original/missing.png",
        "https://cdn.example.net/img/default.jpg",
        "https://cdn.example.net/img/default_avatar.png",
        "https://cdn.example.net/img/avatar-default.svg",
        "https://cdn.example.net/img/defaultAvatar.png",
        "https://cdn.example.net/img/placeholder.gif",
        "https://cdn.example.net/img/blank.png",
        "https://www.gravatar.com/avatar/0abc?d=mp&s=200",
        "https://www.gravatar.com/avatar/0abc?d=identicon",
        "https://www.gravatar.com/avatar/0abc?f=y",
        "https://abs.twimg.com/sticky/default_profile_images/default_profile_normal.png",
        "https://cdn.example.net/static/img/logo.png",
        "https://cdn.example.net/og/alice.jpg",
        "https://cdn.example.net/share/card/alice.png",
        "https://cdn.example.net/img/zaslepka.png",
    ],
)
def test_default_or_generated_images_are_rejected(url):
    assert filter_reason("avatar_url", url, "alice", "Kwai", "https://www.kwai.com/@alice") == (
        "TEMPLATE_VALUE"
    )


@pytest.mark.parametrize(
    "url",
    [
        "https://cdn.example.net/u/9f3a/photo.jpg",
        "https://cdn.example.net/avatars/alice-1234.jpg",
        "https://cdn.example.net/static/avatars/9f3a.jpg",
        "https://www.gravatar.com/avatar/0abcdef1234",
        "https://cdn.example.net/img/eggplant.jpg",
    ],
)
def test_real_images_are_kept(url):
    assert filter_reason("avatar_url", url, "alice", "Kwai", "https://www.kwai.com/@alice") == ""


def test_other_fields_are_never_filtered():
    for field in ("followers", "created_at", "username", "user_id", "verified"):
        assert filter_reason(field, "alice", "alice", "Kwai", "https://kwai.com/@alice") == ""


def test_control_digest_is_nick_independent_and_case_insensitive():
    a = control_digest("Alice | Kwai - watch short videos", "alice")
    b = control_digest("zq81xv | KWAI - watch short videos", "zq81xv")
    assert a == b
    assert a != control_digest("Alice Smith | Kwai", "alice")
    assert len(a) == 16


def test_control_equal_value_is_rejected_after_nick_substitution():
    digest = control_digest("zq81xv's Kwai page - videos and more", "zq81xv")
    assert (
        filter_reason(
            "display_name",
            "alice's Kwai page - videos and more",
            "alice",
            "Kwai",
            "https://www.kwai.com/@alice",
            frozenset({digest}),
        )
        == "CONTROL_SAME_VALUE"
    )
    assert (
        filter_reason(
            "display_name",
            "Alice Smith",
            "alice",
            "Kwai",
            "https://www.kwai.com/@alice",
            frozenset({digest}),
        )
        == ""
    )


# ---------------------------------------------------------------- through enrich()


def test_echo_template_and_default_avatar_are_diagnosed_not_stored():
    body = json_page(
        {
            "displayName": "@alice",
            "bio": "You can view and join @alice right away.",
            "avatar": "https://cdn.example.net/images/nophoto.png",
            "location": "alice",
        }
    )
    result = enrich(
        TransportResponse(
            "https://www.kwai.com/@alice",
            200,
            body.encode(),
            HEADERS,
            "https://www.kwai.com/@alice",
        ),
        "alice",
        make_site(),
        DetectionResult(Verdict.FOUND),
    )
    got = values(result)
    assert "display_name" not in got and "bio" not in got and "avatar_url" not in got
    assert "location" not in got
    assert {"NICK_ECHO", "TEMPLATE_VALUE"} <= set(result.diagnostics)
    assert {"display_name", "bio", "avatar_url", "location"} <= set(result.coverage.rejected_fields)


def test_real_values_next_to_rejected_ones_survive():
    body = json_page(
        {
            "displayName": "Alice Smith",
            "bio": "Join alice on Kwai",
            "avatar": "https://cdn.example.net/u/9f3a/photo.jpg",
        }
    )
    got = values(run(body))
    assert got["display_name"] == "Alice Smith"
    assert got["avatar_url"] == "https://cdn.example.net/u/9f3a/photo.jpg"
    assert "bio" not in got


def test_page_meta_title_equal_to_control_is_rejected():
    body = (
        "<title>alice | Kwai - short videos</title>"
        '<meta property="og:title" content="Anna Kowalska">'
        '<meta property="og:description" content="Watch and share short videos with the world">'
        '<meta property="og:image" content="https://cdn.kwai.net/u/9f3a/photo.jpg">'
    )
    digests = frozenset(
        {
            control_digest("Anna Kowalska", "zq81xv"),
            control_digest("Watch and share short videos with the world", "zq81xv"),
        }
    )
    plain = values(run(body))
    assert plain.get("display_name") == "Anna Kowalska"
    assert "bio" not in plain  # PageMetaExtractor never takes descriptions
    result = run(body, control_digests=digests)
    got = values(result)
    assert "bio" not in got and "display_name" not in got
    assert got["avatar_url"] == "https://cdn.kwai.net/u/9f3a/photo.jpg"
    assert "CONTROL_SAME_VALUE" in result.diagnostics


def test_response_digests_cover_titles_and_social_meta_of_the_control_page():
    html = (
        "<html><head><title>zq81xv | Kwai</title>"
        '<meta property="og:title" content="zq81xv | Kwai">'
        '<meta property="og:description" content="Watch short videos on Kwai">'
        '<meta name="twitter:image" content="https://cdn.kwai.net/og/zq81xv.jpg">'
        '<meta name="description" content="x"></head><body>hi</body></html>'
    )
    response = TransportResponse(
        "https://www.kwai.com/@zq81xv", 200, html.encode(), HEADERS, "https://www.kwai.com/@zq81xv"
    )
    digests = response_digests(response, "zq81xv")
    assert control_digest("zq81xv | Kwai", "zq81xv") in digests
    assert control_digest("Watch short videos on Kwai", "zq81xv") in digests
    assert control_digest("https://cdn.kwai.net/og/zq81xv.jpg", "zq81xv") in digests
    assert len(digests) <= 16


def test_response_digests_ignore_non_html_and_oversize_noise():
    response = TransportResponse(
        "https://x.test/", 200, b"\xff\xfe\x00 binary", (("Content-Type", "image/png"),), None
    )
    assert response_digests(response, "zq81xv") == frozenset()


def test_filter_is_fast_on_hostile_values():
    text = "join " + "a " * 40000 + "on kwai"
    started = time.perf_counter()
    for field in ("bio", "display_name"):
        filter_reason(field, text, "alice", "Kwai", "https://www.kwai.com/@alice")
        filter_reason(field, "(" * 50000, "alice", "Kwai", "https://www.kwai.com/@alice")
    assert time.perf_counter() - started < 0.5


# ---------------------------------------------------------------- control plumbing


def _engine_run(digests):
    import asyncio

    from ultimate_username import control as ctl
    from ultimate_username.domain.metadata import EnrichmentMode
    from ultimate_username.engine import SearchOptions, UsernameEngine
    from ultimate_username.enrichment import enrich as real_enrich
    from ultimate_username.profile_service import ProfileService
    from ultimate_username.registry import SiteRegistry
    from ultimate_username.transport import FakeTransport

    calls = []

    class Inline(ProfileService):
        async def run(self, response, username, site, detection, control_digests=frozenset()):
            calls.append(control_digests)
            return real_enrich(response, username, site, detection, control_digests=control_digests)

    site = SiteDefinition(
        "ctl",
        "Ctl",
        "https://ctl.test/u/{username}",
        DetectionSpec(Rule("message", "profile"), binding=Rule("redirect", "{profile_url}")),
    )
    body = (
        "<html><head><title>alice | Ctl - videos</title>"
        '<meta property="og:title" content="Anna Kowalska">'
        "</head><body><h1>alice</h1><p>profile</p></body></html>"
    )

    def handler(request, index):
        return TransportResponse(request.url, 200, body.encode(), HEADERS)

    async def go():
        registry = SiteRegistry([site])
        async with UsernameEngine(
            registry, FakeTransport(handler=handler), profiles=Inline(), random_seed=1
        ) as engine:
            if digests:
                key = ("ctl", site.method.value, site.probe_url or site.profile_url, site.query)
                engine._control_cache[key] = ctl.ControlObservation(
                    ctl.PageFacts(),
                    ctl.RuleOutcome(ctl.PredicateState.TRUE, ctl.PredicateState.FALSE),
                    "zq81xv",
                    1,
                    digests=digests,
                )
            out = await engine.search(
                "alice", options=SearchOptions(enrichment_mode=EnrichmentMode.BASIC)
            )
        return out[0], calls

    return asyncio.run(go())


def test_engine_hands_cached_control_digests_to_enrichment():
    digests = frozenset({control_digest("Anna Kowalska", "zq81xv")})
    result, calls = _engine_run(digests)
    assert calls == [digests]
    assert result.profile_metadata.get("display_name") is None
    assert "CONTROL_SAME_VALUE" in result.profile_metadata.diagnostics


def test_engine_without_control_digests_keeps_the_page_values():
    result, calls = _engine_run(frozenset())
    assert calls == [frozenset()]
    assert result.profile_metadata.get("display_name") == "Anna Kowalska"
