"""Harmless redirects are followed without an explicit allowed origin; unsafe ones are not."""

import asyncio

import pytest

from ultimate_username.domain.models import (
    DetectionSpec,
    ErrorCode,
    HttpMethod,
    RedirectPolicy,
    Rule,
    SiteDefinition,
    TransportResponse,
    Verdict,
)
from ultimate_username.domain.urls import is_public_host, registrable_domain
from ultimate_username.engine import UsernameEngine
from ultimate_username.planning import plan_request
from ultimate_username.policies import redirect_request
from ultimate_username.registry import SiteRegistry
from ultimate_username.transport import FakeTransport

PROFILE = Rule("message", "profile")


def make_site(host="example.test", scheme="https", **changes):
    changes.setdefault("redirects", RedirectPolicy(follow=True))
    return SiteDefinition(
        "s", "S", f"{scheme}://{host}/{{username}}", DetectionSpec(PROFILE), **changes
    )


def follow(
    location, host="example.test", status=301, name="alice", insecure_source=False, **site_changes
):
    scheme = "http" if insecure_source else "https"
    plan = plan_request(name, make_site(host, scheme, **site_changes), "t")
    response = TransportResponse(plan.request.url, status, headers=(("Location", location),))
    return redirect_request(plan.request, response, plan, {plan.request.url})


@pytest.mark.parametrize(
    ("host", "location", "target"),
    [
        (
            "renderosity.com",
            "https://www.renderosity.com/alice",
            "https://www.renderosity.com/alice",
        ),
        ("www.buzzfeed.com", "https://buzzfeed.com/alice", "https://buzzfeed.com/alice"),
        ("hackerrank.com", "https://www.hackerrank.com/profile/alice", None),
        # an alias domain keeps the name in the path
        ("buymeacoff.ee", "https://www.buymeacoffee.com/alice", None),
        # the language version of the path keeps the name as a fragment of a segment
        ("tikbuddy.com", "https://tikbuddy.com/en/tiktok/alice", None),
        ("short.test", "https://long.example/en/users/ALICE-profile", None),
        ("short.test", "https://long.example/en/%41lice", None),
        # same registrable domain, different subdomain
        ("example.test", "https://accounts.example.test/login-free", None),
        ("a.example.co.uk", "https://b.example.co.uk/home", None),
    ],
)
def test_harmless_redirects_are_followed(host, location, target):
    moved = follow(location, host)
    assert moved is not None and moved.url == (target or location)


@pytest.mark.parametrize(
    "location",
    [
        "https://other.test/home",
        "https://other.test/",
        "https://example.test.evil.test/home",
        "https://evil.co.uk/home",
        "https://other.test/alpha",  # a 2-character name only matches a whole segment
    ],
)
def test_other_host_without_the_name_is_still_an_error(location):
    with pytest.raises(ValueError, match="Cross-origin"):
        follow(location, "example.co.uk" if "co.uk" in location else "example.test", name="al")


def test_registrable_domain_knows_two_level_suffixes():
    assert registrable_domain("www.example.co.uk") == "example.co.uk"
    assert registrable_domain("a.b.example.com.br") == "example.com.br"
    assert registrable_domain("x.example.com") == "example.com"
    assert registrable_domain("example.com") == "example.com"
    with pytest.raises(ValueError):
        follow("https://evil.co.uk/home", "example.co.uk")
    assert follow("https://shop.example.co.uk/home", "www.example.co.uk") is not None


@pytest.mark.parametrize(
    "location",
    [
        "http://127.0.0.1/alice",
        "https://10.0.0.5/alice",
        "https://192.168.1.1/alice",
        "http://169.254.169.254/latest/alice",
        "https://[::1]/alice",
        "http://localhost/alice",
        "https://intranet/alice",
        "https://printer.local/alice",
        "https://2130706433/alice",
    ],
)
def test_private_and_local_targets_are_blocked_even_with_the_name(location):
    with pytest.raises(ValueError, match="non-public|downgrade"):
        follow(location)
    with pytest.raises(ValueError, match="non-public"):
        follow(location.replace("https://", "http://"), insecure_source=True)


def test_public_host_helper():
    assert is_public_host("example.com") and is_public_host("8.8.8.8")
    assert not any(map(is_public_host, ["127.0.0.1", "::ffff:10.0.0.1", "localhost", "a.internal"]))


def test_https_downgrade_loop_hops_and_post_rules_survive():
    with pytest.raises(ValueError, match="downgrade"):
        follow("http://www.example.test/alice")
    plan = plan_request("alice", make_site(), "t")
    request = plan.request
    response = TransportResponse(request.url, 301, headers=(("Location", request.url),))
    with pytest.raises(ValueError, match="loop"):
        redirect_request(request, response, plan, {request.url})
    hops = make_site(redirects=RedirectPolicy(follow=True, max_hops=1))
    plan = plan_request("alice", hops, "t")
    response = TransportResponse(
        plan.request.url, 301, headers=(("Location", "https://www.example.test/alice"),)
    )
    with pytest.raises(ValueError, match="hop"):
        redirect_request(plan.request, response, plan, {"a", "b"})
    post = make_site(method=HttpMethod.POST, raw_body="x")
    with pytest.raises(ValueError, match="post_to_get"):
        follow("https://www.example.test/alice", method=HttpMethod.POST, raw_body="x")
    assert post.method == HttpMethod.POST


def test_follow_disabled_never_follows():
    assert follow("https://www.example.test/alice", redirects=RedirectPolicy()) is None


def test_post_to_get_apex_to_www_drops_body():
    moved = follow(
        "https://www.example.test/alice",
        method=HttpMethod.POST,
        raw_body="x",
        redirects=RedirectPolicy(follow=True, post_to_get=True),
    )
    assert moved is not None and moved.method == HttpMethod.GET and moved.body is None


# --- through the engine ------------------------------------------------------------------


def run(definition, handler):
    async def go():
        transport = FakeTransport(handler=handler)
        async with UsernameEngine(SiteRegistry([definition]), transport) as engine:
            return (await engine.search("alice"))[0], transport

    return asyncio.run(go())


def test_apex_to_www_gives_the_verdict_of_the_www_page():
    def handler(request, i):
        if request.url.startswith("https://example.test/"):
            return TransportResponse(
                request.url, 301, headers=(("Location", "https://www.example.test/alice"),)
            )
        return TransportResponse(request.url, 200, b"profile alice", (), request.url)

    result, transport = run(make_site(), handler)
    direct, _ = run(
        make_site("www.example.test"),
        lambda request, i: TransportResponse(request.url, 200, b"profile alice", (), request.url),
    )
    assert result.detection.verdict == direct.detection.verdict == Verdict.PROBABLE
    assert [r.url for r in transport.requests][-1] == "https://www.example.test/alice"
    assert result.final_url == "https://www.example.test/alice"


def test_redirect_to_other_host_without_the_name_stays_a_redirect_error():
    def handler(request, i):
        return TransportResponse(
            request.url, 302, headers=(("Location", "https://other.test/welcome"),)
        )

    result, transport = run(make_site(), handler)
    assert result.detection.errors[0].code == ErrorCode.REDIRECT_ERROR
    assert transport.total == 1


def test_redirect_to_a_private_host_is_blocked_in_the_engine():
    def handler(request, i):
        return TransportResponse(
            request.url, 302, headers=(("Location", "http://127.0.0.1/alice"),)
        )

    result, transport = run(make_site(), handler)
    assert result.detection.errors[0].code == ErrorCode.REDIRECT_ERROR
    assert transport.total == 1


def test_homepage_after_the_new_redirect_path_is_still_redirect_only():
    def handler(request, i):
        if request.url.startswith("https://example.test/"):
            return TransportResponse(
                request.url, 301, headers=(("Location", "https://www.example.test/"),)
            )
        return TransportResponse(
            request.url, 200, b"<title>Home</title>", (), "https://www.example.test/"
        )

    result, _ = run(make_site(), handler)
    assert result.detection.response_class == "REDIRECT_ONLY"
    assert result.detection.verdict != Verdict.FOUND
