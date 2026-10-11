"""Final-review security fixes: SSRF (host forms, resolved IPs, redirects, avatars), ReDoS,
origin cooldown cap, report escaping and generator cleanup. No network: resolvers are mocked."""

from __future__ import annotations

import asyncio
import time
from types import SimpleNamespace

import pytest

from ultimate_username.domain.models import (
    DetectionResult,
    DetectionSpec,
    ErrorCode,
    HttpMethod,
    Rule,
    SiteDefinition,
    TimeoutProfile,
    TransportRequest,
    TransportResponse,
)
from ultimate_username.domain.urls import is_public_host

# ------------------------------------------------------------------ is_public_host forms

LOOPBACK_FORMS = [
    "127.0.0.1",
    "127.1",
    "127.0.1",
    "0177.0.0.1",
    "2130706433",
    "0x7f000001",
    "0x7f.1",
    "0x7f.0.0.1",
    "0.0.0.0",
    "10.1",
    "169.254.169.254",
    "2852039166",
    "192.168.1",
    "::1",
    "[::1]",
    "::ffff:127.0.0.1",
    "fe80::1",
    "localhost",
    "LOCALHOST.",
    "foo.localhost",
    "printer.local",
    "db.internal",
    "nas.lan",
    "router.home",
    "pc.localdomain",
    "",
]


@pytest.mark.parametrize("host", LOOPBACK_FORMS)
def test_non_public_host_forms_are_rejected(host):
    assert not is_public_host(host)


@pytest.mark.parametrize(
    "host", ["example.com", "8.8.8.8", "8.8", "1password.com", "www.sub.example.co.uk", "3com.com"]
)
def test_ordinary_public_hosts_stay_public(host):
    assert is_public_host(host)


def test_resolved_addresses_are_checked_on_request():
    resolver = {"evil.example": ["93.184.216.34", "10.0.0.5"], "good.example": ["93.184.216.34"]}
    assert not is_public_host("evil.example", resolver=lambda h: resolver[h])
    assert is_public_host("good.example", resolver=lambda h: resolver[h])
    assert not is_public_host("rebind.example", resolver=lambda h: ["::ffff:169.254.169.254"])


def test_unresolvable_host_is_not_an_ssrf_risk():
    def broken(host):
        raise OSError("no such host")

    assert is_public_host("nxdomain.example", resolver=broken)


# ------------------------------------------------------------------ guarded transport


class Recorder:
    def __init__(self) -> None:
        self.sent: list[str] = []

    async def send(self, request: TransportRequest) -> TransportResponse:
        self.sent.append(request.url)
        return TransportResponse(request.url, status=200)

    async def close(self) -> None:
        pass


def request(url: str) -> TransportRequest:
    return TransportRequest(url=url, method=HttpMethod.GET, timeout=TimeoutProfile(5, 5, 5))


def guarded(resolver):
    from ultimate_username.opsec.transport_factory import public_egress_transport

    inner = Recorder()
    return public_egress_transport(inner, resolver=resolver), inner


@pytest.mark.parametrize(
    "url",
    [
        "http://127.1/x",
        "http://0177.0.0.1/x",
        "http://2130706433/x",
        "http://0x7f000001/x",
        "http://[::1]/x",
        "http://169.254.169.254/latest/meta-data",
        "http://localhost/x",
        "http://printer.local/x",
    ],
)
def test_transport_refuses_non_public_destinations_without_dns(url):
    def resolver(host):
        raise AssertionError("literal and local forms must be decided without DNS")

    transport, inner = guarded(resolver)
    response = asyncio.run(transport.send(request(url)))
    assert response.error is not None and response.error.code == ErrorCode.UNSUPPORTED
    assert inner.sent == []


def test_transport_refuses_a_name_that_resolves_to_a_private_address():
    transport, inner = guarded(lambda h: ["93.184.216.34", "192.168.0.7"])
    response = asyncio.run(transport.send(request("https://rebind.example/alice")))
    assert response.error is not None and inner.sent == []


def test_transport_lets_public_hosts_and_dns_failures_through_unchanged():
    transport, inner = guarded(lambda h: ["93.184.216.34"])
    ok = asyncio.run(transport.send(request("https://example.com:8443/alice?x=1")))
    assert ok.error is None and inner.sent == ["https://example.com:8443/alice?x=1"]

    def broken(host):
        raise OSError("nxdomain")

    transport, inner = guarded(broken)
    asyncio.run(transport.send(request("https://gone.example/alice")))
    assert inner.sent == ["https://gone.example/alice"]  # the real transport reports DNS errors


def test_redirect_to_a_private_resolution_is_stopped_at_the_transport():
    # The engine issues each redirect hop as a new transport request, so the guard covers it.
    transport, inner = guarded(lambda h: ["10.0.0.1"] if h == "internal.example" else ["8.8.8.8"])
    assert asyncio.run(transport.send(request("https://public.example/a"))).error is None
    assert asyncio.run(transport.send(request("https://internal.example/a"))).error is not None
    assert inner.sent == ["https://public.example/a"]


def test_onion_hosts_skip_dns_so_a_configured_proxy_keeps_working():
    transport, inner = guarded(lambda h: (_ for _ in ()).throw(AssertionError("no DNS")))
    asyncio.run(transport.send(request("http://abcdefghijklmnop.onion/x")))
    assert inner.sent == ["http://abcdefghijklmnop.onion/x"]


# ------------------------------------------------------------------ avatars


def test_avatar_url_filter_uses_the_shared_host_check_and_standard_ports():
    from ultimate_username.identity import _public_http_url

    assert _public_http_url("https://cdn.example.com/a.png")
    assert _public_http_url("http://cdn.example.com:80/a.png")
    assert _public_http_url("https://cdn.example.com:443/a.png")
    for bad in (
        "https://cdn.example.com:8443/a.png",
        "http://127.1/a.png",
        "http://2130706433/a.png",
        "http://0177.0.0.1/a.png",
        "http://[::1]/a.png",
        "http://localhost/a.png",
        "http://x.localdomain/a.png",
        "ftp://cdn.example.com/a.png",
        "https://user:pw@cdn.example.com/a.png",
    ):
        assert not _public_http_url(bad), bad


# ------------------------------------------------------------------ ReDoS


def test_clean_name_is_not_quadratic():
    from ultimate_username.enrichment import PageMetaExtractor

    site = SiteDefinition(
        "kwai",
        "Kwai",
        "https://www.kwai.com/@{username}",
        DetectionSpec(Rule("status", statuses=(200,))),
    )
    context = SimpleNamespace(
        username="alice",
        url="https://www.kwai.com/@alice",
        profile_url="https://www.kwai.com/@alice",
        site=site,
    )
    extractor = PageMetaExtractor()
    started = time.perf_counter()
    extractor.clean_name("(@" * 200000, context)
    extractor.clean_name("(" + " " * 200000 + "@" * 1000, context)
    assert time.perf_counter() - started < 0.2


def test_clean_name_behaviour_for_normal_titles_is_unchanged():
    from ultimate_username.enrichment import PageMetaExtractor

    site = SiteDefinition(
        "kwai",
        "Kwai",
        "https://www.kwai.com/@{username}",
        DetectionSpec(Rule("status", statuses=(200,))),
    )
    context = SimpleNamespace(
        username="PublicRefA",
        url="https://www.kwai.com/@PublicRefA",
        profile_url="https://www.kwai.com/@PublicRefA",
        site=site,
    )
    cleaned = PageMetaExtractor().clean_name("Ingrid Testova (@PublicRefA) on Kwai", context)
    assert cleaned == "Ingrid Testova"


# ------------------------------------------------------------------ cooldown cap


def test_429_retry_after_cooldown_is_capped_at_the_give_up_limit():
    from ultimate_username.engine import _SearchWork
    from ultimate_username.policies import RETRY_AFTER_GIVE_UP

    calls: list[tuple[str, float]] = []
    fake = SimpleNamespace(
        runtime=None,
        origin="https://a.test:443",
        engine=SimpleNamespace(
            scheduler=SimpleNamespace(cooldown=lambda origin, until: calls.append((origin, until)))
        ),
    )
    response = TransportResponse(
        "https://a.test/x", 429, b"", (("Retry-After", "86400"),), "https://a.test/x"
    )
    now = time.monotonic()
    _SearchWork._observe_origin(fake, response, DetectionResult())
    assert len(calls) == 1
    assert calls[0][1] - now <= RETRY_AFTER_GIVE_UP + 1


# ------------------------------------------------------------------ report escaping


def test_requested_url_with_markup_in_the_host_gives_no_live_tag():
    from ultimate_username.html_report import render_report

    evil = "http://<style>x{}</style>.example/alice"
    document = {
        "username": "alice",
        "profiles": [
            {
                "site": "S",
                "status": "NOT_FOUND",
                "requested_url": evil,
                "profile_url": evil,
            },
            {
                "site": "S2",
                "status": "NOT_FOUND",
                "requested_url": 'http://a"b.example/alice',
            },
        ],
    }
    html = render_report([document])
    assert "<style>x{}" not in html
    assert "<style>" not in html.replace("<style>\n", "").split("</head>")[1]


# ------------------------------------------------------------------ health_probe aclose


def test_probe_closes_the_search_stream_generator(monkeypatch):
    from ultimate_username.engine import UsernameEngine
    from ultimate_username.health_probe import probe_health
    from ultimate_username.registry import SiteRegistry
    from ultimate_username.transport import FakeTransport

    original = UsernameEngine.search_stream
    state = {"opened": 0, "closed": 0}

    class Tracked:
        def __init__(self, generator):
            self.generator = generator

        def __aiter__(self):
            return self

        async def __anext__(self):
            return await self.generator.__anext__()

        async def aclose(self):
            state["closed"] += 1
            await self.generator.aclose()

    def wrapper(self, *args, **kwargs):
        state["opened"] += 1
        return Tracked(original(self, *args, **kwargs))

    monkeypatch.setattr(UsernameEngine, "search_stream", wrapper)
    site = SiteDefinition(
        "plain",
        "plain",
        "https://plain.test/u/{username}",
        DetectionSpec(Rule("status", statuses=(200,)), Rule("status", statuses=(404,))),
    )
    transport = FakeTransport(
        handler=lambda r, i: TransportResponse(r.url, 404, b"nope", (), r.url)
    )
    asyncio.run(probe_health(SiteRegistry([site]), transport, concurrency=1, job_timeout=10))
    assert state["opened"] >= 1 and state["closed"] == state["opened"]
