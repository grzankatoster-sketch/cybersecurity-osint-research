import asyncio
import gzip
import ssl
from contextlib import asynccontextmanager
from pathlib import Path

import pytest
from aiohttp import web

from ultimate_username.domain.models import (
    DetectionSpec,
    ErrorCode,
    RedirectPolicy,
    RetryPolicy,
    Rule,
    SiteDefinition,
    TimeoutProfile,
    TransportRequest,
    Verdict,
)
from ultimate_username.engine import UsernameEngine
from ultimate_username.http_transport import AiohttpTransport, HttpConfig
from ultimate_username.registry import SiteRegistry

pytestmark = pytest.mark.local_http


@asynccontextmanager
async def server(handler, ssl_context=None):
    app = web.Application()
    app.router.add_route("*", "/{tail:.*}", handler)
    runner = web.AppRunner(app, shutdown_timeout=0.1)
    await runner.setup()
    listener = web.TCPSite(runner, "127.0.0.1", 0, ssl_context=ssl_context)
    await listener.start()
    port = runner.addresses[0][1]
    try:
        yield f"{'https' if ssl_context else 'http'}://127.0.0.1:{port}"
    finally:
        await runner.cleanup()


def test_pool_reused_redirect_not_automatic_and_cookies_disabled():
    async def run():
        connections, cookies = [], []

        async def handler(request):
            connections.append(request.transport)
            cookies.append(request.headers.get("Cookie"))
            return web.Response(
                status=302, headers={"Location": "/final", "Set-Cookie": "secret=x"}
            )

        async with server(handler) as base, AiohttpTransport() as transport:
            for _ in range(3):
                response = await transport.send(TransportRequest(base + "/start"))
                assert response.status == 302
                assert response.final_url == base + "/start"
                assert response.header("Location") == "/final"
            assert transport.sessions_created == 1
            assert len({id(c) for c in connections}) == 1
            assert cookies == [None] * 3
        assert transport.closed

    asyncio.run(run())


@pytest.mark.parametrize("compressed", [False, True])
def test_decoded_body_limit(compressed):
    async def run():
        async def handler(request):
            data = b"x" * 1000000
            return web.Response(
                body=gzip.compress(data) if compressed else data,
                headers={"Content-Encoding": "gzip"} if compressed else {},
            )

        async with server(handler) as base, AiohttpTransport() as transport:
            result = await transport.send(TransportRequest(base, body_limit=512))
            assert len(result.body) == 512
            assert result.error.code == ErrorCode.BODY_LIMIT
            assert not result.body_complete

    asyncio.run(run())


def test_read_timeout_and_cancel_cleanup():
    async def run():
        async def handler(request):
            await asyncio.sleep(0.1)
            return web.Response(text="late")

        async with server(handler) as base, AiohttpTransport() as transport:
            result = await transport.send(
                TransportRequest(base, timeout=TimeoutProfile(read=0.005))
            )
            assert result.error.code == ErrorCode.READ_TIMEOUT
            task = asyncio.create_task(transport.send(TransportRequest(base)))
            await asyncio.sleep(0.005)
            task.cancel()
            with pytest.raises(asyncio.CancelledError):
                await task
        assert transport.closed

    asyncio.run(run())


def test_real_engine_redirect_retry_and_decoding():
    async def run():
        calls = []

        async def handler(request):
            calls.append(request.path)
            if request.path == "/alice":
                return web.Response(status=302, headers={"Location": "/profile/alice"})
            if calls.count(request.path) == 1:
                return web.Response(status=429, headers={"Retry-After": "0"})
            return web.Response(
                body=gzip.compress(b"profile alice"), headers={"Content-Encoding": "gzip"}
            )

        async with server(handler) as base:
            definition = SiteDefinition(
                "local",
                "Local",
                base + "/profile/{username}",
                DetectionSpec(
                    present=Rule("message", "profile"), binding=Rule("redirect", "{profile_url}")
                ),
                probe_url=base + "/{username}",
                redirects=RedirectPolicy(True),
                retry=RetryPolicy(2, base_delay=0, max_delay=0),
            )
            transport = AiohttpTransport()
            async with UsernameEngine(SiteRegistry([definition]), transport) as engine:
                result = (await engine.search("alice"))[0]
                assert result.detection.verdict == Verdict.FOUND
                assert [a.status for a in result.attempts] == [302, 429, 200]
                assert result.final_url == base + "/profile/alice"
            assert transport.closed

    asyncio.run(run())


def test_untrusted_tls_certificate_is_error_without_verdict():
    fixtures = Path(__file__).resolve().parents[1] / "fixtures"
    if not (fixtures / "untrusted-test-key.pem").is_file():
        pytest.skip(
            "self-signed test certificate not present (*.pem is git-ignored); "
            "see tests/fixtures/README.md"
        )

    async def run():
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(
            fixtures / "untrusted-test-cert.pem", fixtures / "untrusted-test-key.pem"
        )

        async def handler(request):
            return web.Response(text="profile")

        async with server(handler, context) as base, AiohttpTransport() as transport:
            result = await transport.send(TransportRequest(base))
            assert result.error.code == ErrorCode.TLS_ERROR
            assert result.status is None

    asyncio.run(run())


def test_onion_without_configured_transport_does_not_resolve():
    async def run():
        async with AiohttpTransport() as transport:
            result = await transport.send(TransportRequest("http://example.onion/alice"))
            assert result.error.code == ErrorCode.UNSUPPORTED
            assert transport.sessions_created == 0

    asyncio.run(run())


def test_explicit_http_proxy_and_separate_context_pools():
    async def run():
        paths = []

        async def proxy_handler(request):
            paths.append(request.raw_path)
            return web.Response(text="proxy fixture")

        async with server(proxy_handler) as proxy:
            async with AiohttpTransport(HttpConfig(proxy=proxy)) as transport:
                for context in ("public", "isolated"):
                    result = await transport.send(
                        TransportRequest(
                            "http://unresolved.example.invalid/alice", context_id=context
                        )
                    )
                    assert result.status == 200
                    assert result.body == b"proxy fixture"
                assert transport.sessions_created == 2
        assert paths == ["http://unresolved.example.invalid/alice"] * 2

    asyncio.run(run())
