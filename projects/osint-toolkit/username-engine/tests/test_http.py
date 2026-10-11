"""Testy klienta HTTP na lokalnym serwerze 127.0.0.1 (bez internetu)."""
import asyncio

from aiohttp import web

from username_engine.http import Fetcher, retry_delay


def test_retry_delay_backoff_and_retry_after():
    assert retry_delay(0) == 1.0
    assert retry_delay(2) == 4.0
    assert retry_delay(10) == 10.0          # limit
    assert retry_delay(0, "3") == 3.0                    # Retry-After to minimum
    assert retry_delay(0, "999") is None                 # powyżej 60 s nie czekamy (ERROR „limit zapytań”)
    assert retry_delay(1, "Wed, 21 Oct 2020 07:28:00 GMT") == 2.0     # data z przeszłości -> backoff


async def _with_server(routes, coro_fn):
    app = web.Application()
    app.add_routes(routes)
    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(runner, "127.0.0.1", 0)
    await site.start()
    port = site._server.sockets[0].getsockname()[1]
    try:
        return await coro_fn(f"http://127.0.0.1:{port}")
    finally:
        await runner.cleanup()


def test_retries_after_429_then_succeeds():
    hits = {"n": 0}

    async def handler(request):
        hits["n"] += 1
        if hits["n"] == 1:
            return web.Response(status=429, headers={"Retry-After": "0"})
        return web.Response(text="ok profile")

    async def go(base):
        async with Fetcher(retries=2, jitter=False, allow_private=True) as f:
            return await f.fetch("GET", base + "/u/alice")

    r = asyncio.run(_with_server([web.get("/u/{name}", handler)], go))
    assert r.status == 200 and "ok profile" in r.text and hits["n"] == 2


def test_large_streamed_body_read_completely():
    """Strona wysyłana kawałkami (jak GOG, 481 KB) musi być przeczytana do końca, nie tylko pierwszy fragment."""
    async def big(request):
        resp = web.StreamResponse()
        await resp.prepare(request)
        for i in range(40):
            await resp.write(b"x" * 10_000)
            await asyncio.sleep(0.005)
        await resp.write(b"MARKER_NA_KONCU")
        await resp.write_eof()
        return resp

    async def go(base):
        async with Fetcher(retries=0, allow_private=True) as f:
            return await f.fetch("GET", base + "/big")

    r = asyncio.run(_with_server([web.get("/big", big)], go))
    assert len(r.text) == 400_000 + len("MARKER_NA_KONCU") and r.text.endswith("MARKER_NA_KONCU")


def test_redirect_final_url_reported():
    async def start(request):
        raise web.HTTPFound("/login")

    async def login(request):
        return web.Response(text="login")

    async def go(base):
        async with Fetcher(retries=0, allow_private=True) as f:
            return await f.fetch("GET", base + "/u/alice")

    r = asyncio.run(_with_server([web.get("/u/{name}", start), web.get("/login", login)], go))
    assert r.status == 200 and r.final_url.endswith("/login")


def test_timeout_returns_error_response():
    async def slow(request):
        await asyncio.sleep(2)
        return web.Response(text="late")

    async def go(base):
        async with Fetcher(timeout=0.3, retries=0, allow_private=True) as f:
            return await f.fetch("GET", base + "/slow")

    r = asyncio.run(_with_server([web.get("/slow", slow)], go))
    assert r.status is None and r.error == "timeout"


def test_connection_refused_is_error_not_exception():
    async def go():
        async with Fetcher(timeout=2, retries=0, allow_private=True) as f:
            return await f.fetch("GET", "http://127.0.0.1:9/")

    r = asyncio.run(go())
    assert r.status is None and r.error


# ---------------------------------------------------------------- 429: Retry-After, jedna ponowna próba

def _fake_sleep(monkeypatch):
    sleeps, real = [], asyncio.sleep

    async def fake(d):
        if d:                       # sleep(0) zna też serwer testowy aiohttp
            sleeps.append(d)
        await real(0)

    monkeypatch.setattr("username_engine.http.asyncio.sleep", fake)
    return sleeps


def test_429_respects_retry_after_then_succeeds(monkeypatch):
    sleeps = _fake_sleep(monkeypatch)
    hits = {"n": 0}

    async def handler(request):
        hits["n"] += 1
        return web.Response(status=429, headers={"Retry-After": "7"}) if hits["n"] == 1 else web.Response(text="ok")

    async def go(base):
        async with Fetcher(retries=2, jitter=False, allow_private=True) as f:
            return await f.fetch("GET", base + "/u/alice")

    r = asyncio.run(_with_server([web.get("/u/{name}", handler)], go))
    assert r.status == 200 and hits["n"] == 2 and sleeps == [7.0]


def test_429_gets_exactly_one_retry_even_with_more_retries_configured(monkeypatch):
    _fake_sleep(monkeypatch)
    hits = {"n": 0}

    async def handler(request):
        hits["n"] += 1
        return web.Response(status=429, headers={"Retry-After": "1"})

    async def go(base):
        async with Fetcher(retries=5, jitter=False, allow_private=True) as f:
            return await f.fetch("GET", base + "/u/alice")

    r = asyncio.run(_with_server([web.get("/u/{name}", handler)], go))
    assert r.status == 429 and hits["n"] == 2


def test_429_retry_after_cap_is_30_seconds(monkeypatch):
    sleeps = _fake_sleep(monkeypatch)
    hits = {"n": 0}

    async def handler(request):
        hits["n"] += 1
        return web.Response(status=429, headers={"Retry-After": request.query["ra"]})

    async def go(base, ra):
        async with Fetcher(retries=2, jitter=True, allow_private=True) as f:
            return await f.fetch("GET", f"{base}/u/alice?ra={ra}")

    r = asyncio.run(_with_server([web.get("/u/{name}", handler)], lambda b: go(b, 31)))
    assert r.status == 429 and hits["n"] == 1 and sleeps == []            # 31 s > limit: bez czekania i bez ponowienia
    hits["n"] = 0
    r = asyncio.run(_with_server([web.get("/u/{name}", handler)], lambda b: go(b, 30)))
    assert r.status == 429 and hits["n"] == 2 and sleeps == [30.0]        # dokładnie 30 s: czekamy, jitter nie przekracza limitu


def test_other_retryable_statuses_keep_full_retry_budget(monkeypatch):
    _fake_sleep(monkeypatch)
    hits = {"n": 0}

    async def handler(request):
        hits["n"] += 1
        return web.Response(status=503)

    async def go(base):
        async with Fetcher(retries=2, jitter=False, allow_private=True) as f:
            return await f.fetch("GET", base + "/u/alice")

    r = asyncio.run(_with_server([web.get("/u/{name}", handler)], go))
    assert r.status == 503 and hits["n"] == 3
