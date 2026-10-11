"""Red-team: the forward proxy end to end (phase 5.A / 5.B).

All targets are loopback or policy-denied, so nothing leaves the host. The
autouse ``block_external_network`` fixture guarantees it.
"""

from __future__ import annotations

import asyncio
import socket
from collections.abc import Awaitable, Callable
from typing import TypeVar

from ultimate_username.opsec.config import ProxyConfig
from ultimate_username.opsec.policy import EgressPolicy
from ultimate_username.opsec.server import ForwardProxy

T = TypeVar("T")

PERMISSIVE = EgressPolicy(
    require_allowlist=False, block_private_ips=False, allowed_ports=frozenset()
)


def _run(coro: Awaitable[T]) -> T:
    return asyncio.run(coro)  # type: ignore[arg-type]


def _free_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


async def _echo_server() -> asyncio.AbstractServer:
    async def handle(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        data = await reader.read(64)
        writer.write(data)
        await writer.drain()
        writer.close()

    return await asyncio.start_server(handle, "127.0.0.1", 0)


async def _connect(
    port: int, authority: str, auth: str | None = None
) -> tuple[asyncio.StreamReader, asyncio.StreamWriter, bytes]:
    reader, writer = await asyncio.open_connection("127.0.0.1", port)
    request = f"CONNECT {authority} HTTP/1.1\r\nHost: {authority}\r\n"
    if auth is not None:
        request += f"Proxy-Authorization: {auth}\r\n"
    request += "\r\n"
    writer.write(request.encode("latin-1"))
    await writer.drain()
    # Consume the whole header block so the tunnel body is not polluted.
    header = await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), timeout=5)
    status_line = header.split(b"\r\n", 1)[0]
    return reader, writer, status_line


async def _with_proxy(
    config: ProxyConfig,
    policy: EgressPolicy,
    body: Callable[[ForwardProxy], Awaitable[T]],
    resolver: Callable[[str], list[str]] = lambda h: ["8.8.8.8"],
) -> T:
    proxy = ForwardProxy(config, policy=policy, resolver=resolver)
    await proxy.start()
    try:
        return await body(proxy)
    finally:
        await proxy.stop()


def test_tunnel_to_loopback_target_succeeds() -> None:
    async def scenario() -> None:
        echo = await _echo_server()
        echo_port = echo.sockets[0].getsockname()[1]
        try:

            async def body(proxy: ForwardProxy) -> None:
                reader, writer, status = await _connect(proxy.port, f"127.0.0.1:{echo_port}")
                assert b"200" in status
                writer.write(b"ping")
                await writer.drain()
                assert await asyncio.wait_for(reader.read(4), timeout=5) == b"ping"
                writer.close()

            await _with_proxy(
                ProxyConfig(bind_port=0, require_allowlist=False),
                PERMISSIVE,
                body,
                resolver=lambda h: ["127.0.0.1"],
            )
        finally:
            echo.close()
            await echo.wait_closed()

    _run(scenario())


def test_disallowed_host_is_forbidden() -> None:
    async def body(proxy: ForwardProxy) -> None:
        _, writer, status = await _connect(proxy.port, "evil.com:443")
        assert b"403" in status
        writer.close()

    _run(
        _with_proxy(
            ProxyConfig(bind_port=0, allowed_hosts=frozenset({"example.com"})),
            EgressPolicy(allowed_hosts=frozenset({"example.com"}), allowed_ports=frozenset({443})),
            body,
        )
    )
    # the proxy must not have attempted any outbound connection: 403 not 502


def test_ssrf_to_metadata_is_forbidden_before_connect() -> None:
    async def body(proxy: ForwardProxy) -> None:
        _, writer, status = await _connect(proxy.port, "metadata.example.com:443")
        assert b"403" in status  # policy-denied, never a 502 connect failure
        assert proxy.stats["denied"] == 1
        writer.close()

    _run(
        _with_proxy(
            ProxyConfig(bind_port=0, require_allowlist=False),
            EgressPolicy(require_allowlist=False, allowed_ports=frozenset()),
            body,
            resolver=lambda h: ["169.254.169.254"],
        )
    )


def test_missing_auth_is_rejected() -> None:
    async def body(proxy: ForwardProxy) -> None:
        _, writer, status = await _connect(proxy.port, "8.8.8.8:443")
        assert b"407" in status
        writer.close()

    _run(
        _with_proxy(
            ProxyConfig(bind_port=0, require_allowlist=False, auth_token="secret"),
            PERMISSIVE,
            body,
        )
    )


def test_correct_auth_allows_tunnel() -> None:
    async def scenario() -> None:
        echo = await _echo_server()
        echo_port = echo.sockets[0].getsockname()[1]
        try:

            async def body(proxy: ForwardProxy) -> None:
                _, writer, status = await _connect(
                    proxy.port, f"127.0.0.1:{echo_port}", auth="Bearer secret"
                )
                assert b"200" in status
                writer.close()

            await _with_proxy(
                ProxyConfig(bind_port=0, require_allowlist=False, auth_token="secret"),
                PERMISSIVE,
                body,
                resolver=lambda h: ["127.0.0.1"],
            )
        finally:
            echo.close()
            await echo.wait_closed()

    _run(scenario())


def test_unreachable_upstream_fails_closed() -> None:
    dead = _free_port()

    async def body(proxy: ForwardProxy) -> None:
        _, writer, status = await _connect(proxy.port, "example.com:443")
        assert b"502" in status  # fail-closed: no silent direct connection
        writer.close()

    _run(
        _with_proxy(
            ProxyConfig(
                bind_port=0,
                require_allowlist=False,
                fail_closed=True,
                upstream_url=f"http://127.0.0.1:{dead}",
            ),
            PERMISSIVE,
            body,
        )
    )
