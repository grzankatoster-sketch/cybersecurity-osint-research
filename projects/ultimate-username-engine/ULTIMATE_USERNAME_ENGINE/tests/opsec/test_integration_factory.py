"""Integration contract: one transport layer, no silent direct fallback (P5)."""

from __future__ import annotations

import asyncio

import pytest

from ultimate_username.domain.models import (
    HttpMethod,
    TimeoutProfile,
    TransportRequest,
    TransportResponse,
)
from ultimate_username.opsec.config import ProxyConfig
from ultimate_username.opsec.guard import GuardedTransport
from ultimate_username.opsec.server import ProxyError
from ultimate_username.opsec.transport_factory import build_transport


class RecordingTransport:
    def __init__(self) -> None:
        self.sent: list[str] = []

    async def send(self, request: TransportRequest) -> TransportResponse:
        self.sent.append(request.url)
        return TransportResponse(request.url, status=200)

    async def close(self) -> None:  # pragma: no cover
        pass


def _req(url: str) -> TransportRequest:
    return TransportRequest(url=url, method=HttpMethod.GET, timeout=TimeoutProfile(5, 5, 5))


def test_disabled_returns_inner_unchanged() -> None:
    inner = RecordingTransport()
    assert build_transport(ProxyConfig(enabled=False), inner) is inner


def test_mandatory_proxy_not_routed_refuses_to_build_direct() -> None:
    cfg = ProxyConfig(enabled=True, fail_closed=True, allowed_hosts=frozenset({"github.com"}))
    with pytest.raises(ProxyError):
        build_transport(cfg, RecordingTransport(), inner_routes_through_proxy=False)


def test_enabled_routed_wraps_in_guard_and_enforces_policy() -> None:
    cfg = ProxyConfig(enabled=True, fail_closed=True, allowed_hosts=frozenset({"github.com"}))
    inner = RecordingTransport()
    transport = build_transport(
        cfg, inner, inner_routes_through_proxy=True, resolver=lambda h: ["140.82.121.6"]
    )
    assert isinstance(transport, GuardedTransport)

    blocked = asyncio.run(transport.send(_req("https://evil.example.com/")))
    assert blocked.error is not None
    assert inner.sent == []

    allowed = asyncio.run(transport.send(_req("https://api.github.com/x")))
    assert allowed.error is None
    assert inner.sent == ["https://api.github.com/x"]


def test_dns_rebinding_blocked_when_resolution_includes_forbidden_ip() -> None:
    # A rebinding-style answer (public + internal) must be rejected as a whole,
    # not partially accepted.
    cfg = ProxyConfig(
        enabled=True,
        fail_closed=False,
        require_allowlist=False,
        allowed_hosts=frozenset(),
        allowed_ports=frozenset(),
    )
    inner = RecordingTransport()
    transport = build_transport(
        cfg,
        inner,
        inner_routes_through_proxy=True,
        resolver=lambda h: ["8.8.8.8", "169.254.169.254"],
    )
    result = asyncio.run(transport.send(_req("https://rebind.example.com/")))
    assert result.error is not None
    assert inner.sent == []
