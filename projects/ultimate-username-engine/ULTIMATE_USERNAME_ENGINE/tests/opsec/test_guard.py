"""Red-team: the application-side guard blocks before the inner transport runs."""

from __future__ import annotations

import asyncio

from ultimate_username.domain.models import (
    ErrorCode,
    HttpMethod,
    TimeoutProfile,
    TransportRequest,
    TransportResponse,
)
from ultimate_username.opsec.guard import GuardedTransport
from ultimate_username.opsec.policy import EgressPolicy


class RecordingTransport:
    def __init__(self) -> None:
        self.sent: list[str] = []

    async def send(self, request: TransportRequest) -> TransportResponse:
        self.sent.append(request.url)
        return TransportResponse(request.url, status=200)

    async def close(self) -> None:  # pragma: no cover - trivial
        pass


def _request(url: str) -> TransportRequest:
    return TransportRequest(url=url, method=HttpMethod.GET, timeout=TimeoutProfile(5, 5, 5))


def test_guard_blocks_disallowed_host_without_calling_inner() -> None:
    inner = RecordingTransport()
    guard = GuardedTransport(
        inner,
        EgressPolicy(allowed_hosts=frozenset({"github.com"}), allowed_ports=frozenset({443})),
        resolver=lambda h: ["140.82.121.6"],
    )
    response = asyncio.run(guard.send(_request("https://evil.example.com/")))
    assert response.error is not None
    assert response.error.code == ErrorCode.UNSUPPORTED
    assert inner.sent == []
    assert guard.blocked == 1


def test_guard_blocks_ssrf_to_metadata() -> None:
    inner = RecordingTransport()
    guard = GuardedTransport(
        inner,
        EgressPolicy(require_allowlist=False, allowed_ports=frozenset()),
        resolver=lambda h: ["169.254.169.254"],
    )
    response = asyncio.run(guard.send(_request("https://metadata.example.com/")))
    assert response.error is not None
    assert inner.sent == []


def test_guard_allows_permitted_destination() -> None:
    inner = RecordingTransport()
    guard = GuardedTransport(
        inner,
        EgressPolicy(allowed_hosts=frozenset({"github.com"}), allowed_ports=frozenset({443})),
        resolver=lambda h: ["140.82.121.6"],
    )
    response = asyncio.run(guard.send(_request("https://api.github.com/users/x")))
    assert response.error is None
    assert inner.sent == ["https://api.github.com/users/x"]
