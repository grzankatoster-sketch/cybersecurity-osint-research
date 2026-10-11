"""Transport port and deterministic, bounded-observation offline implementation."""

from __future__ import annotations

import asyncio
from collections import Counter
from collections.abc import Callable, Mapping, Sequence
from dataclasses import replace
from time import perf_counter
from typing import Protocol

from ultimate_username.domain.models import Timing, TransportRequest, TransportResponse
from ultimate_username.domain.urls import origin


class Transport(Protocol):
    async def send(self, request: TransportRequest) -> TransportResponse: ...
    async def close(self) -> None: ...


class FakeTransport:
    def __init__(
        self,
        responses: Mapping[str, Sequence[TransportResponse]] | None = None,
        *,
        handler: Callable[[TransportRequest, int], TransportResponse] | None = None,
        delay: float = 0,
        history_limit: int = 100,
    ) -> None:
        self.responses = {k: tuple(v) for k, v in (responses or {}).items()}
        self.handler = handler
        self.delay = delay
        self.history_limit = history_limit
        self.requests: list[TransportRequest] = []
        self.calls: Counter[str] = Counter()
        self.origins: Counter[str] = Counter()
        self.peak_origins: Counter[str] = Counter()
        self.active = self.peak_active = self.total = 0
        self.closed = False

    async def send(self, request: TransportRequest) -> TransportResponse:
        if self.closed:
            raise RuntimeError("Transport closed")
        started = perf_counter()
        host = origin(request.url)
        self.active += 1
        self.total += 1
        self.origins[host] += 1
        self.peak_active = max(self.peak_active, self.active)
        self.peak_origins[host] = max(self.peak_origins[host], self.origins[host])
        # No unbounded per-URL bookkeeping in benchmark handler mode.
        index = self.calls[request.url] if self.handler is None else self.total - 1
        if self.handler is None:
            self.calls[request.url] += 1
        if len(self.requests) < self.history_limit:
            self.requests.append(request)
        try:
            await asyncio.sleep(self.delay)
            if self.handler:
                result = self.handler(request, index)
            else:
                sequence = self.responses[request.url]
                result = sequence[min(index, len(sequence) - 1)]
            return replace(
                result,
                requested_url=request.url,
                final_url=result.final_url or request.url,
                timing=Timing(perf_counter() - started),
                backend="fake",
            )
        finally:
            self.active -= 1
            self.origins[host] -= 1

    async def close(self) -> None:
        self.closed = True
