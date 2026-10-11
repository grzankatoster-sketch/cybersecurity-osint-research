"""Application-side egress guard implementing the ``Transport`` port.

Wraps any transport and refuses a request whose destination fails the egress
policy *before* the inner transport opens a socket. This is the in-process
belt that complements the standalone forward proxy (``server.py``): callers that
do not route through the proxy still get allowlist + SSRF enforcement.
"""

from __future__ import annotations

import asyncio
from urllib.parse import urlsplit

from ultimate_username.domain.models import (
    ErrorCode,
    SearchError,
    TransportRequest,
    TransportResponse,
)
from ultimate_username.opsec.policy import EgressPolicy, Resolver
from ultimate_username.opsec.server import default_resolver
from ultimate_username.transport import Transport


class GuardedTransport:
    def __init__(
        self,
        inner: Transport,
        policy: EgressPolicy,
        *,
        resolver: Resolver = default_resolver,
        dns_failure_passes: bool = False,
        unresolved_suffixes: tuple[str, ...] = (),
    ) -> None:
        """``dns_failure_passes``: a name that does not resolve is handed to ``inner`` unchanged
        (it reports the genuine DNS error); only a name resolving to a forbidden address is
        refused. ``unresolved_suffixes`` (e.g. ``.onion``) skip the check: a proxy resolves them.
        """
        self.inner = inner
        self.policy = policy
        self.resolver = resolver
        self.dns_failure_passes = dns_failure_passes
        self.unresolved_suffixes = unresolved_suffixes
        self.blocked = 0

    async def send(self, request: TransportRequest) -> TransportResponse:
        host = (urlsplit(request.url).hostname or "").lower().rstrip(".")
        if self.unresolved_suffixes and host.endswith(self.unresolved_suffixes):
            return await self.inner.send(request)
        # getaddrinfo blocks: keep it off the event loop.
        decision = await asyncio.to_thread(self.policy.check_url, request.url, self.resolver)
        if self.dns_failure_passes and decision.dns_failed:
            return await self.inner.send(request)
        if not decision.allowed:
            self.blocked += 1
            return TransportResponse(
                request.url,
                error=SearchError(
                    ErrorCode.UNSUPPORTED,
                    "transport",
                    f"blocked by egress policy: {decision.reason}",
                ),
            )
        return await self.inner.send(request)

    async def close(self) -> None:
        await self.inner.close()
