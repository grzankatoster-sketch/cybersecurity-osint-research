"""Pooled aiohttp adapter: exactly one hop, bounded decoded body, explicit cleanup."""

from __future__ import annotations

import asyncio
import socket
import zlib
from dataclasses import dataclass, replace
from time import perf_counter
from urllib.parse import urlsplit

import aiohttp

from ultimate_username.domain.models import (
    ErrorCode,
    Headers,
    SearchError,
    Timing,
    TransportRequest,
    TransportResponse,
)
from ultimate_username.domain.urls import origin


def _classify_exception(exc: Exception) -> SearchError:
    if isinstance(exc, aiohttp.ConnectionTimeoutError):
        return SearchError(ErrorCode.CONNECT_TIMEOUT, "connect", "Connect deadline exceeded", True)
    if isinstance(exc, aiohttp.SocketTimeoutError):
        return SearchError(ErrorCode.READ_TIMEOUT, "read", "Read deadline exceeded", True)
    if isinstance(exc, TimeoutError):
        return SearchError(ErrorCode.ATTEMPT_TIMEOUT, "transport", "Total deadline exceeded", True)
    if isinstance(exc, (aiohttp.ClientConnectorCertificateError, aiohttp.ClientSSLError)):
        return SearchError(ErrorCode.TLS_ERROR, "tls", "TLS verification or handshake failed")
    if isinstance(exc, aiohttp.ClientConnectorDNSError):
        temporary = (
            isinstance(exc.os_error, socket.gaierror) and exc.os_error.errno == socket.EAI_AGAIN
        )
        return SearchError(
            ErrorCode.DNS_TEMPORARY if temporary else ErrorCode.DNS_NOT_FOUND,
            "dns",
            "DNS resolution failed",
            temporary,
        )
    if isinstance(exc, (aiohttp.ClientConnectionResetError, aiohttp.ServerDisconnectedError)):
        return SearchError(ErrorCode.CONNECTION_RESET, "read", "Connection reset", True)
    if isinstance(exc, aiohttp.ClientConnectorError):
        return SearchError(ErrorCode.CONNECTION_FAILED, "connect", "Connection failed", True)
    if isinstance(exc, (aiohttp.ClientPayloadError, zlib.error, ValueError)):
        return SearchError(ErrorCode.PARSE_ERROR, "response", "Malformed response payload")
    return SearchError(ErrorCode.CONNECTION_FAILED, "transport", type(exc).__name__)


def classify_exception(exc: Exception) -> SearchError:
    return replace(_classify_exception(exc), cause_type=type(exc).__name__)


@dataclass(frozen=True, slots=True)
class HttpConfig:
    connection_limit: int = 100
    proxy: str | None = None
    max_contexts: int = 16
    user_agent: str = "UltimateUsernameEngine/0.1"

    def __post_init__(self) -> None:
        if self.connection_limit < 1 or self.max_contexts < 1:
            raise ValueError("HTTP limits must be positive")
        if self.proxy and urlsplit(self.proxy).scheme not in ("http", "https", "socks5", "socks4"):
            raise ValueError("Unsupported proxy scheme")
        if "\n" in self.user_agent or "\r" in self.user_agent:
            raise ValueError("Invalid User-Agent")


class AiohttpTransport:
    def __init__(self, config: HttpConfig | None = None) -> None:
        self.config = config or HttpConfig()
        self._sessions: dict[str, aiohttp.ClientSession] = {}
        self.closed = False
        self.sessions_created = 0

    def _session(self, context_id: str) -> aiohttp.ClientSession:
        if self.closed:
            raise RuntimeError("HTTP transport closed")
        if context_id not in self._sessions:
            if len(self._sessions) >= self.config.max_contexts:
                raise ValueError("HTTP context budget exhausted")
            connector: aiohttp.BaseConnector
            proxy = self.config.proxy
            if proxy and urlsplit(proxy).scheme.startswith("socks"):
                from aiohttp_socks import ProxyConnector

                connector = ProxyConnector.from_url(proxy, limit=self.config.connection_limit)
            else:
                connector = aiohttp.TCPConnector(
                    limit=self.config.connection_limit, ttl_dns_cache=60
                )
            self._sessions[context_id] = aiohttp.ClientSession(
                connector=connector,
                cookie_jar=aiohttp.DummyCookieJar(),
                trust_env=False,
                auto_decompress=False,
                headers={"User-Agent": self.config.user_agent, "Accept-Encoding": "gzip, deflate"},
            )
            self.sessions_created += 1
        return self._sessions[context_id]

    async def send(self, request: TransportRequest) -> TransportResponse:
        origin(request.url)
        if (urlsplit(request.url).hostname or "").endswith(".onion") and not self.config.proxy:
            return TransportResponse(
                request.url,
                error=SearchError(
                    ErrorCode.UNSUPPORTED, "transport", "Onion host requires an explicit proxy"
                ),
            )
        session = self._session(request.context_id)
        started = perf_counter()
        status: int | None = None
        headers: Headers = ()
        final_url = request.url
        body = bytearray()
        first_byte: float | None = None
        received_bytes = 0
        timeout = aiohttp.ClientTimeout(
            total=request.timeout.total,
            connect=request.timeout.connect,
            sock_connect=request.timeout.connect,
            sock_read=request.timeout.read,
        )
        proxy = self.config.proxy
        if proxy and urlsplit(proxy).scheme.startswith("socks"):
            proxy = None
        try:
            async with session.request(
                request.method.value,
                request.url,
                headers=request.headers,
                data=request.body,
                timeout=timeout,
                allow_redirects=False,
                proxy=proxy,
            ) as response:
                status = response.status
                headers = tuple(response.headers.items())
                final_url = str(response.url)
                encoding = response.headers.get("Content-Encoding", "").lower().strip()
                if encoding not in ("", "identity", "gzip", "deflate"):
                    raise ValueError("Unsupported Content-Encoding")
                decompressor = (
                    zlib.decompressobj(
                        16 + zlib.MAX_WBITS if encoding == "gzip" else zlib.MAX_WBITS
                    )
                    if encoding in ("gzip", "deflate")
                    else None
                )
                async for chunk in response.content.iter_chunked(8192):
                    received_bytes += len(chunk)
                    if first_byte is None:
                        first_byte = perf_counter() - started
                    remaining = request.body_limit + 1 - len(body)
                    decoded = decompressor.decompress(chunk, remaining) if decompressor else chunk
                    body.extend(decoded[:remaining])
                    if len(body) > request.body_limit:
                        response.close()
                        return TransportResponse(
                            request.url,
                            status,
                            bytes(body[: request.body_limit]),
                            headers,
                            final_url,
                            timing=Timing(perf_counter() - started, first_byte=first_byte),
                            error=SearchError(ErrorCode.BODY_LIMIT, "read", "Body limit exceeded"),
                            body_complete=False,
                            backend="aiohttp",
                            received_bytes=received_bytes,
                        )
                if decompressor and (not decompressor.eof or decompressor.unused_data):
                    raise ValueError("Truncated or concatenated compressed response")
            return TransportResponse(
                request.url,
                status,
                bytes(body),
                headers,
                final_url,
                timing=Timing(perf_counter() - started, first_byte=first_byte),
                backend="aiohttp",
                received_bytes=received_bytes,
            )
        except asyncio.CancelledError:
            raise
        except (aiohttp.ClientError, TimeoutError, zlib.error, ValueError) as exc:
            return TransportResponse(
                request.url,
                status,
                bytes(body),
                headers,
                final_url,
                timing=Timing(perf_counter() - started, first_byte=first_byte),
                error=classify_exception(exc),
                body_complete=False,
                backend="aiohttp",
                received_bytes=received_bytes,
            )

    async def close(self) -> None:
        if not self.closed:
            self.closed = True
            for session in self._sessions.values():
                await session.close()
            self._sessions.clear()

    async def __aenter__(self) -> AiohttpTransport:
        return self

    async def __aexit__(self, exc_type: object, exc: object, tb: object) -> None:
        await self.close()
