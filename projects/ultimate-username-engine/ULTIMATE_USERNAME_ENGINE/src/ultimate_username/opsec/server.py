"""OSINT_OPSEC forward proxy: a controlled local HTTPS CONNECT tunnel.

Security posture (deny by default):

* Binds to loopback unless an auth token is configured (never an open proxy).
* Requires ``Proxy-Authorization: Bearer <token>`` when a token is set.
* Validates every CONNECT target against :class:`EgressPolicy`
  (allowlist + port + SSRF defence) *before* any outbound socket is opened.
* Connects to the already-validated resolved IP, closing the DNS-rebinding window.
* Chains through a configured upstream; with ``fail_closed`` an unreachable
  upstream stops traffic instead of silently going direct.
* Diagnostics are redacted - no tokens, cookies or ``Authorization`` material.

This is a native implementation; it contains no third-party proxy code.
"""

from __future__ import annotations

import asyncio
import hmac
import logging
import socket
from collections import Counter
from dataclasses import dataclass
from urllib.parse import urlsplit

from ultimate_username.opsec.config import ProxyConfig
from ultimate_username.opsec.policy import EgressPolicy, Resolver

_MAX_HEADER_BYTES = 16 * 1024
_LOG = logging.getLogger("ultimate_username.opsec.proxy")


def default_resolver(host: str) -> list[str]:
    infos = socket.getaddrinfo(host, None, proto=socket.IPPROTO_TCP)
    return [str(info[4][0]) for info in infos]


@dataclass(slots=True)
class _Request:
    method: str
    target: str
    headers: dict[str, str]


class ProxyError(Exception):
    """Raised with an HTTP status to return to the proxy client."""

    def __init__(self, status: int, message: str) -> None:
        super().__init__(message)
        self.status = status
        self.message = message


class ForwardProxy:
    def __init__(
        self,
        config: ProxyConfig,
        *,
        policy: EgressPolicy | None = None,
        resolver: Resolver = default_resolver,
    ) -> None:
        self.config = config
        self.policy = policy or config.policy()
        self.resolver = resolver
        self.stats: Counter[str] = Counter()
        self._server: asyncio.Server | None = None
        self._active: set[asyncio.StreamWriter] = set()

    @property
    def port(self) -> int:
        if self._server is None:
            raise RuntimeError("proxy not started")
        return int(self._server.sockets[0].getsockname()[1])

    async def start(self) -> None:
        problems = self.config.validate()
        if problems:
            raise ProxyError(500, "; ".join(problems))
        self._server = await asyncio.start_server(
            self._handle, self.config.bind_host, self.config.bind_port
        )

    async def stop(self) -> None:
        if self._server is not None:
            self._server.close()
            for writer in list(self._active):
                writer.close()
            try:
                await asyncio.wait_for(self._server.wait_closed(), timeout=5)
            except TimeoutError:
                pass
            self._server = None

    async def serve_forever(self) -> None:
        if self._server is None:
            await self.start()
        server = self._server
        if server is None:  # start() always sets it; defensive for type-narrowing
            raise RuntimeError("proxy failed to start")
        async with server:
            await server.serve_forever()

    # -- connection handling -------------------------------------------------

    async def _handle(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        self.stats["connections"] += 1
        self._active.add(writer)
        try:
            request = await self._read_request(reader)
            if request.method == "GET" and request.target.rstrip("/").endswith("healthz"):
                await self._respond(writer, 200, "OK", body=b"opsec-proxy ok\n")
                return
            if request.method != "CONNECT":
                raise ProxyError(405, "only CONNECT is supported")
            self._authenticate(request)
            host, port = self._split_authority(request.target)
            await self._tunnel(reader, writer, host, port)
        except ProxyError as exc:
            self.stats[f"status_{exc.status}"] += 1
            if exc.status == 403:
                self.stats["denied"] += 1
            if exc.status == 407:
                self.stats["auth_failures"] += 1
            _LOG.warning("proxy rejected request: %s %s", exc.status, exc.message)
            await self._respond(writer, exc.status, exc.message)
        except (asyncio.IncompleteReadError, ConnectionError):
            pass
        finally:
            self._active.discard(writer)
            writer.close()
            try:
                await writer.wait_closed()
            except (ConnectionError, OSError):
                pass

    async def _read_request(self, reader: asyncio.StreamReader) -> _Request:
        try:
            raw = await asyncio.wait_for(
                reader.readuntil(b"\r\n\r\n"), timeout=self.config.timeout
            )
        except asyncio.LimitOverrunError as exc:
            raise ProxyError(431, "request header too large") from exc
        except TimeoutError as exc:
            raise ProxyError(408, "request timeout") from exc
        if len(raw) > _MAX_HEADER_BYTES:
            raise ProxyError(431, "request header too large")
        lines = raw.decode("latin-1").split("\r\n")
        try:
            method, target, _ = lines[0].split(" ", 2)
        except ValueError as exc:
            raise ProxyError(400, "malformed request line") from exc
        headers: dict[str, str] = {}
        for line in lines[1:]:
            if not line:
                continue
            name, _, value = line.partition(":")
            headers[name.strip().lower()] = value.strip()
        return _Request(method.upper(), target, headers)

    def _authenticate(self, request: _Request) -> None:
        token = self.config.auth_token
        if not token:
            return
        provided = request.headers.get("proxy-authorization", "")
        scheme, _, credential = provided.partition(" ")
        if scheme.lower() != "bearer" or not hmac.compare_digest(credential, token):
            raise ProxyError(407, "proxy authentication required")

    @staticmethod
    def _split_authority(authority: str) -> tuple[str, int]:
        host, sep, port_text = authority.rpartition(":")
        if not sep:
            raise ProxyError(400, "CONNECT target must be host:port")
        host = host.strip("[]")
        try:
            port = int(port_text)
        except ValueError as exc:
            raise ProxyError(400, "invalid port") from exc
        return host, port

    async def _tunnel(
        self,
        client_reader: asyncio.StreamReader,
        client_writer: asyncio.StreamWriter,
        host: str,
        port: int,
    ) -> None:
        decision = self.policy.check_target(host, port, self.resolver)
        if not decision.allowed:
            raise ProxyError(403, f"destination denied: {decision.reason}")
        self.stats["allowed"] += 1

        upstream = self.config.upstream_url
        try:
            if upstream:
                remote_reader, remote_writer = await self._connect_upstream(upstream, host, port)
            else:
                target_ip = decision.resolved_ips[0] if decision.resolved_ips else host
                remote_reader, remote_writer = await asyncio.wait_for(
                    asyncio.open_connection(target_ip, port), timeout=self.config.timeout
                )
        except (TimeoutError, ConnectionError, OSError) as exc:
            if self.config.fail_closed:
                raise ProxyError(502, "upstream unavailable (fail-closed)") from exc
            raise ProxyError(502, "destination unavailable") from exc

        # A CONNECT 200 must be a bare status line; the socket is now a raw tunnel.
        client_writer.write(b"HTTP/1.1 200 Connection Established\r\n\r\n")
        await client_writer.drain()
        await self._splice(client_reader, client_writer, remote_reader, remote_writer)

    async def _connect_upstream(
        self, upstream: str, host: str, port: int
    ) -> tuple[asyncio.StreamReader, asyncio.StreamWriter]:
        parts = urlsplit(upstream)
        up_host = parts.hostname or ""
        up_port = parts.port or (443 if parts.scheme == "https" else 8080)
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(up_host, up_port), timeout=self.config.timeout
        )
        writer.write(
            f"CONNECT {host}:{port} HTTP/1.1\r\nHost: {host}:{port}\r\n\r\n".encode("latin-1")
        )
        await writer.drain()
        status_line = await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), self.config.timeout)
        if b" 200 " not in status_line.split(b"\r\n")[0]:
            writer.close()
            raise ProxyError(502, "upstream refused CONNECT")
        return reader, writer

    @staticmethod
    async def _splice(
        client_reader: asyncio.StreamReader,
        client_writer: asyncio.StreamWriter,
        remote_reader: asyncio.StreamReader,
        remote_writer: asyncio.StreamWriter,
    ) -> None:
        async def pump(src: asyncio.StreamReader, dst: asyncio.StreamWriter) -> None:
            try:
                while not src.at_eof():
                    chunk = await src.read(65536)
                    if not chunk:
                        break
                    dst.write(chunk)
                    await dst.drain()
            except (ConnectionError, OSError):
                pass
            finally:
                if dst.can_write_eof():
                    try:
                        dst.write_eof()
                    except (ConnectionError, OSError):
                        pass

        await asyncio.gather(
            pump(client_reader, remote_writer),
            pump(remote_reader, client_writer),
        )
        remote_writer.close()

    @staticmethod
    async def _respond(
        writer: asyncio.StreamWriter, status: int, message: str, *, body: bytes = b""
    ) -> None:
        reason = message.replace("\r", " ").replace("\n", " ")
        head = f"HTTP/1.1 {status} {reason}\r\nContent-Length: {len(body)}\r\nConnection: close\r\n"
        if status == 407:
            head += 'Proxy-Authenticate: Bearer realm="opsec"\r\n'
        head += "\r\n"
        try:
            writer.write(head.encode("latin-1") + body)
            await writer.drain()
        except (ConnectionError, OSError):
            pass
