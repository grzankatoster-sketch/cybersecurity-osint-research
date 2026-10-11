"""OSINT_OPSEC: controlled egress for OSINT research traffic.

A deny-by-default egress policy (allowlist + SSRF defence), a local HTTPS
CONNECT forward proxy that enforces it, an application-side transport guard,
and redaction helpers for safe diagnostics.
"""

from __future__ import annotations

from ultimate_username.opsec.config import ProxyConfig, load
from ultimate_username.opsec.guard import GuardedTransport
from ultimate_username.opsec.policy import Decision, EgressPolicy, classify_ip
from ultimate_username.opsec.redaction import redact_headers, redact_text, redact_url
from ultimate_username.opsec.server import ForwardProxy, ProxyError
from ultimate_username.opsec.transport_factory import build_transport

__all__ = [
    "Decision",
    "EgressPolicy",
    "ForwardProxy",
    "GuardedTransport",
    "ProxyConfig",
    "ProxyError",
    "build_transport",
    "classify_ip",
    "load",
    "redact_headers",
    "redact_text",
    "redact_url",
]
