"""osint_connectors — własny, clean-room rdzeń konektorów OSINT.

Publiczne API rdzenia. Konektory referencyjne są w podpakiecie ``connectors``.
"""
from __future__ import annotations

from .connector import Connector, Context, ConnectorRegistry, connector, registry
from .errors import (
    AuthRequired,
    ConnectorError,
    ConnectorTimeout,
    NotConfigured,
    ParseError,
    RateLimited,
    RequestRejected,
    SchemaChanged,
    TransportError,
)
from .http import HttpClient, HttpResponse, HttpxClient, UrllibClient
from .model import Finding, InputKind, SourceKind, Status, Subject
from .privacy import subject_ref
from .runner import run, summarize

__all__ = [
    "Connector",
    "Context",
    "ConnectorRegistry",
    "connector",
    "registry",
    "ConnectorError",
    "RateLimited",
    "AuthRequired",
    "ConnectorTimeout",
    "NotConfigured",
    "RequestRejected",
    "TransportError",
    "ParseError",
    "SchemaChanged",
    "Finding",
    "InputKind",
    "SourceKind",
    "Status",
    "Subject",
    "subject_ref",
    "run",
    "summarize",
    "HttpClient",
    "HttpResponse",
    "HttpxClient",
    "UrllibClient",
]

__version__ = "0.1.0"
