"""Taksonomia wyjątków konektorów.

Konektory zgłaszają błędy typowanymi wyjątkami; runner mapuje je na
:class:`~osint_connectors.model.Status`. To naprawia wadę z audytu, gdzie
timeout, błąd transportu, błąd parsera i realny limit sklejały się w jeden
stan ``rateLimit`` i nie dało się odróżnić „zbanowano" od „serwis padł".
"""
from __future__ import annotations


class ConnectorError(Exception):
    """Baza. ``error_kind`` trafia do Finding; ``status`` decyduje o mapowaniu."""

    error_kind = "unspecified"
    #: UNKNOWN (niepewność) vs ERROR (realny błąd) — ustawiane w podklasach.
    maps_to_unknown = False


class RateLimited(ConnectorError):
    """Serwis ograniczył zapytania — to niepewność, nie negatyw."""

    error_kind = "rate_limited"
    maps_to_unknown = True


class AuthRequired(ConnectorError):
    """Źródło wymaga uwierzytelnienia/zgody, której nie ma — niepewność."""

    error_kind = "auth_required"
    maps_to_unknown = True


class ConnectorTimeout(ConnectorError):
    """Przekroczono czas — realny błąd."""

    error_kind = "timeout"


class TransportError(ConnectorError):
    """Błąd sieci/transportu — realny błąd."""

    error_kind = "transport"


class ParseError(ConnectorError):
    """Odpowiedź nie dała się sparsować — realny błąd."""

    error_kind = "parse"


class SchemaChanged(ConnectorError):
    """Format odpowiedzi inny niż oczekiwany — realny błąd (sygnał do utrzymania)."""

    error_kind = "schema_changed"


class NotConfigured(ConnectorError):
    """Brak konfiguracji źródła (np. klucza API) — nic nie wysłano; niepewność, nie negatyw."""

    error_kind = "not_configured"
    maps_to_unknown = True


class RequestRejected(ConnectorError):
    """Źródło odrzuciło zapytanie jako niepoprawne (np. HTTP 400/422) — realny błąd."""

    error_kind = "request_rejected"
