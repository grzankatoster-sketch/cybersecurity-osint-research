"""Wspólny kontrakt wyniku dla wszystkich operacji Meta (API, heurystyka HTML, linki ręczne).

Statusy rozróżniają: wynik, pustą odpowiedź, brak konfiguracji, token nieważny, brak uprawnień, limit, błąd
źródła i błędne zapytanie. Pusta odpowiedź (no_result) NIE dowodzi, że osoba nie ma konta."""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum

TOOL = "meta-search"
SCHEMA = 1
IDENTITY_CAVEAT = "Zgodny nick nie potwierdza tożsamości osoby: wynik to trop do weryfikacji, nie dowód."


class St(str, Enum):
    FOUND = "found"                          # źródło zwróciło dane
    NO_RESULT = "no_result"                  # źródło odpowiedziało poprawnie, ale bez wyników dla zapytania
    NOT_CONFIGURED = "not_configured"        # brak tokenu / konfiguracji: zapytania nie wysłano
    AUTH_ERROR = "auth_error"                # token nieważny, wygasły albo odwołany
    PERMISSION_DENIED = "permission_denied"  # token bez potrzebnego uprawnienia albo funkcja bez dostępu
    RATE_LIMITED = "rate_limited"            # limit zapytań źródła
    SOURCE_ERROR = "source_error"            # sieć, timeout, 5xx, nieoczekiwana odpowiedź
    INVALID_INPUT = "invalid_input"          # zapytanie odrzucone lokalnie, nic nie wysłano
    MANUAL = "manual"                        # tylko linki do ręcznego sprawdzenia, nic nie sprawdzono


class SourceKind(str, Enum):
    API = "api"                        # oficjalne API Meta
    HTML_HEURISTIC = "html_heuristic"  # reguły username-engine na publicznym HTML
    MANUAL = "manual"                  # link do otwarcia przez człowieka


EXIT_CODES = {St.FOUND: 0, St.NO_RESULT: 0, St.MANUAL: 0, St.INVALID_INPUT: 2, St.NOT_CONFIGURED: 3,
              St.AUTH_ERROR: 4, St.PERMISSION_DENIED: 4, St.RATE_LIMITED: 5, St.SOURCE_ERROR: 1}

LABELS_PL = {
    St.FOUND: "wynik", St.NO_RESULT: "brak wyniku", St.NOT_CONFIGURED: "wymaga konfiguracji",
    St.AUTH_ERROR: "token nieważny", St.PERMISSION_DENIED: "brak uprawnień", St.RATE_LIMITED: "limit zapytań",
    St.SOURCE_ERROR: "błąd źródła", St.INVALID_INPUT: "błędne zapytanie", St.MANUAL: "do ręcznego sprawdzenia",
}


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


@dataclass
class MetaResult:
    platform: str                 # threads | instagram | facebook | meta (kilka platform)
    operation: str                # threads_profile | threads_search | links ...
    query: str
    status: St
    source_kind: SourceKind
    endpoint: str = ""            # adres BEZ parametrów (nigdy z tokenem)
    api_version: str = ""
    items: list[dict] = field(default_factory=list)
    message: str = ""
    caveats: list[str] = field(default_factory=list)
    http_status: int | None = None
    error_code: int | None = None
    fetched_at: str = field(default_factory=utc_now)

    def to_dict(self) -> dict:
        return {
            "tool": TOOL, "schema": SCHEMA, "platform": self.platform, "operation": self.operation,
            "query": self.query, "status": self.status.value, "status_label": LABELS_PL[self.status],
            "source": {"kind": self.source_kind.value, "endpoint": self.endpoint, "api_version": self.api_version},
            "fetched_at": self.fetched_at, "items": self.items, "message": self.message,
            "caveats": self.caveats, "http_status": self.http_status, "error_code": self.error_code,
        }

    @property
    def exit_code(self) -> int:
        return EXIT_CODES[self.status]
