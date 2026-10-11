"""Rdzeniowy model danych konektorów OSINT.

Clean-room: koncepcja (jednolity rekord wyniku) przejęta z audytu holehe/ignorant,
kod własny. Naprawia główną wadę oryginałów — sklejanie czterech stanów w
``exists: bool`` + ``rateLimit`` — wprowadzając jawny ``Status`` i ``confidence``.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Mapping, Optional


class Status(str, Enum):
    """Jawny, czterowartościowy status wyniku pojedynczego konektora."""

    FOUND = "found"
    NOT_FOUND = "not_found"
    UNKNOWN = "unknown"  # limit, CAPTCHA, brak pewności — NIGDY nie jest negatywem
    ERROR = "error"      # timeout, transport, parser, zmiana formatu


class InputKind(str, Enum):
    """Rodzaj identyfikatora celu, który konektor potrafi sprawdzić."""

    EMAIL = "email"
    PHONE = "phone"
    USERNAME = "username"
    PERSON_NAME = "person_name"  # imię i nazwisko jako fraza do wyszukiwarki (nie nick, nie e-mail)


class SourceKind(str, Enum):
    """Z jakiego rodzaju źródła korzysta konektor (polityka doboru źródeł)."""

    OFFICIAL_API = "official_api"  # oficjalne API, w granicach regulaminu
    PASSIVE = "passive"            # dane własne/publiczne, bez interakcji z celem
    MANUAL = "manual"              # podpowiedź do ręcznego potwierdzenia


@dataclass(frozen=True)
class Subject:
    """Cel sprawdzenia. Surowa wartość nie trafia do :class:`Finding`."""

    kind: InputKind
    value: str

    def __post_init__(self) -> None:
        if not isinstance(self.value, str) or not self.value.strip():
            raise ValueError("Subject.value musi być niepustym tekstem")


@dataclass(frozen=True)
class Finding:
    """Znormalizowany, serializowalny wynik jednego konektora.

    ``subject_ref`` to zahaszowany identyfikator celu — surowy e-mail/numer
    nigdy nie jest tu przechowywany ani logowany.
    """

    connector: str
    source: SourceKind
    status: Status
    confidence: float          # 0..1 — jawna niepewność zamiast boolean
    subject_ref: str           # hash celu (sól per-sprawa)
    evidence: Optional[str] = None
    extra: Mapping[str, object] = field(default_factory=dict)
    error_kind: Optional[str] = None
    checked_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    def __post_init__(self) -> None:
        if not 0.0 <= self.confidence <= 1.0:
            raise ValueError("confidence musi być w zakresie 0..1")
        if self.status in (Status.ERROR, Status.UNKNOWN) and self.error_kind is None:
            # Dla ERROR/UNKNOWN wymagamy jawnej przyczyny — to różnica wobec
            # oryginałów, które gubiły typ błędu.
            object.__setattr__(self, "error_kind", "unspecified")

    def to_dict(self) -> dict:
        """Deterministyczny słownik (np. do eksportu/JSON). Bez surowego celu."""
        return {
            "connector": self.connector,
            "source": self.source.value,
            "status": self.status.value,
            "confidence": round(self.confidence, 4),
            "subject_ref": self.subject_ref,
            "evidence": self.evidence,
            "extra": dict(self.extra),
            "error_kind": self.error_kind,
            "checked_at": self.checked_at.astimezone(timezone.utc).isoformat(),
        }
