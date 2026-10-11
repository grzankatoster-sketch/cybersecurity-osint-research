"""Modele danych silnika: reguła serwisu, odpowiedź HTTP, wynik sprawdzenia."""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from urllib.parse import quote

from multidict import CIMultiDict


class Status(str, Enum):
    FOUND = "FOUND"              # konto istnieje (z poziomem pewności)
    NOT_FOUND = "NOT_FOUND"      # serwis wyraźnie odpowiedział, że konta nie ma
    ERROR = "ERROR"              # nie da się rozstrzygnąć: sieć, limit, CAPTCHA, logowanie, 5xx
    UNSUPPORTED = "UNSUPPORTED"  # nazwa nie spełnia reguł serwisu (regex) — zapytania nie wysłano


# powód wyniku-zastępnika dla serwisów niesprawdzonych po przerwaniu skanu (zawsze ERROR, nigdy NOT_FOUND)
ABORT_REASON = "przerwano: proxy przestało działać"

_STR_FIELDS = ("probe_url", "method", "body", "check_type", "regex", "source")
_INT_FIELDS = ("e_code", "m_code")
_LIST_FIELDS = ("e_strings", "m_strings", "tags", "known")
_BOOL_FIELDS = ("absence_unproven",)


@dataclass
class Site:
    name: str
    url: str                       # adres profilu pokazywany użytkownikowi, z {username}
    probe_url: str | None = None   # adres faktycznie odpytywany (np. API), z {username}
    method: str = "GET"
    headers: dict[str, str] = field(default_factory=dict)
    body: str | None = None        # treść POST z {username}
    check_type: str = "message"    # message | status_code | response_url
    e_code: int | None = None      # kod HTTP oznaczający istnienie konta
    e_strings: list[str] = field(default_factory=list)   # teksty obecności konta (wystarczy jeden); {username}
                                                         # = tekst związany ze sprawdzaną nazwą (bez wielkości liter)
    m_code: int | None = None      # kod HTTP oznaczający brak konta
    m_strings: list[str] = field(default_factory=list)   # teksty braku konta (wystarczy jeden)
    regex: str | None = None       # dozwolony format nazwy
    tags: list[str] = field(default_factory=list)
    source: str = ""               # wmn | maigret — atrybucja licencyjna
    known: list[str] = field(default_factory=list)       # nazwy istniejących kont (self-check)
    absence_unproven: bool = False  # brak tekstu obecności NIE oznacza braku konta (serwis nie ma strony „brak konta”)

    def profile_url(self, username: str) -> str:
        return self.url.replace("{username}", quote(username, safe=""))

    def request_url(self, username: str) -> str:
        return (self.probe_url or self.url).replace("{username}", quote(username, safe=""))

    def to_dict(self) -> dict:
        d = {k: v for k, v in self.__dict__.items() if v not in (None, [], {}, "", False)}
        d["name"] = self.name
        d["url"] = self.url
        return d

    @classmethod
    def from_dict(cls, d: dict) -> "Site":
        """Wpis bazy -> Site. Baza jest niezaufanym wejściem: typy pól są sprawdzane, błąd to ValueError z nazwą wpisu."""
        if not isinstance(d, dict):
            raise ValueError(f"wpis bazy nie jest obiektem ({type(d).__name__})")
        label = d.get("name") if isinstance(d.get("name"), str) else "?"

        def bad(field_name: str, expected: str):
            return ValueError(f"wpis bazy {label!r}: pole {field_name} ma zły typ (oczekiwano: {expected})")

        for req in ("name", "url"):
            if not isinstance(d.get(req), str) or not d[req].strip():
                raise bad(req, "niepusty tekst")
        for k in _STR_FIELDS:
            if d.get(k) is not None and not isinstance(d[k], str):
                raise bad(k, "tekst")
        for k in _INT_FIELDS:
            v = d.get(k)
            if v is not None and (not isinstance(v, int) or isinstance(v, bool)):
                raise bad(k, "liczba całkowita")
        for k in _LIST_FIELDS:
            v = d.get(k)
            if v is not None and (not isinstance(v, list) or not all(isinstance(x, str) for x in v)):
                raise bad(k, "lista tekstów")
        for k in _BOOL_FIELDS:
            if d.get(k) is not None and not isinstance(d[k], bool):
                raise bad(k, "true/false")
        h = d.get("headers")
        if h is not None and (not isinstance(h, dict) or not all(isinstance(a, str) and isinstance(b, str)
                                                                  for a, b in h.items())):
            raise bad("headers", "słownik tekst -> tekst")
        allowed = cls.__dataclass_fields__.keys()
        return cls(**{k: v for k, v in d.items() if k in allowed and v is not None})


@dataclass
class Response:
    status: int | None             # None = brak odpowiedzi (błąd sieci)
    text: str = ""
    final_url: str = ""
    error: str | None = None       # opis błędu transportu (DNS, timeout, połączenie)
    headers: dict[str, str] = field(default_factory=dict)   # po inicjalizacji: CIMultiDict (nazwy bez wielkości liter)
    insecure: bool = False         # odpowiedź pobrana bez weryfikacji certyfikatu TLS
    truncated: bool = False        # treść ucięta limitem rozmiaru: brak tekstu w niej niczego nie dowodzi

    def __post_init__(self) -> None:
        if not isinstance(self.headers, CIMultiDict):
            self.headers = CIMultiDict(self.headers or {})


@dataclass
class Result:
    site: str
    url: str
    status: Status
    confidence: float = 0.0        # 0–1, sensowne dla FOUND
    reason: str = ""
    http_status: int | None = None
    profile: dict = field(default_factory=dict)   # dane wyciągnięte ze znalezionego profilu (extract.py)
    evidence: list[str] = field(default_factory=list)   # dopasowane teksty obecności konta (classify.matched_evidence)
    not_found_kind: str | None = None  # negative_match | no_match_default, tylko dla NOT_FOUND
    insecure: bool = False         # odpowiedź bez weryfikacji TLS: pewność ograniczona, bez ekstrakcji i korelacji
    channel: str = "direct"        # którędy sprawdzono: direct | proxy | proxy-retry (nowy obwód) | fallback (drugie proxy)

    def to_dict(self) -> dict:
        d = {
            "site": self.site,
            "url": self.url,
            "status": self.status.value,
            "confidence": round(self.confidence, 2),
            "reason": self.reason,
            "http_status": self.http_status,
            "channel": self.channel,
        }
        if self.profile:
            d["profile"] = self.profile
        if self.evidence:
            d["evidence"] = self.evidence
        if self.not_found_kind:
            d["not_found_kind"] = self.not_found_kind
        if self.insecure:
            d["insecure"] = True
        return d


def is_abort_placeholder(r: Result) -> bool:
    """Serwis, którego nie sprawdzono, bo skan przerwano (martwe proxy): nie jest to błąd tego serwisu."""
    return r.status is Status.ERROR and r.reason == ABORT_REASON
