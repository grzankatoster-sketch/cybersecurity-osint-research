"""Straznicy zasad: proweniencja obowiazkowa, zero wyciekow, zero surowych sekretow, ostrozne dane osob.

Rekord niespelniajacy zasad jest odrzucany (RejectedRecord), a import pozostalych rekordow trwa dalej.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import UTC, datetime
from urllib.parse import urlsplit

from .models import FIRST_PARTY_TYPES, Confidence, Source, SourceType
from .normalize import is_same_or_subdomain, normalize_url


class RejectedRecord(Exception):
    """Rekord (albo zrodlo) odrzucone z czytelnym powodem."""

    def __init__(self, reason: str):
        super().__init__(reason)
        self.reason = reason


NO_EMAIL_NOTE = "e-mail odrzucony: brak potwierdzenia w źródle first-party/official"

# --- sygnaly wycieku w zrodle -------------------------------------------------

_LEAK_WORDS = ("dump", "leak", "combolist", "stealer", "paste", "breachforums", "t.me/", "telegram")
_LEAK_HOSTS = ("t.me", "telegram.me", "telegram.org", "pastebin.com", "ghostbin.com", "rentry.co", "anonfiles.com")
# Komunikaty CERT, dokumenty urzedowe i katalog HIBP opisuja wycieki z natury ("wyciek-stealer-2023"):
# dla nich slowa kluczowe nie dzialaja, blokowane sa tylko hosty z wyciekami i slowa w nazwie hosta.
_DESCRIBES_LEAKS = {SourceType.CERT_ADVISORY.value, SourceType.OFFICIAL_DOCUMENT.value, SourceType.HIBP_CATALOG.value}
_PERSON_RELATION_KEYS = {
    "person",
    "persons",
    "people",
    "email",
    "emails",
    "e_mail",
    "account",
    "accounts",
    "address",
    "addresses",
    "affected_emails",
    "affected_persons",
}
_INCIDENT_RELATION_KEYS = {"incident", "incidents", "breach", "breaches", "affected_incidents"}


def _norm_key(key: object) -> str:
    return str(key).strip().lower().replace("-", "_").replace(" ", "_")


def parse_iso8601(value: object) -> str:
    """Zwraca znormalizowany znacznik 'YYYY-MM-DDTHH:MM:SSZ' (czas bez strefy traktujemy jak UTC)."""
    if not isinstance(value, str) or not value.strip():
        raise ValueError("brak daty")
    try:
        dt = datetime.fromisoformat(value.strip())
    except ValueError:
        raise ValueError(f"niepoprawna data ISO 8601: {value!r}") from None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=UTC)
    return dt.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def check_source_signals(name: str, source_type: str, url: str) -> None:
    """Odrzuca zrodla wygladajace na dump / paste / Telegram / forum z wyciekami."""
    host = (urlsplit(url).hostname or "").lower()
    blob = host if source_type in _DESCRIBES_LEAKS else f"{name} {source_type} {url}".lower()
    for word in _LEAK_WORDS:
        if word in blob:
            raise RejectedRecord(f"źródło wygląda na dane z wycieku (sygnał: '{word}'); takie źródła są niedozwolone")
    if any(host == h or host.endswith("." + h) for h in _LEAK_HOSTS):
        raise RejectedRecord(f"źródło wygląda na dane z wycieku (host {host}); takie źródła są niedozwolone")


def validate_source(record: dict, source_id: str) -> Source:
    """Buduje Source z rekordu wejsciowego (bez klucza `key`) albo zglasza RejectedRecord."""
    check_secrets(record)
    name = str(record.get("name") or "").strip()
    url = str(record.get("url") or "").strip()
    raw_type = str(record.get("source_type") or "").strip()
    check_source_signals(name, raw_type, url)
    if not name:
        raise RejectedRecord("źródło bez nazwy")
    try:
        stype = SourceType(raw_type)
    except ValueError:
        raise RejectedRecord(f"nieznany typ źródła: {raw_type!r}") from None
    if not re.match(r"^https?://", url, re.IGNORECASE):
        raise RejectedRecord("źródło wymaga adresu url http/https")
    try:
        _key, display = normalize_url(url)
    except ValueError as exc:
        raise RejectedRecord(str(exc)) from None
    try:
        retrieved = parse_iso8601(record.get("retrieved_at"))
    except ValueError as exc:
        raise RejectedRecord(f"źródło wymaga retrieved_at w formacie ISO 8601 ({exc})") from None
    try:
        reliability = Confidence(str(record.get("reliability") or "medium").strip().lower())
    except ValueError:
        raise RejectedRecord(f"niepoprawna reliability: {record.get('reliability')!r}") from None
    content_hash = record.get("content_hash")
    if content_hash is not None and not re.fullmatch(r"[0-9a-fA-F]{64}", str(content_hash)):
        raise RejectedRecord("content_hash musi być sha256 w hex (64 znaki)")
    return Source(
        id=source_id,
        name=name,
        url=display,
        source_type=stype,
        license=str(record.get("license") or "").strip(),
        retrieved_at=retrieved,
        reliability=reliability,
        notes=str(record.get("notes") or "").strip(),
        content_hash=str(content_hash).lower() if content_hash else None,
    )


def require_sources(keys: object, known: dict[str, Source], rejected_keys: set[str] | None = None) -> list[Source]:
    """Rekord musi wskazywac co najmniej jedno istniejace zrodlo; nieznany klucz odrzuca rekord (literowka
    nie moze po cichu zgubic proweniencji)."""
    if isinstance(keys, str):
        keys = [keys]
    if not isinstance(keys, list) or not keys:
        raise RejectedRecord("brak źródła")
    out: list[Source] = []
    for key in keys:
        if not isinstance(key, str) or not key:
            raise RejectedRecord("brak źródła (niepoprawny klucz źródła)")
        if key in known:
            if known[key] not in out:
                out.append(known[key])
        elif rejected_keys and key in rejected_keys:
            raise RejectedRecord(f"brak źródła (źródło {key!r} zostało odrzucone)")
        else:
            raise RejectedRecord(f"brak źródła (nieznany klucz źródła {key!r})")
    return out


# --- surowe sekrety -----------------------------------------------------------

_SECRET_KEY_EXACT = {"pass", "pwd", "hash", "session", "cookie", "authorization"}
_SECRET_KEY_PARTS = (
    "password",
    "passwd",
    "secret",
    "token",
    "api_key",
    "apikey",
    "private_key",
    "cookie",
    "authorization",
)
_HASH_KEYS_ALLOWED = {"content_hash", "evidence_hash"}
_URL_KEYS = {"url", "evidence_url"}

_JWT_RE = re.compile(r"eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.")
_PRIVATE_KEY_RE = re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----")
_BCRYPT_RE = re.compile(r"\$2[aby]\$[0-9]{2}\$")
_HEX_RE = re.compile(r"(?<![0-9A-Fa-f])(?:[0-9A-Fa-f]{64}|[0-9A-Fa-f]{40}|[0-9A-Fa-f]{32})(?![0-9A-Fa-f])")
_EMAIL_PASS_RE = re.compile(r"[\w.+-]+@[\w-]+(?:\.[\w-]+)+[:;|](?!\d+(?:/|$))\S{3,}")
_BEARER_RE = re.compile(r"\bBearer\s+[A-Za-z0-9._~+/=-]{20,}")


def _secret_key(key: str) -> bool:
    k = _norm_key(key)
    if k in _HASH_KEYS_ALLOWED:
        return False
    if k in _SECRET_KEY_EXACT or k.endswith(("_hash", "_session")) or k.startswith("session_"):
        return True
    return any(part in k for part in _SECRET_KEY_PARTS)


def check_secrets(value: object, path: str = "") -> None:
    """Rekurencyjnie sprawdza klucze i wartosci; zglasza RejectedRecord przy surowym sekrecie.

    Dozwolone: pola content_hash/evidence_hash (sha256) oraz data_classes z nazwa klasy "Passwords"
    (to tylko etykieta z katalogu HIBP; sprawdzamy wzorce wartosci, nie slowa)."""
    if isinstance(value, dict):
        for key, item in value.items():
            if _secret_key(str(key)):
                raise RejectedRecord(
                    f"pole sekretu w rekordzie: '{key}' (surowe hasła, tokeny i hashe są niedozwolone)"
                )
            check_secrets(item, f"{path}.{key}" if path else str(key))
        return
    if isinstance(value, (list, tuple)):
        for item in value:
            check_secrets(item, path)
        return
    if not isinstance(value, str):
        return
    leaf = path.rsplit(".", 1)[-1]
    if _JWT_RE.search(value):
        raise RejectedRecord(f"token JWT w wartości pola '{leaf}'")
    if _PRIVATE_KEY_RE.search(value):
        raise RejectedRecord(f"klucz prywatny w wartości pola '{leaf}'")
    if _BCRYPT_RE.search(value):
        raise RejectedRecord(f"hash bcrypt w wartości pola '{leaf}'")
    if _BEARER_RE.search(value):
        raise RejectedRecord(f"token Bearer w wartości pola '{leaf}'")
    if not re.match(r"^https?://", value.strip(), re.IGNORECASE) and _EMAIL_PASS_RE.search(value):
        raise RejectedRecord(f"para e-mail:hasło w wartości pola '{leaf}'")
    if _norm_key(leaf) not in _HASH_KEYS_ALLOWED | _URL_KEYS and _HEX_RE.search(value):
        raise RejectedRecord(f"ciąg hex 32/40/64 znaków (podejrzenie hasha) w polu '{leaf}'")


# --- relacje zakazane -----------------------------------------------------------


def reject_forbidden_relations(record: dict, kind: str) -> None:
    """Nigdy nie tworzymy relacji e-mail->osoba ani osoba->incydent: incydent laczy sie tylko z domena/organizacja."""
    keys = {_norm_key(k) for k in record}
    if kind == "incident" and keys & _PERSON_RELATION_KEYS:
        raise RejectedRecord("incydent nie może być powiązany z osobami, adresami e-mail ani kontami")
    if kind == "person" and keys & _INCIDENT_RELATION_KEYS:
        raise RejectedRecord("osoba nie może być powiązana z incydentem")


def catalog_forbidden_key(key: object) -> str | None:
    """Powod odrzucenia klucza rekordu KATALOGU HIBP albo None. Katalog zawiera wylacznie metadane incydentu;
    pole z kontami, adresami e-mail, haslami albo sekretami oznacza inny rodzaj danych, wiec caly rekord jest
    odrzucany (fail-closed, tak jak relacje incydent->osoba w `reject_forbidden_relations`)."""
    norm = _norm_key(key)
    if norm in _PERSON_RELATION_KEYS or "email" in norm or "account" in norm:
        return f"pole z kontami lub adresami e-mail: '{key}' (katalog HIBP ma zawierać tylko metadane incydentu)"
    if _secret_key(str(key)):
        return f"pole sekretu w rekordzie: '{key}' (surowe hasła, tokeny i hashe są niedozwolone)"
    return None


# --- osoby publiczne ------------------------------------------------------------


def person_sources(sources: list[Source]) -> tuple[list[Source], list[Source]]:
    """-> (zrodla dopuszczone dla osoby, pominiete). Dopuszczone: rejestr urzedowy, strona firmy, dokument."""
    ok = [s for s in sources if s.source_type in FIRST_PARTY_TYPES]
    return ok, [s for s in sources if s not in ok]


def require_person_sources(sources: list[Source]) -> tuple[list[Source], list[Source]]:
    ok, dropped = person_sources(sources)
    if not ok:
        raise RejectedRecord(
            "osoba wymaga źródła official_registry, company_website lub official_document "
            "(hibp_catalog, cert_advisory i manual nie wystarczają)"
        )
    return ok, dropped


_EMAIL_RE = re.compile(r"^[A-Za-z0-9._%+-]{1,64}@([A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+)$")


@dataclass
class EmailDecision:
    email: str | None
    note: str = ""


def decide_person_email(
    raw_email: object,
    email_sources: list[Source],
    official_domain: str | None,
    evidence_quote: str | None,
) -> EmailDecision:
    """E-mail osoby przyjmujemy tylko, gdy SPELNIONE SA OBA warunki:
    (a) zrodlo e-maila jest first-party/official (rejestr, strona firmy, dokument), oraz
    (b) domena e-maila jest domena oficjalna organizacji (lub jej subdomena) ALBO adres wystepuje
        dosłownie w cytacie dowodu (`evidence_quote`) z tego zrodla.
    W przeciwnym razie osoba jest zapisywana BEZ e-maila, a powod trafia do notatki obserwacji."""
    if raw_email is None or str(raw_email).strip() == "":
        return EmailDecision(None)
    email = str(raw_email).strip().lower()
    m = _EMAIL_RE.match(email)
    if not m:
        return EmailDecision(None, "e-mail odrzucony: niepoprawny format")
    if not any(s.source_type in FIRST_PARTY_TYPES for s in email_sources):
        return EmailDecision(None, NO_EMAIL_NOTE)
    domain = m.group(1)
    domain_ok = bool(official_domain) and is_same_or_subdomain(domain, official_domain)
    quote_ok = bool(evidence_quote) and email in str(evidence_quote).lower()
    if domain_ok or quote_ok:
        return EmailDecision(email)
    return EmailDecision(None, NO_EMAIL_NOTE)
