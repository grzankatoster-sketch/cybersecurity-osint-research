"""Weryfikacja wlasnosci domeny (wzorzec HIBP): rekord TXT `org-intel-verification=<token>`.

Token jest pokazywany uzytkownikowi JEDEN raz; w magazynie zostaje tylko jego sha256.
Rozstrzygniecie (sprawdzenie) wymaga resolvera: Protocol `txt(name) -> list[str]`. Siec uzywa tylko DohResolver
(DNS-over-HTTPS JSON), wywolywany wylacznie w trybie --online.
"""

from __future__ import annotations

import hmac
import json
import re
import secrets
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Protocol
from urllib.parse import urlencode

from .http import Client, NetworkError, UrllibClient
from .models import VerificationStatus, sha256_hex
from .normalize import normalize_domain
from .store import Store, StoreError

TXT_PREFIX = "org-intel-verification="
DOH_URL = "https://cloudflare-dns.com/dns-query"
DOH_TIMEOUT = 10.0


class VerificationError(StoreError):
    """Domena nie nadaje sie do weryfikacji (brak w magazynie, brak wydanego tokenu)."""


class Resolver(Protocol):
    def txt(self, name: str) -> list[str]: ...


class DohResolver:
    """DNS-over-HTTPS (Cloudflare, format JSON). Timeout 10 s."""

    def __init__(self, client: Client | None = None):
        self._client = client or UrllibClient(timeout=DOH_TIMEOUT)

    def txt(self, name: str) -> list[str]:
        url = f"{DOH_URL}?{urlencode({'name': name, 'type': 'TXT'})}"
        resp = self._client.get(url, {"Accept": "application/dns-json"})
        if resp.status != 200:
            raise NetworkError(f"Resolver DoH zwrócił HTTP {resp.status}.", resp.status)
        try:
            data = json.loads(resp.text)
        except json.JSONDecodeError:
            raise NetworkError("Resolver DoH zwrócił nieprawidłową odpowiedź (to nie jest JSON).") from None
        out: list[str] = []
        for answer in data.get("Answer", []) if isinstance(data, dict) else []:
            if answer.get("type") == 16 and isinstance(answer.get("data"), str):
                raw = answer["data"]
                parts = re.findall(r'"((?:[^"\\]|\\.)*)"', raw)
                out.append("".join(parts) if parts else raw)
        return out


def _now(now: datetime | None) -> str:
    return (now or datetime.now(UTC)).astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


@dataclass
class IssuedToken:
    domain: str
    token: str  # pokazywany raz
    txt_record: str

    def instruction(self) -> str:
        return (
            f"Dodaj rekord TXT na domenie {self.domain}:\n  {self.txt_record}\n"
            "Token jest pokazany tylko teraz (w magazynie zapisano wyłącznie jego hash). "
            f"Potem uruchom: org-intel verify-domain {self.domain} --check --online"
        )


def _domain_record(store: Store, domain: str):
    dom = store.find_domain(domain)
    if dom is None:
        raise VerificationError(
            f"Domena {domain} nie jest w magazynie. Najpierw zaimportuj ją (ingest) z podaniem źródła."
        )
    return dom


def issue_token(store: Store, domain: str, *, now: datetime | None = None) -> IssuedToken:
    domain = normalize_domain(domain)
    dom = _domain_record(store, domain)
    token = secrets.token_urlsafe(24)
    dom.verification_status = VerificationStatus.PENDING
    dom.verified_at = None
    store.verifications[domain] = {"token_hash": sha256_hex(token), "issued_at": _now(now), "checks": 0}
    return IssuedToken(domain, token, f"{TXT_PREFIX}{token}")


def check(store: Store, domain: str, resolver: Resolver, *, now: datetime | None = None) -> VerificationStatus:
    """Sprawdza TXT i ustawia verified albo failed (failed mozna ponowic). Bledy sieci nie zmieniaja statusu."""
    domain = normalize_domain(domain)
    dom = _domain_record(store, domain)
    record = store.verifications.get(domain)
    if not record or not record.get("token_hash"):
        raise VerificationError(f"Brak wydanego tokenu dla {domain}: uruchom najpierw `verify-domain {domain}`.")
    values = resolver.txt(domain)  # moze zglosic NetworkError: status bez zmian
    expected = record["token_hash"]
    found = False
    for value in values:
        value = value.strip().strip('"')
        if value.startswith(TXT_PREFIX):
            candidate = value[len(TXT_PREFIX) :].strip()
            if hmac.compare_digest(sha256_hex(candidate), expected):
                found = True
                break
    record["checks"] = int(record.get("checks", 0)) + 1
    record["last_check"] = _now(now)
    if found:
        dom.verification_status = VerificationStatus.VERIFIED
        dom.verified_at = _now(now)
    else:
        dom.verification_status = VerificationStatus.FAILED
        dom.verified_at = None
    return dom.verification_status
