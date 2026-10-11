"""Platne API HIBP: wyszukiwanie w ZWERYFIKOWANEJ domenie wlasciciela.

Klucz wylacznie ze zmiennej srodowiskowej HIBP_API_KEY (nigdy z pliku ani z argumentu CLI).
Domyslnie wynik jest zagregowany (liczby kont na wyciek); adresy tylko na jawne zadanie.
"""
from __future__ import annotations

import json
import os
from collections import Counter
from dataclasses import dataclass, field
from typing import Mapping

from .breaches import BASE, normalize_domain
from .http import Client, HibpError

ENV_KEY = "HIBP_API_KEY"

MISSING_KEY_MESSAGE = (
    "Brak klucza API. To polecenie wymaga platnego klucza HIBP i ZWERYFIKOWANEJ domeny "
    "(tylko Twojej). Ustaw zmienna srodowiskowa " + ENV_KEY + " (klucz nie jest czytany z plikow), np.:\n"
    "  PowerShell: $env:" + ENV_KEY + ' = "..."\n'
    "  cmd:        set " + ENV_KEY + "=..."
)


class MissingApiKey(HibpError):
    def __init__(self) -> None:
        super().__init__(MISSING_KEY_MESSAGE)


def get_api_key(environ: Mapping[str, str] | None = None) -> str:
    key = (environ if environ is not None else os.environ).get(ENV_KEY, "").strip()
    if not key:
        raise MissingApiKey()
    return key


@dataclass
class DomainSearchResult:
    domain: str
    total_accounts: int
    per_breach: dict[str, int]
    addresses: dict[str, list[str]] | None = field(default=None)  # alias -> wycieki; tylko z --show-addresses

    def to_dict(self) -> dict:
        out: dict = {"domain": self.domain, "total_accounts": self.total_accounts, "per_breach": self.per_breach}
        if self.addresses is not None:
            out["addresses"] = {f"{a}@{self.domain}": b for a, b in sorted(self.addresses.items())}
        return out


def aggregate(domain: str, data: dict[str, list[str]], show_addresses: bool = False) -> DomainSearchResult:
    counts: Counter[str] = Counter()
    for breaches in data.values():
        counts.update(set(breaches))
    per_breach = dict(sorted(counts.items(), key=lambda kv: (-kv[1], kv[0])))
    return DomainSearchResult(domain, len(data), per_breach, dict(data) if show_addresses else None)


def domain_search(client: Client, domain: str, api_key: str, show_addresses: bool = False) -> DomainSearchResult:
    domain = normalize_domain(domain)
    resp = client.get(f"{BASE}/breacheddomain/{domain}", {"hibp-api-key": api_key, "Accept": "application/json"})
    if resp.status == 200:
        try:
            data = json.loads(resp.text)
        except json.JSONDecodeError:
            raise HibpError("Nieprawidlowa odpowiedz HIBP (to nie jest JSON).") from None
        if not isinstance(data, dict):
            raise HibpError("Nieoczekiwany format odpowiedzi HIBP (oczekiwano obiektu).")
        clean: dict[str, list[str]] = {}
        for k, v in data.items():
            if v is None:
                v = []
            if not isinstance(v, list) or not all(isinstance(b, str) for b in v):
                raise HibpError("Nieoczekiwany format odpowiedzi HIBP (oczekiwano listy wyciekow).")
            clean[str(k)] = v
        return aggregate(domain, clean, show_addresses)
    if resp.status == 401:
        raise HibpError("HIBP odrzucil klucz API (401): klucz niepoprawny lub bez uprawnien.", 401)
    if resp.status == 403:
        raise HibpError("HIBP odmowil dostepu (403): sprawdz User-Agent, zakres klucza i weryfikacje domeny.", 403)
    if resp.status == 404:
        raise HibpError(f"Domena {domain} nie jest zweryfikowana na Twoim koncie HIBP (404).", 404)
    raise HibpError(f"HIBP zwrocil blad HTTP {resp.status}.", resp.status)
