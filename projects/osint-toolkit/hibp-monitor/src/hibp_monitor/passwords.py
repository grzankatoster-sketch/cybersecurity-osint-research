"""Pwned Passwords z k-anonymity: do sieci trafia wylacznie 5-znakowy prefiks SHA-1.

Haslo nie jest nigdzie logowane ani zapisywane. Funkcje nie wypisuja go w wyjatkach.
"""
from __future__ import annotations

import hashlib
import re

from .http import Client, HibpError

RANGE_URL = "https://api.pwnedpasswords.com/range/"
_SUFFIX_RE = re.compile(r"^[0-9A-F]{35}$")


def sha1_split(password: str) -> tuple[str, str]:
    digest = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()  # SHA-1 wymagany przez API
    return digest[:5], digest[5:]


def parse_range(text: str) -> dict[str, int]:
    """Parsuje odpowiedz range: linie SUFFIX:COUNT. Wiersze paddingu (COUNT=0) sa pomijane."""
    out: dict[str, int] = {}
    rows = 0
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        suffix, sep, count = line.partition(":")
        suffix = suffix.upper()
        if not sep or not _SUFFIX_RE.match(suffix) or not re.fullmatch(r"[0-9]+", count.strip()):
            raise HibpError("Nieprawidlowa odpowiedz Pwned Passwords (zly format wiersza).")
        rows += 1
        n = int(count)
        if n > 0:
            out[suffix] = n
    if rows == 0:  # brak jakichkolwiek wierszy (nawet paddingu) to nie wynik "nie wystepuje"
        raise HibpError("Pusta odpowiedz API (brak wierszy), wynik nieustalony.")
    return out


def check_password(client: Client, password: str) -> int:
    """Zwraca liczbe wystapien hasla w wyciekach (0 = nie znaleziono)."""
    if not password:
        raise ValueError("Puste haslo.")
    prefix, suffix = sha1_split(password)
    resp = client.get(RANGE_URL + prefix, {"Add-Padding": "true"})
    if resp.status != 200:
        raise HibpError(f"Pwned Passwords zwrocil blad HTTP {resp.status}.", resp.status)
    return parse_range(resp.text).get(suffix, 0)
