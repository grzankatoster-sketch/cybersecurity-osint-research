"""Normalizacja identyfikatorów firm i rachunków (NIP, REGON, KRS, IBAN) do porównań między źródłami.

Zwracają None dla wartości nieczytelnych: nieprawidłowy identyfikator nigdy nie służy do scalania węzłów."""
from __future__ import annotations

import re


def normalize_nip(raw) -> str | None:
    text = re.sub(r"[\s-]", "", str(raw or "")).upper().removeprefix("PL")
    return text if re.fullmatch(r"[0-9]{10}", text) else None


def normalize_regon(raw) -> str | None:
    """REGON 9 albo 14 cyfr (zachowuje długość z pliku)."""
    text = re.sub(r"[\s-]", "", str(raw or ""))
    return text if re.fullmatch(r"[0-9]{9}|[0-9]{14}", text) else None


def regon_core(regon: str | None) -> str | None:
    """9 pierwszych cyfr: REGON 14-cyfrowy (jednostka lokalna) ma prefiks równy REGON-owi 9-cyfrowemu podmiotu."""
    return regon[:9] if regon else None


def normalize_krs(raw) -> str | None:
    text = re.sub(r"[\s-]", "", str(raw or ""))
    return text.zfill(10) if re.fullmatch(r"[0-9]{1,10}", text) else None


def normalize_iban(raw) -> str | None:
    """IBAN bez spacji, wielkimi literami; 26 cyfr (rachunek z Wykazu VAT) dostaje prefiks PL."""
    text = re.sub(r"[\s-]", "", str(raw or "")).upper()
    if re.fullmatch(r"[0-9]{26}", text):
        text = "PL" + text
    return text if re.fullmatch(r"[A-Z]{2}[0-9]{2}[A-Z0-9]{11,30}", text) else None
