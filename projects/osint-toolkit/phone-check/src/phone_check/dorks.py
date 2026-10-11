"""Warianty zapisu numeru jako frazy w cudzyslowie do RECZNEGO wyszukania.

Modul tylko buduje tekst. Nic nie wysyla i nie otwiera zadnych adresow.
"""

from __future__ import annotations

from typing import NamedTuple

import phonenumbers
from phonenumbers import PhoneNumberFormat

from .core import DEFAULT_REGION, normalize_region

DORK_UNPARSEABLE = "unparseable"  # wejscia nie da sie sparsowac jako numeru
DORK_IMPOSSIBLE = "impossible_length"  # da sie sparsowac, ale dlugosc jest niemozliwa


class DorkResult(NamedTuple):
    variants: list[str]
    reason: str | None  # None gdy sa warianty; inaczej DORK_UNPARSEABLE / DORK_IMPOSSIBLE


def _group(digits: str, sizes: tuple[int, ...]) -> list[str]:
    parts, i = [], 0
    for s in sizes:
        parts.append(digits[i : i + s])
        i += s
    if i < len(digits):
        parts.append(digits[i:])
    return [p for p in parts if p]


def _groupings(nsn: str, fixed_line: bool = True) -> list[tuple[int, ...]]:
    if len(nsn) == 9:
        if not fixed_line:
            return [(3, 3, 3)]  # 603 123 456
        return [(3, 3, 3), (2, 3, 2, 2)]  # 123 456 789 oraz 22 123 45 67
    if len(nsn) >= 6:
        return [(3,) * (len(nsn) // 3)]
    return []


def dork_variants(raw: str, region: str = DEFAULT_REGION) -> list[str]:
    """Zwraca liste unikalnych fraz w cudzyslowie. Pusta lista, gdy numer jest nie do uzycia."""
    return dork_result(raw, region).variants


def dork_result(raw: str, region: str = DEFAULT_REGION) -> DorkResult:
    """Jak dork_variants, ale przy pustym wyniku podaje przyczyne (nie do sparsowania vs zla dlugosc)."""
    try:
        num = phonenumbers.parse(raw, normalize_region(region))
    except phonenumbers.NumberParseException:
        return DorkResult([], DORK_UNPARSEABLE)
    if phonenumbers.is_possible_number_with_reason(num) != phonenumbers.ValidationResult.IS_POSSIBLE:
        return DorkResult([], DORK_IMPOSSIBLE)

    cc = str(num.country_code)
    nsn = phonenumbers.national_significant_number(num)
    variants: list[str] = []

    def add(s: str) -> None:
        if s and s not in variants:
            variants.append(s)

    # Kopia bez dopisku numeru wewnetrznego - warianty dotycza samego numeru abonenta
    num_no_ext = phonenumbers.PhoneNumber()
    num_no_ext.merge_from(num)
    num_no_ext.extension = None

    # Formaty z biblioteki
    add(phonenumbers.format_number(num, PhoneNumberFormat.E164))  # +48123456789
    add(phonenumbers.format_number(num_no_ext, PhoneNumberFormat.INTERNATIONAL))  # +48 123 456 789
    add(phonenumbers.format_number(num_no_ext, PhoneNumberFormat.NATIONAL))
    add(phonenumbers.format_number(num_no_ext, PhoneNumberFormat.INTERNATIONAL).replace(" ", "-"))

    # Bez plusa / z 00 / w nawiasie / same cyfry krajowe
    add(f"{cc}{nsn}")
    add(f"00{cc}{nsn}")
    add(f"(+{cc}) {nsn}")
    add(nsn)

    # Grupowania cyfr (spacje, myslniki, kropki) z i bez kierunkowego
    fixed_line = phonenumbers.number_type(num) == phonenumbers.PhoneNumberType.FIXED_LINE
    for sizes in _groupings(nsn, fixed_line):
        grouped = _group(nsn, sizes)
        for sep in (" ", "-", "."):
            body = sep.join(grouped)
            add(body)
            add(f"+{cc} {body}")
            add(f"+{cc}-{body}" if sep == "-" else f"+{cc}{sep}{body}")
            add(f"(+{cc}) {body}")
            add(f"00{cc} {body}")

    return DorkResult([f'"{v}"' for v in variants], None)
