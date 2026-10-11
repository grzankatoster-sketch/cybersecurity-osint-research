"""Lab: numer niegeograficzny (+800 itp.) nie moze dostac pseudo-regionu '001' jako kodu kraju ISO."""

import phonenumbers
from phonenumbers import PhoneNumberFormat

from phone_check.core import analyze


def _non_geo_example(cc: int) -> str:
    num = phonenumbers.example_number_for_non_geo_entity(cc)
    assert num is not None
    return phonenumbers.format_number(num, PhoneNumberFormat.E164)


def test_non_geographic_number_has_no_iso_region():
    raw = _non_geo_example(800)  # miedzynarodowy numer bezplatny (UIFN)
    info = analyze(raw, "PL")
    # warunki wstepne: numer poprawny, kierunkowy zachowany
    assert info.parsed and info.valid
    assert info.country_code == 800
    assert info.e164 == raw
    # region to kod kraju ISO 3166 (dwie litery) albo brak - nigdy pseudo-region '001'
    assert info.region is None or (len(info.region) == 2 and info.region.isalpha()), info.region


def test_geographic_number_keeps_iso_region():
    info = analyze("+48 603 123 456", "PL")
    assert info.valid and info.region == "PL"
