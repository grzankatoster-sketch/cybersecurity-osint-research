"""Dorki: grupowanie 2-3-2-2 dotyczy zapisu stacjonarnego, nie numerow komorkowych."""

import re

import phonenumbers
from phonenumbers import PhoneNumberType

from phone_check.dorks import dork_variants


def test_mobile_number_has_no_landline_2_3_2_2_grouping():
    raw = "603123456"
    # Warunek wstepny: biblioteka klasyfikuje numer jako komorkowy.
    assert phonenumbers.number_type(phonenumbers.parse(raw, "PL")) == PhoneNumberType.MOBILE

    variants = dork_variants(raw, "PL")
    # zwykle zapisy komorkowe nadal sa
    assert '"603 123 456"' in variants
    assert '"+48 603 123 456"' in variants
    # zapis stacjonarny 2-3-2-2 (np. "60 312 34 56") nie pasuje do numeru komorkowego
    bad = [v for v in variants if re.search(r"(?<!\d)60[ .-]312[ .-]34[ .-]56(?!\d)", v)]
    assert bad == [], f"grupowanie stacjonarne dla komorki: {bad}"


def test_landline_keeps_2_3_2_2_grouping():
    raw = "123456789"  # kierunkowy 12 = Krakow
    assert phonenumbers.number_type(phonenumbers.parse(raw, "PL")) == PhoneNumberType.FIXED_LINE

    variants = dork_variants(raw, "PL")
    assert '"12 345 67 89"' in variants
    assert '"123 456 789"' in variants
