"""Kod jezyka opisow (lang) powinien byc niezalezny od wielkosci liter i bialych znakow, jak region."""

import pytest

from phone_check.core import analyze

NUMBER = "+48 22 123 45 67"  # stacjonarny, Warszawa


@pytest.mark.parametrize("lang", ["PL", " pl ", "Pl"])
def test_lang_case_and_whitespace_do_not_change_descriptions(lang):
    ref = analyze(NUMBER, "PL", "pl")
    assert ref.valid
    assert ref.country_name == "Polska"

    info = analyze(NUMBER, "PL", lang)
    assert info.valid
    # Ten sam jezyk zapisany inaczej nie moze po cichu przelaczyc opisow na angielski.
    assert info.country_name == ref.country_name
    assert info.geo_description == ref.geo_description
    assert info.carrier == ref.carrier
