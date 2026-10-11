"""Numer tylko lokalny (bez kierunkowego) nie moze dostac pelnego E.164."""

import phonenumbers
from phonenumbers import ValidationResult

from phone_check.core import analyze


def test_local_only_number_has_no_e164_and_is_not_possible():
    raw, region = "253 0000", "US"
    # Warunek wstepny: biblioteka klasyfikuje wejscie jako numer tylko lokalny (brak kierunkowego).
    num = phonenumbers.parse(raw, region)
    assert phonenumbers.is_possible_number_with_reason(num) == ValidationResult.IS_POSSIBLE_LOCAL_ONLY
    assert not phonenumbers.is_valid_number(num)

    info = analyze(raw, region)
    assert info.parsed
    assert not info.valid
    # Niepelny numer nie jest 'mozliwy' jako kompletny numer i nie ma poprawnego zapisu E.164.
    assert info.possible is False, f"numer lokalny uznany za mozliwy: e164={info.e164!r}"
    assert info.e164 is None
    assert info.international is None
    assert info.rfc3966 is None
    assert info.error == "numer niepoprawny (zła długość lub prefiks)"
