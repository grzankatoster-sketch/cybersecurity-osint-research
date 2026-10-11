import re

import phonenumbers
import pytest
from phonenumbers import PhoneNumberFormat

from phone_check.dorks import dork_variants


def _digits(s: str) -> str:
    return re.sub(r"\D", "", s)


@pytest.mark.parametrize(
    "raw, region",
    [
        ("+48 603 123 456 ext. 12", "PL"),
        ("+354 611 1234 ext. 99", "IS"),  # NSN 7 cyfr
        ("+47 412 34 567 ext. 3", "NO"),  # NSN 8 cyfr
        ("+49 30 1234567 ext. 45", "DE"),
        ("+1 201-555-0123 ext. 7", "US"),
    ],
)
def test_dork_variants_do_not_add_or_lose_digits(raw, region):
    num = phonenumbers.parse(raw, region)
    assert num.extension  # wejscie naprawde ma numer wewnetrzny
    cc = str(num.country_code)
    nsn = phonenumbers.national_significant_number(num)
    bare = phonenumbers.PhoneNumber()
    bare.merge_from(num)
    bare.extension = None
    national = _digits(phonenumbers.format_number(bare, PhoneNumberFormat.NATIONAL))
    allowed = {cc + nsn, "00" + cc + nsn, nsn, national}

    variants = dork_variants(raw, region)
    assert variants, "brak wariantow dla poprawnego numeru"
    bad = [v for v in variants if _digits(v) not in allowed]
    assert bad == [], f"warianty z innym zestawem cyfr niz numer abonenta: {bad}"
