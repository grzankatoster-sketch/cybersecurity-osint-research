import re

from phone_check.dorks import dork_variants


def test_dork_variants_with_extension_are_not_mangled_by_hyphens():
    variants = dork_variants("+48 603 123 456 ext. 12", "PL")
    # numer nadal daje zwykle warianty zapisu
    assert '"+48603123456"' in variants
    assert '"+48-603-123-456"' in variants
    # zaden wariant nie moze miec liter sklejonych myslnikiem z cyframi (np. "-ext.-12")
    bad = [v for v in variants if re.search(r"[A-Za-z]\.?-|-[A-Za-z]", v)]
    assert bad == [], f"znieksztalcone warianty: {bad}"
