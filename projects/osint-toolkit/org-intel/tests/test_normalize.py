from __future__ import annotations

import pytest

from org_intel.normalize import (
    company_names_match,
    normalize_company_name,
    normalize_domain,
    normalize_krs,
    normalize_nip,
    normalize_regon,
    normalize_url,
)


@pytest.mark.parametrize(
    "raw",
    [
        "example.test",
        "WWW.Example.TEST",
        "https://www.example.test/",
        "http://example.test:8080/sciezka?x=1#frag",
        "https://user:pass@example.test/",
        "example.test.",
    ],
)
def test_normalize_domain_warianty(raw):
    assert normalize_domain(raw) == "example.test"


def test_normalize_domain_idn():
    ascii_form = normalize_domain("zażółć.pl")
    assert ascii_form.startswith("xn--") and ascii_form.endswith(".pl") and ascii_form.isascii()
    assert normalize_domain("ZAŻÓŁĆ.PL") == ascii_form
    assert normalize_domain("https://www.münchen.test/") == "xn--mnchen-3ya.test"


def test_normalize_domain_subdomena_zachowana():
    assert normalize_domain("https://shop.example.test/x") == "shop.example.test"


@pytest.mark.parametrize(
    "raw", ["", "   ", "localhost", "a b.test", "-x.test", "http://", "1.2.3.4", "exa mple.test", "a..test"]
)
def test_normalize_domain_odrzuca_smieci(raw):
    with pytest.raises(ValueError):
        normalize_domain(raw)


def test_nazwy_firm_formy_prawne():
    variants = [
        "Example Sp. z o.o.",
        "EXAMPLE sp.z o.o.",
        "Example  spółka z ograniczoną odpowiedzialnością",
        "„Example” Sp. z o. o.",
        "Example sp z oo",
    ]
    keys = {normalize_company_name(v) for v in variants}
    assert keys == {"example sp. z o.o."}


def test_nazwy_firm_inne_formy_i_diakrytyki():
    assert (
        normalize_company_name("Żółć Bank S.A.")
        == normalize_company_name("zolc bank spółka akcyjna")
        == "zolc bank s.a."
    )
    assert normalize_company_name("Foo sp.k.") == normalize_company_name("Foo Spółka Komandytowa") == "foo sp.k."
    assert normalize_company_name("Foo sp.j.") == normalize_company_name("Foo spółka jawna") == "foo sp.j."
    assert normalize_company_name('Foo   Bar "Baz"  S.A.') == "foo bar baz s.a."


def test_nazwa_formy_tylko_na_koncu():
    assert normalize_company_name("S.A. Foo") == "s a foo"


def test_company_names_match_bez_formy():
    assert company_names_match("Example", "Example Sp. z o.o.")
    assert not company_names_match("Example Sp. z o.o.", "Example S.A.")


def test_nip_regon_krs_sumy_kontrolne():
    assert normalize_nip("527-100-12-38") == "5271001238"
    assert normalize_nip("PL 5271001238") == "5271001238"
    assert normalize_nip("5271001239") is None
    assert normalize_nip("123") is None
    assert normalize_regon("360123459") == "360123459"
    assert normalize_regon("360123458") is None
    assert normalize_regon("12345678500010") == "12345678500010"
    assert normalize_regon("12345678500011") is None
    assert normalize_krs("123456") == "0000123456"
    assert normalize_krs("0000000000") is None
    assert normalize_krs("12345678901") is None


def test_normalize_url_dedup():
    base = normalize_url("https://Example.TEST/a/b")[0]
    assert normalize_url("https://example.test/a/b/")[0] == base
    assert normalize_url("https://example.test/a/b?utm_source=x&utm_medium=y")[0] == base
    assert normalize_url("https://example.test/a/b#frag")[0] == base
    assert normalize_url("http://example.test:80/a/b")[0] == base
    assert normalize_url("https://example.test/a/b?id=2")[0] != base
    assert normalize_url("https://user:pw@example.test/a/b")[1] == "https://example.test/a/b"


@pytest.mark.parametrize(
    "raw", ["", "example.test/a", "ftp://example.test/a", "javascript:alert(1)", "https://", "https://a b.test"]
)
def test_normalize_url_odrzuca(raw):
    with pytest.raises(ValueError):
        normalize_url(raw)
