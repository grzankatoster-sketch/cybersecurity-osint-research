"""Testy offline: zadnych zapytan sieciowych, tylko dane wbudowane w phonenumbers."""

import csv
import json

import phonenumbers
import pytest
from phonenumbers import PhoneNumberFormat, PhoneNumberType

from phone_check.cli import main, read_numbers
from phone_check.core import UKE_URL, analyze
from phone_check.dorks import dork_variants


def _example(region: str, ntype=None, fmt=PhoneNumberFormat.E164) -> str:
    num = (
        phonenumbers.example_number(region)
        if ntype is None
        else phonenumbers.example_number_for_type(region, ntype)
    )
    return phonenumbers.format_number(num, fmt)


def test_example_number_pl_is_valid_with_all_formats():
    info = analyze(_example("PL"), "PL")
    assert info.valid and info.possible and info.parsed
    assert info.region == "PL" and info.country_code == 48
    assert info.e164.startswith("+48") and len(info.e164) == 12
    assert info.international.startswith("+48 ")
    assert info.rfc3966.startswith("tel:+48-")
    assert info.national and not info.national.startswith("+")
    assert info.timezones == ["Europe/Warsaw"]


def test_polish_mobile():
    raw = _example("PL", PhoneNumberType.MOBILE)
    info = analyze(raw, "PL")
    assert info.valid
    assert info.line_type_code == "MOBILE"
    assert info.line_type == "komórkowy"
    assert info.carrier_check_url == UKE_URL
    assert "numeracja.uke.gov.pl" in info.carrier_note
    assert "przeniesion" in info.carrier_note


def test_polish_landline_has_polish_geo_description():
    info = analyze("12 345 67 89", "PL")  # kierunkowy 12 = Krakow
    assert info.valid
    assert info.line_type_code == "FIXED_LINE"
    assert info.line_type == "stacjonarny"
    assert info.geo_description == "Kraków"
    assert info.e164 == "+48123456789"


@pytest.mark.parametrize(
    "raw", ["603123456", "603 123 456", "603-123-456", "+48 603 123 456", "0048603123456", "(+48) 603123456"]
)
def test_any_input_format_gives_same_e164(raw):
    assert analyze(raw, "PL").e164 == "+48603123456"


def test_invalid_number():
    info = analyze("123", "PL")
    assert info.parsed and not info.valid and not info.possible
    assert info.error
    assert info.e164 is None and info.line_type is None and info.carrier is None


def test_possible_but_not_valid():
    info = analyze("000000000", "PL")  # 9 cyfr, ale prefiks spoza planu
    assert info.possible and not info.valid
    assert "niepoprawny" in info.error


def test_unparseable_does_not_raise():
    info = analyze("abc", "PL")
    assert not info.parsed and not info.valid
    assert info.error


def test_toll_free_and_premium_types():
    assert analyze(_example("PL", PhoneNumberType.TOLL_FREE), "PL").line_type_code == "TOLL_FREE"
    assert analyze(_example("PL", PhoneNumberType.PREMIUM_RATE), "PL").line_type_code == "PREMIUM_RATE"


def test_foreign_number_with_region_and_generic_note():
    info = analyze(_example("DE"), "PL")  # numer miedzynarodowy z + ignoruje region domyslny
    assert info.valid and info.region == "DE" and info.country_code == 49
    assert info.carrier_check_url is None
    assert "przenosić" in info.carrier_note
    assert analyze(_example("US", fmt=PhoneNumberFormat.NATIONAL), "US").region == "US"


def test_carrier_for_country_with_data():
    # Prefiks 603 to pula Plusa; operator z planu numeracji jest niepustym tekstem, ale nie dowodem
    info = analyze("603123456", "PL")
    assert info.carrier
    assert "NIE jest pewny" in info.carrier_note
    assert analyze("+447400123456", "GB").carrier
    # numery bezplatne nie maja operatora w planie
    assert analyze("+48 800 123 456", "PL").carrier is None


def test_dorks_variants_for_polish_mobile():
    v = dork_variants("603123456", "PL")
    for expected in [
        '"+48603123456"',
        '"+48 603 123 456"',
        '"603 123 456"',
        '"603-123-456"',
        '"603123456"',
        '"48603123456"',
        '"0048603123456"',
        '"+48 603-123-456"',
    ]:
        assert expected in v
    assert all(x.startswith('"') and x.endswith('"') for x in v)
    assert len(v) == len(set(v))


def test_dorks_empty_for_bad_number():
    assert dork_variants("abc", "PL") == []
    assert dork_variants("12", "PL") == []


def test_dorks_from_example_number_pl():
    raw = _example("PL")
    v = dork_variants(raw, "PL")
    assert '"+48123456789"' in v and '"123 456 789"' in v


def test_read_numbers_skips_blank_and_comments(tmp_path):
    f = tmp_path / "n.txt"
    f.write_text("﻿603123456\n\n# komentarz\n  +48 12 345 67 89  \n", encoding="utf-8")
    assert read_numbers(f) == ["603123456", "+48 12 345 67 89"]


def test_cli_single(capsys):
    assert main(["603123456", "--dorks"]) == 0
    out = capsys.readouterr().out
    assert "komórkowy" in out and "numeracja.uke.gov.pl" in out and '"+48 603 123 456"' in out


def test_cli_invalid_returns_1(capsys):
    assert main(["123"]) == 1


def test_cli_batch_csv_json(tmp_path, capsys):
    src = tmp_path / "numery.txt"
    src.write_text("603123456\n123\n12 345 67 89\n", encoding="utf-8")
    out_json, out_csv = tmp_path / "o.json", tmp_path / "o.csv"
    rc = main(["--file", str(src), "--json", str(out_json), "--csv", str(out_csv)])
    assert rc == 1  # jeden niepoprawny
    data = json.loads(out_json.read_text(encoding="utf-8"))
    assert [d["valid"] for d in data] == [True, False, True]
    rows = list(csv.DictReader(out_csv.open(encoding="utf-8-sig"), delimiter=";"))
    assert len(rows) == 3 and rows[0]["e164"] == "'+48603123456" and rows[2]["geo_description"] == "Kraków"
    assert "poprawnych: 2" in capsys.readouterr().out


def test_cli_requires_input(capsys):
    assert main([]) == 2
