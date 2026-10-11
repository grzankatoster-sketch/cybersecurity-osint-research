"""Spec: walidacja --region w CLI (offline). Nieznany kod regionu to blad wejscia (kod 2)."""

import pytest

from phone_check.cli import main


def _batch(tmp_path, content="603123456\n+48 12 345 67 89\n"):
    src = tmp_path / "numery.txt"
    src.write_text(content, encoding="utf-8")
    return src


# --- nowe zachowanie (dzis oblewa) -------------------------------------------

def test_unknown_region_single_number_is_input_error(capsys):
    # dzis: blad parsowania numeru i kod 1 (wyglada jak zly numer)
    assert main(["603123456", "--region", "XX"]) == 2
    cap = capsys.readouterr()
    assert "nieznany region" in cap.err and "XX" in cap.err
    assert "ISO" in cap.err
    assert cap.out == ""


def test_unknown_region_is_error_even_for_number_with_plus(capsys):
    # dzis: numer z + ignoruje region i wynik to 0 - literowka przechodzi niezauwazona
    assert main(["+48603123456", "--region", "Polska"]) == 2
    cap = capsys.readouterr()
    assert "nieznany region" in cap.err and "POLSKA" in cap.err
    assert cap.out == ""


def test_unknown_region_batch_writes_nothing(tmp_path, capsys):
    src = _batch(tmp_path)
    out_json, out_csv = tmp_path / "o.json", tmp_path / "o.csv"
    rc = main(["--file", str(src), "--region", "ZZ", "--json", str(out_json), "--csv", str(out_csv)])
    assert rc == 2
    assert not out_json.exists() and not out_csv.exists()
    assert sorted(p.name for p in tmp_path.iterdir()) == ["numery.txt"]
    cap = capsys.readouterr()
    assert "nieznany region" in cap.err and "ZZ" in cap.err
    assert "Razem:" not in cap.out


def test_unknown_region_with_dorks_prints_no_variants(capsys):
    assert main(["603123456", "--region", "UK", "--dorks"]) == 2  # poprawnie GB
    cap = capsys.readouterr()
    assert "nieznany region" in cap.err and "UK" in cap.err
    assert "Warianty" not in cap.out and cap.out == ""


@pytest.mark.parametrize("bad", ["001", "P", "PLN"])
def test_non_iso_region_codes_rejected(bad, capsys):
    assert main(["603123456", "--region", bad]) == 2
    assert "nieznany region" in capsys.readouterr().err


# --- dotychczasowe zachowanie bez zmian ---------------------------------------

@pytest.mark.parametrize("region", ["PL", "pl", " pl ", ""])
def test_known_or_empty_region_still_accepted(region, capsys):
    assert main(["603123456", "--region", region]) == 0
    cap = capsys.readouterr()
    assert "nieznany region" not in cap.err
    assert "komórkowy" in cap.out


def test_foreign_known_region_batch_unchanged(tmp_path, capsys):
    src = _batch(tmp_path, "+48603123456\n")
    out_json = tmp_path / "o.json"
    assert main(["--file", str(src), "--region", "de", "--json", str(out_json)]) == 0
    assert out_json.exists()
    assert "poprawnych: 1" in capsys.readouterr().out
