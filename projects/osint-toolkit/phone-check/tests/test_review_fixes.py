"""Testy poprawek z przegladu logiki (offline). Kazdy test odtwarza konkretny blad."""

import csv
import inspect
import json
import os

import pytest

import phone_check.cli as cli_mod
from phone_check.cli import CSV_EXCLUDED, CSV_FIELDS, build_parser, csv_safe, main, write_csv
from phone_check.core import DEFAULT_LANG, DEFAULT_REGION, PhoneInfo, analyze
from phone_check.dorks import DORK_IMPOSSIBLE, DORK_UNPARSEABLE, dork_result, dork_variants


def _batch_file(tmp_path, content="603123456\n12 345 67 89\n"):
    src = tmp_path / "numery.txt"
    src.write_text(content, encoding="utf-8")
    return src


def _read_csv(path):
    return list(csv.DictReader(path.open(encoding="utf-8-sig"), delimiter=";"))


# 1. kolizje sciezek ----------------------------------------------------------

def test_collision_input_equals_json(tmp_path, capsys):
    src = _batch_file(tmp_path)
    before = src.read_bytes()
    assert main(["--file", str(src), "--json", str(src)]) == 2
    assert src.read_bytes() == before
    assert "ta sama ścieżka" in capsys.readouterr().err


def test_collision_input_equals_csv(tmp_path):
    src = _batch_file(tmp_path)
    before = src.read_bytes()
    assert main(["--file", str(src), "--csv", str(src)]) == 2
    assert src.read_bytes() == before


def test_collision_json_equals_csv_writes_nothing(tmp_path):
    src = _batch_file(tmp_path)
    out = tmp_path / "wyniki.dat"
    assert main(["--file", str(src), "--json", str(out), "--csv", str(out)]) == 2
    assert not out.exists()


def test_collision_via_different_spelling(tmp_path):
    src = _batch_file(tmp_path)
    (tmp_path / "sub").mkdir()
    sneaky = tmp_path / "sub" / ".." / "numery.txt"
    before = src.read_bytes()
    assert main(["--file", str(src), "--json", str(sneaky)]) == 2
    assert src.read_bytes() == before


def test_collision_via_hardlink_samefile(tmp_path):
    src = _batch_file(tmp_path)
    link = tmp_path / "link.json"
    try:
        os.link(src, link)
    except (OSError, NotImplementedError, AttributeError):
        pytest.skip("twarde linki niedostepne")
    before = src.read_bytes()
    assert main(["--file", str(src), "--json", str(link)]) == 2
    assert src.read_bytes() == before


def test_collision_single_number_json_equals_csv(tmp_path):
    out = tmp_path / "x.out"
    assert main(["603123456", "--json", str(out), "--csv", str(out)]) == 2
    assert not out.exists()


# 2. zapis atomowy + obsluga OSError -----------------------------------------

def test_write_is_atomic_on_replace_failure(tmp_path, monkeypatch, capsys):
    src = _batch_file(tmp_path)
    out = tmp_path / "o.json"
    out.write_text("STARY", encoding="utf-8")

    def boom(*a, **k):
        raise OSError("symulowana awaria")

    monkeypatch.setattr(cli_mod.os, "replace", boom)
    assert main(["--file", str(src), "--json", str(out)]) == 2
    assert out.read_text(encoding="utf-8") == "STARY"  # oryginal nietkniety
    assert sorted(p.name for p in tmp_path.iterdir()) == ["numery.txt", "o.json"]  # brak plikow .tmp
    err = capsys.readouterr().err
    assert "JSON" in err and "symulowana awaria" in err


def test_no_partial_file_when_target_is_new(tmp_path, monkeypatch):
    src = _batch_file(tmp_path)
    out = tmp_path / "o.csv"

    def boom(*a, **k):
        raise OSError("x")

    monkeypatch.setattr(cli_mod.os, "replace", boom)
    assert main(["--file", str(src), "--csv", str(out)]) == 2
    assert not out.exists() and [p.name for p in tmp_path.iterdir()] == ["numery.txt"]


def test_export_failure_reports_which_succeeded(tmp_path, capsys):
    src = _batch_file(tmp_path)
    out_json = tmp_path / "o.json"
    bad_csv = tmp_path / "nie_ma_katalogu" / "o.csv"
    assert main(["--file", str(src), "--json", str(out_json), "--csv", str(bad_csv)]) == 2
    cap = capsys.readouterr()
    assert json.loads(out_json.read_text(encoding="utf-8"))
    assert "Zapisano JSON" in cap.out
    assert "CSV" in cap.err and "nie zapisano" in cap.err.lower()


def test_export_failure_all_failed_message(tmp_path, capsys):
    bad = tmp_path / "brak" / "o.json"
    assert main(["603123456", "--json", str(bad)]) == 2
    assert "żaden eksport" in capsys.readouterr().err


# 3. pusty plik ----------------------------------------------------------------

def test_empty_file_is_error(tmp_path, capsys):
    f = tmp_path / "pusty.txt"
    f.write_text("", encoding="utf-8")
    assert main(["--file", str(f)]) == 2
    assert "nie zawiera żadnych numerów" in capsys.readouterr().err


def test_comments_only_file_is_error_and_writes_nothing(tmp_path):
    f = tmp_path / "kom.txt"
    f.write_text("# a\n\n   # b\n", encoding="utf-8")
    out = tmp_path / "o.json"
    assert main(["--file", str(f), "--json", str(out)]) == 2
    assert not out.exists()


# 4. numer + --file ------------------------------------------------------------

def test_positional_and_file_mutually_exclusive(tmp_path, capsys):
    f = _batch_file(tmp_path)
    with pytest.raises(SystemExit) as e:
        main(["603123456", "--file", str(f)])
    assert e.value.code == 2
    assert "--file" in capsys.readouterr().err


# 5. kodowanie -----------------------------------------------------------------

def test_non_utf8_file_is_controlled_error(tmp_path, capsys):
    f = tmp_path / "cp1250.txt"
    f.write_bytes("603123456\nł\n".encode("cp1250"))
    assert main(["--file", str(f)]) == 2
    assert "UTF-8" in capsys.readouterr().err


def test_utf8_bom_file_is_accepted(tmp_path):
    f = tmp_path / "bom.txt"
    f.write_bytes(b"\xef\xbb\xbf603123456\n")
    assert main(["--file", str(f)]) == 0


# 6. CSV: carrier_note + neutralizacja formul ----------------------------------

def test_csv_has_carrier_note_column(tmp_path):
    src = _batch_file(tmp_path)
    out = tmp_path / "o.csv"
    main(["--file", str(src), "--csv", str(out)])
    rows = _read_csv(out)
    assert "carrier_note" in rows[0]
    assert "przeniesion" in rows[0]["carrier_note"]


def test_csv_columns_cover_all_fields_except_documented():
    all_fields = set(PhoneInfo.__dataclass_fields__)
    assert set(CSV_FIELDS) | set(CSV_EXCLUDED) == all_fields
    assert not set(CSV_FIELDS) & set(CSV_EXCLUDED)


@pytest.mark.parametrize("raw", ["=1+1", "+48 603 123 456", "-5", "@SUM(A1)", "\t=x", "\r=x"])
def test_csv_safe_prefixes_formula_triggers(raw):
    assert csv_safe(raw) == "'" + raw


@pytest.mark.parametrize("raw", ["", "603 123 456", "tel:+48-603", "Kraków", "a=b"])
def test_csv_safe_leaves_ordinary_text(raw):
    assert csv_safe(raw) == raw


def test_csv_neutralises_formulas_and_numbers_json_unchanged(tmp_path):
    src = _batch_file(tmp_path, "=1+1\n+48 603 123 456\n@cmd\n")
    out_csv, out_json = tmp_path / "o.csv", tmp_path / "o.json"
    main(["--file", str(src), "--csv", str(out_csv), "--json", str(out_json)])
    rows = _read_csv(out_csv)
    assert rows[0]["input"] == "'=1+1"
    assert rows[1]["input"] == "'+48 603 123 456" and rows[1]["e164"] == "'+48603123456"
    assert rows[1]["international"].startswith("'+48")
    assert rows[2]["input"] == "'@cmd"
    for r in rows:
        for v in r.values():
            assert not v or v[0] not in "=+-@\t\r"
    data = json.loads(out_json.read_text(encoding="utf-8"))
    assert data[0]["input"] == "=1+1" and data[1]["e164"] == "+48603123456"


def test_write_csv_direct_neutralises_text_not_numbers(tmp_path):
    info = PhoneInfo(input="-1", region_hint="PL", error="=err", country_code=48)
    out = tmp_path / "d.csv"
    write_csv(out, [info])
    row = _read_csv(out)[0]
    assert row["input"] == "'-1" and row["error"] == "'=err" and row["country_code"] == "48"


# 7. podsumowanie wsadowe ------------------------------------------------------

def test_batch_summary_shows_error_even_with_e164(tmp_path, capsys):
    src = _batch_file(tmp_path, "000000000\n")  # mozliwy dlugosciowo, niepoprawny: ma e164 i error
    out = tmp_path / "o.json"
    assert main(["--file", str(src), "--json", str(out)]) == 1
    line = next(ln for ln in capsys.readouterr().out.splitlines() if ln.startswith("[BLAD]"))
    assert "niepoprawny w planie numeracji" in line


# 8. dorki ---------------------------------------------------------------------

def test_dork_result_distinguishes_reasons():
    assert dork_result("abc", "PL").reason == DORK_UNPARSEABLE
    assert dork_result("12", "PL").reason == DORK_IMPOSSIBLE
    ok = dork_result("603123456", "PL")
    assert ok.reason is None and ok.variants == dork_variants("603123456", "PL")


def test_cli_dorks_messages_differ(capsys):
    main(["abc", "--dorks"])
    assert "nie do sparsowania" in capsys.readouterr().out
    main(["12", "--dorks"])
    out = capsys.readouterr().out
    assert "niemożliwa długość" in out and "nie do sparsowania" not in out


# 9. stale ---------------------------------------------------------------------

def test_defaults_single_source_of_truth():
    assert (DEFAULT_REGION, DEFAULT_LANG) == ("PL", "pl")
    args = build_parser().parse_args([])
    assert args.region == DEFAULT_REGION and args.lang == DEFAULT_LANG
    assert inspect.signature(analyze).parameters["region"].default == DEFAULT_REGION
    assert inspect.signature(analyze).parameters["lang"].default == DEFAULT_LANG
    assert inspect.signature(dork_variants).parameters["region"].default == DEFAULT_REGION
    assert analyze("603123456", "").region_hint == DEFAULT_REGION
