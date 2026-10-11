import re

from ultimate_username.variants import ALLOWED, ascii_fold, generate, split_parts


def test_ascii_fold_and_split():
    assert ascii_fold("Łukasz Żółć") == "lukasz zolc"
    assert split_parts("JanKowalski") == ["jan", "kowalski"]
    assert split_parts("Sampler51") == ["sampler", "51"]
    assert split_parts("jan.kowalski_x") == ["jan", "kowalski", "x"]


def test_person_name_orders_common_patterns_first():
    out = generate("Jan Kowalski", limit=20)
    assert out[0] == "jankowalski"
    assert out[:4] == ["jankowalski", "jan.kowalski", "jan_kowalski", "jan-kowalski"]
    assert "jkowalski" in out and "kowalskijan" in out


def test_typed_name_is_always_first_and_unique():
    out = generate("jkowalski", limit=5)
    assert out[0] == "jkowalski"
    assert len(out) == len(set(out)) == 5


def test_limit_is_hard_and_zero_gives_empty():
    assert len(generate("Jan Kowalski", limit=3)) == 3
    assert generate("Jan Kowalski", limit=0) == []
    assert generate("", limit=5) == []


def test_years_and_leet_are_opt_in():
    plain = generate("sampler", limit=30)
    assert not any("1990" in v or "54mpl3r" == v for v in plain)
    with_years = generate("sampler", years=[1990, 90], leet=True, limit=30)
    assert "sampler1990" in with_years and "sampler_90" in with_years
    assert "54mpl3r" in with_years


def test_digit_suffix_name_keeps_number_variants():
    out = generate("Sampler51", limit=20)
    assert out[0] == "sampler51"
    assert "sampler_51" in out and "51sampler" in out


def test_all_variants_match_name_regex():
    for text in ("Łukasz Żółć", "a", "x" * 80, "Anna Maria Nowak-Kowalska", "ab"):
        for variant in generate(text, years=[1999], leet=True, limit=40):
            assert ALLOWED.fullmatch(variant) and re.fullmatch(r"[a-z0-9._-]{2,40}", variant)
