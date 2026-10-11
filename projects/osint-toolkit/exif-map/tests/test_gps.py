import math

from exif_map.gps import dms_to_decimal, valid_coordinates


def test_dms_north_east():
    assert math.isclose(dms_to_decimal((52, 13, 56.2), "N"), 52 + 13 / 60 + 56.2 / 3600)


def test_dms_south_west_negative():
    assert dms_to_decimal((33, 51, 54.0), "S") < 0
    assert math.isclose(dms_to_decimal((151, 12, 36.0), "W"), -(151 + 12 / 60 + 36 / 3600))


def test_ref_bytes_and_lowercase():
    assert dms_to_decimal((10, 0, 0), b"S") == -10.0
    assert dms_to_decimal((10, 0, 0), "w") == -10.0
    assert dms_to_decimal((10, 0, 0), "E") == 10.0


def test_rational_tuples_and_zero_denominator():
    assert math.isclose(dms_to_decimal(((52, 1), (30, 1), (0, 1)), "N"), 52.5)
    assert dms_to_decimal(((52, 1), (30, 0), (0, 1)), "N") is None


def test_bad_input():
    assert dms_to_decimal(None, "N") is None
    assert dms_to_decimal((1, 2), "N") is None


def test_valid_coordinates():
    assert valid_coordinates(52.2, 21.0)
    assert not valid_coordinates(0.0, 0.0)  # brak fixa
    assert not valid_coordinates(91.0, 10.0)
    assert not valid_coordinates(None, 10.0)
