from exif_map.models import PhotoMeta
from exif_map.reader import _apply_gps, meta_from_exiftool


def _gps(alt, ref):
    return {1: "N", 2: (52, 13, 56.2), 3: "E", 4: (21, 0, 30.9), 5: ref, 6: alt}


def test_negative_altitude_with_below_sea_ref_stays_below_sea_level():
    m = PhotoMeta(path="x.jpg")
    _apply_gps(m, _gps(-30.0, 1))
    assert m.has_gps
    assert m.altitude == -30.0  # ref=1: ponizej poziomu morza, niezaleznie od znaku wartosci


def test_positive_altitude_with_below_sea_ref_still_works():
    m = PhotoMeta(path="x.jpg")
    _apply_gps(m, _gps(30.0, 1))
    assert m.altitude == -30.0


def test_pillow_and_exiftool_agree_on_altitude_sign():
    m = PhotoMeta(path="x.jpg")
    _apply_gps(m, _gps(-30.0, 1))
    e = meta_from_exiftool({"GPSLatitude": 52.2, "GPSLongitude": 21.0, "GPSAltitude": -30.0,
                            "GPSAltitudeRef": 1}, "x.jpg")
    assert e.altitude == -30.0
    assert m.altitude == e.altitude
