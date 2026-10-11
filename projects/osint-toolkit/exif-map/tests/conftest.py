from __future__ import annotations

from pathlib import Path

import pytest
from PIL import Image

IFD_EXIF, IFD_GPS = 0x8769, 0x8825


def make_image(path: Path, *, gps=None, taken="2024:05:01 10:00:00", make="TestCam", model="TC-1",
               software="Test 1.0", orientation=None, fmt=None, size=(64, 48)) -> Path:
    """Obraz Pillow z wstrzyknietym EXIF. gps = (lat_dms, lat_ref, lon_dms, lon_ref[, alt, alt_ref, direction])."""
    im = Image.new("RGB", size, (200, 30, 30))
    exif = Image.Exif()
    exif[0x010F] = make
    exif[0x0110] = model
    exif[0x0131] = software
    if orientation:
        exif[0x0112] = orientation
    if taken:
        exif.get_ifd(IFD_EXIF)[0x9003] = taken
    if gps:
        g = exif.get_ifd(IFD_GPS)
        g[1], g[2], g[3], g[4] = gps[1], gps[0], gps[3], gps[2]
        if len(gps) > 4:
            g[5], g[6] = gps[5], gps[4]
        if len(gps) > 6:
            g[16], g[17] = "T", gps[6]
    im.save(path, format=fmt, exif=exif)
    return path


# Warszawa ~ 52 13' 56.2" N, 21 0' 30.9" E
WARSAW = ((52, 13, 56.2), "N", (21, 0, 30.9), "E")


@pytest.fixture
def photos(tmp_path: Path) -> Path:
    d = tmp_path / "zdjecia"
    (d / "pod").mkdir(parents=True)
    make_image(d / "a.jpg", gps=WARSAW + (110.5, 0, 90.0), taken="2024:05:01 10:00:00")
    make_image(d / "pod" / "b.jpg", gps=((33, 51, 54.0), "S", (151, 12, 36.0), "W"), taken="2024:05:01 08:00:00")
    make_image(d / "c.png", taken="2024:05:02 12:00:00")  # bez GPS
    return d
