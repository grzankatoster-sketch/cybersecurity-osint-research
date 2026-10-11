"""Konwersje GPS: DMS (stopnie, minuty, sekundy) + ref N/S/E/W -> stopnie dziesietne."""

from __future__ import annotations

import math
from typing import Any


def to_float(value: Any) -> float | None:
    """Rational/IFDRational/(licznik, mianownik)/liczba -> float; None gdy nieprawidlowe (np. mianownik 0)."""
    try:
        if isinstance(value, tuple) and len(value) == 2:
            num, den = value
            if den == 0:
                return None
            f = float(num) / float(den)
        else:
            f = float(value)
    except (TypeError, ValueError, ZeroDivisionError):
        return None
    return f if math.isfinite(f) else None


def dms_to_decimal(dms: Any, ref: Any) -> float | None:
    """((st, min, sek), 'N'|'S'|'E'|'W') -> stopnie dziesietne ze znakiem (S i W ujemne)."""
    if dms is None:
        return None
    try:
        parts = list(dms)
    except TypeError:
        return None
    if len(parts) != 3:
        return None
    vals = [to_float(p) for p in parts]
    if any(v is None for v in vals):
        return None
    deg, minutes, seconds = vals
    result = abs(deg) + minutes / 60.0 + seconds / 3600.0
    if isinstance(ref, bytes):
        ref = ref.decode("ascii", "ignore")
    ref = (str(ref).strip().strip("\x00").upper()[:1]) if ref is not None else ""
    if ref in ("S", "W") or deg < 0:
        result = -result
    return result


def valid_coordinates(lat: float | None, lon: float | None) -> bool:
    """Zakres poprawny; (0, 0) traktujemy jako 'brak fixa' (aparaty zapisuja tak puste GPS)."""
    if lat is None or lon is None:
        return False
    if not (-90.0 <= lat <= 90.0 and -180.0 <= lon <= 180.0):
        return False
    return not (lat == 0.0 and lon == 0.0)


def format_coords(lat: float, lon: float) -> str:
    return f"{lat:.6f}, {lon:.6f}"


def suspicious_reason(lat: float | None, lon: float | None) -> str | None:
    """Powod podejrzenia, ze wspolrzedne sa placeholderem; None gdy wyglada normalnie."""
    if lat is None or lon is None:
        return None
    if lat == 0.0 or lon == 0.0:
        return "zerowa szerokosc lub dlugosc - mozliwy placeholder"
    if lat.is_integer() and lon.is_integer():
        return "pelne stopnie bez minut i sekund - mozliwy placeholder"
    return None
