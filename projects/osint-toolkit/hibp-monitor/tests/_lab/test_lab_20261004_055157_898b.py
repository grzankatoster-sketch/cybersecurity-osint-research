from __future__ import annotations

import pytest

from hibp_monitor.http import HibpError, Response
from hibp_monitor.passwords import RANGE_URL, check_password, parse_range

SUFFIX = "1E4C9B93F3F0682250B6CF8331B7EE68FD8"  # SHA-1('password')[5:]
OTHER = "003D68EB55068C33ACE09247EE4C639306B"


class _Fake:
    def __init__(self, text: str):
        self.text = text
        self.calls = []

    def get(self, url, headers=None):
        self.calls.append((url, dict(headers or {})))
        return Response(200, self.text)


def _raises_hibp(fn) -> bool:
    try:
        fn()
    except HibpError:
        return True
    except Exception:
        return False
    return False


@pytest.mark.parametrize("bad_count", ["\u0660", "\u0663", "\uff13", "\u00b2"])
def test_parse_range_rejects_non_ascii_digit_count(bad_count):
    text = f"{OTHER}:2\n{SUFFIX}:{bad_count}\n"
    assert _raises_hibp(lambda: parse_range(text)), (
        f"licznik {bad_count!r} to nie liczba ASCII - uszkodzona odpowiedz musi dawac HibpError"
    )


def test_check_password_corrupt_zero_count_is_api_error_not_not_found():
    # '\u0660' (arabsko-indyjskie zero) nie jest poprawnym licznikiem API range
    c = _Fake(f"{OTHER}:3\n{SUFFIX}:\u0660\n")
    result = {}

    def run():
        result["count"] = check_password(c, "password")

    assert _raises_hibp(run), (
        f"uszkodzona odpowiedz dala wynik {result.get('count')!r} (NOT_FOUND) zamiast bledu API"
    )
