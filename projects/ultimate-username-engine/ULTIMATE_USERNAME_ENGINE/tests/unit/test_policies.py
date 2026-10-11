from datetime import UTC, datetime

import pytest

from ultimate_username.policies import retry_after


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        (None, None),
        ("garbage", None),
        ("NaN", None),
        ("inf", None),
        ("5", 5),
        ("-2", 0),
        ("Thu, 08 Oct 2026 12:00:05 GMT", 5),
    ],
)
def test_retry_after_delta_and_http_date(value, expected):
    assert retry_after(value, now=datetime(2026, 10, 8, 12, tzinfo=UTC)) == expected
