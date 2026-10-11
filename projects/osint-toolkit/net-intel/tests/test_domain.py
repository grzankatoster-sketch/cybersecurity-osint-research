import pytest

from net_intel.domain import normalize_domain


@pytest.mark.parametrize("raw,expected", [
    ("Example.COM", "example.com"),
    ("https://www.Example.com/path?q=1#x", "www.example.com"),
    ("example.com.", "example.com"),
    ("example.com:8443", "example.com"),
    ("admin@example.com", "example.com"),
    ("  example.com  ", "example.com"),
    ("zażółć.pl", "xn--za-6ja4f8n1l.pl"),
])
def test_normalize_ok(raw, expected):
    assert normalize_domain(raw) == expected


@pytest.mark.parametrize("raw", ["", "localhost", "-bad.com", "a..b.com", "exa mple.com", "x" * 64 + ".com", "a_b.com"])
def test_normalize_rejects(raw):
    with pytest.raises(ValueError):
        normalize_domain(raw)
