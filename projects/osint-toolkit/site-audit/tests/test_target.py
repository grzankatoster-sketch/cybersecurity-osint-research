import pytest

from site_audit.target import BlockedAddress, TargetError, is_public, parse_target, resolve_checked


def test_defaults_to_https_and_root():
    t = parse_target("Example.COM")
    assert (t.scheme, t.host, t.port, t.path) == ("https", "example.com", 443, "/")
    assert t.url == "https://example.com/"


def test_keeps_path_query_port_and_drops_fragment():
    t = parse_target("http://example.com:8080/a/b?x=1#frag")
    assert t.url == "http://example.com:8080/a/b?x=1"


def test_idn_to_punycode():
    assert parse_target("żabka.pl").host == "xn--abka-99a.pl"


def test_ipv6_literal():
    t = parse_target("https://[2001:db8::1]:8443/")
    assert t.host == "2001:db8::1" and t.netloc == "[2001:db8::1]:8443"


@pytest.mark.parametrize("raw", [
    "", "ftp://example.com", "file:///etc/passwd", "javascript:alert(1)", "http://user:pw@example.com/",
    "http://exa mple.com/", "http://example.com:99999/", "http:///x", "http://" + "a" * 64 + ".com/",
])
def test_rejects_bad_targets(raw):
    with pytest.raises(TargetError):
        parse_target(raw)


@pytest.mark.parametrize("ip,public", [
    ("93.184.216.34", True), ("2606:4700::1", True),
    ("127.0.0.1", False), ("10.1.2.3", False), ("192.168.0.1", False), ("172.16.0.1", False),
    ("169.254.169.254", False), ("100.64.0.1", False), ("0.0.0.0", False), ("::1", False),
    ("fe80::1%eth0", False), ("fc00::1", False), ("::ffff:127.0.0.1", False), ("224.0.0.1", False),
    ("192.0.2.1", False),
])
def test_is_public(ip, public):
    assert is_public(ip) is public


def test_blocks_if_any_address_private():
    with pytest.raises(BlockedAddress):
        resolve_checked("x.test", 80, lambda h, p: ["93.184.216.34", "10.0.0.5"])


def test_allow_private_passes():
    assert resolve_checked("x.test", 80, lambda h, p: ["127.0.0.1"], allow_private=True) == ["127.0.0.1"]


def test_resolution_failure_is_target_error_not_block():
    def boom(h, p):
        raise OSError("NXDOMAIN")
    with pytest.raises(TargetError) as ei:
        resolve_checked("x.test", 80, boom)
    assert not isinstance(ei.value, BlockedAddress)
