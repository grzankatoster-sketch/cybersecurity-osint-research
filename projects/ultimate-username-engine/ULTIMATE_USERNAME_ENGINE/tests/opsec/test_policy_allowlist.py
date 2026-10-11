"""Red-team: allowlist / scheme / port enforcement (phase 5.A / 5.C)."""

from __future__ import annotations

from ultimate_username.opsec.policy import EgressPolicy

PUBLIC = lambda host: ["140.82.121.6"]  # noqa: E731 - test shorthand resolver


def test_empty_allowlist_with_require_denies_all() -> None:
    policy = EgressPolicy(require_allowlist=True)
    assert not policy.check_target("api.github.com", 443, PUBLIC).allowed


def test_exact_and_parent_domain_match() -> None:
    policy = EgressPolicy(allowed_hosts=frozenset({"github.com"}), allowed_ports=frozenset({443}))
    assert policy.check_target("github.com", 443, PUBLIC).allowed
    assert policy.check_target("api.github.com", 443, PUBLIC).allowed
    assert not policy.check_target("notgithub.com", 443, PUBLIC).allowed
    assert not policy.check_target("github.com.evil.com", 443, PUBLIC).allowed


def test_port_not_allowed() -> None:
    policy = EgressPolicy(allowed_hosts=frozenset({"github.com"}), allowed_ports=frozenset({443}))
    assert not policy.check_target("github.com", 8080, PUBLIC).allowed


def test_scheme_restricted_to_https_by_default() -> None:
    policy = EgressPolicy(allowed_hosts=frozenset({"github.com"}))
    assert not policy.check_url("http://github.com/x", PUBLIC).allowed
    assert not policy.check_url("file:///etc/passwd", PUBLIC).allowed
    assert not policy.check_url("gopher://github.com/", PUBLIC).allowed


def test_credentials_in_url_rejected() -> None:
    policy = EgressPolicy(allowed_hosts=frozenset({"github.com"}))
    assert not policy.check_url("https://user:pass@github.com/", PUBLIC).allowed


def test_allowed_url_passes() -> None:
    policy = EgressPolicy(allowed_hosts=frozenset({"github.com"}), allowed_ports=frozenset({443}))
    decision = policy.check_url("https://api.github.com/users/x", PUBLIC)
    assert decision.allowed
