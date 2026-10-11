"""Red-team: SSRF defence in the egress policy (phase 5.B / 5.C)."""

from __future__ import annotations

import pytest

from ultimate_username.opsec.policy import EgressPolicy, classify_ip

PERMISSIVE_HOSTS = EgressPolicy(require_allowlist=False, allowed_ports=frozenset())


@pytest.mark.parametrize(
    "address",
    [
        "127.0.0.1",
        "0.0.0.0",
        "10.1.2.3",
        "172.16.5.4",
        "192.168.1.1",
        "169.254.169.254",  # AWS/GCP/Azure instance metadata
        "100.64.0.1",  # CGNAT
        "::1",
        "fe80::1",
        "fc00::1",
        "::ffff:169.254.169.254",  # IPv4-mapped metadata smuggling
        "::ffff:127.0.0.1",
    ],
)
def test_forbidden_addresses_are_rejected(address: str) -> None:
    assert classify_ip(address) is not None


@pytest.mark.parametrize("address", ["8.8.8.8", "1.1.1.1", "140.82.121.4", "2606:4700:4700::1111"])
def test_public_addresses_pass(address: str) -> None:
    assert classify_ip(address) is None


def test_literal_metadata_ip_blocked_without_dns() -> None:
    def resolver(host: str) -> list[str]:  # pragma: no cover - must not be called
        raise AssertionError("literal IP must not trigger DNS")

    decision = PERMISSIVE_HOSTS.check_target("169.254.169.254", 80, resolver)
    assert not decision.allowed
    assert "link-local" in decision.reason


def test_hostname_resolving_to_private_ip_blocked() -> None:
    decision = PERMISSIVE_HOSTS.check_target("evil.example.com", 443, lambda h: ["10.0.0.5"])
    assert not decision.allowed
    assert "private" in decision.reason
    assert decision.resolved_ips == ("10.0.0.5",)


def test_mixed_result_set_blocks_if_any_ip_forbidden() -> None:
    # A rebinding-style answer with one public and one internal address is denied.
    decision = PERMISSIVE_HOSTS.check_target(
        "evil.example.com", 443, lambda h: ["8.8.8.8", "169.254.169.254"]
    )
    assert not decision.allowed


def test_public_hostname_allowed() -> None:
    decision = PERMISSIVE_HOSTS.check_target("api.github.com", 443, lambda h: ["140.82.121.6"])
    assert decision.allowed
    assert decision.resolved_ips == ("140.82.121.6",)


def test_resolver_failure_is_fail_closed() -> None:
    def boom(host: str) -> list[str]:
        raise OSError("dns down")

    decision = PERMISSIVE_HOSTS.check_target("example.com", 443, boom)
    assert not decision.allowed
    assert "DNS" in decision.reason
