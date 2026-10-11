"""OPEN-01 regression: malformed OSINT_PROXY_* values must never weaken the egress policy."""

from __future__ import annotations

import pytest

from ultimate_username.opsec.config import ProxyConfig, load
from ultimate_username.opsec.server import ProxyError
from ultimate_username.opsec.transport_factory import build_transport

HOSTS = {"OSINT_PROXY_ALLOWED_HOSTS": "example.com"}


class _Inner:
    async def send(self, request):  # pragma: no cover - must never be reached
        raise AssertionError("direct transport must not be returned")

    async def close(self) -> None:  # pragma: no cover
        pass


def test_missing_values_keep_safe_defaults_without_errors() -> None:
    cfg = load({})
    assert cfg.errors == ()
    assert cfg.allowed_ports == frozenset({443})
    assert cfg.fail_closed is True and cfg.require_allowlist is True


@pytest.mark.parametrize("value", ["", "   "])
def test_blank_port_list_means_default_443(value: str) -> None:
    cfg = load({**HOSTS, "OSINT_PROXY_ALLOWED_PORTS": value})
    assert cfg.allowed_ports == frozenset({443}) and cfg.errors == ()


@pytest.mark.parametrize(
    "value", ["abc", ",,", ";", "0", "65536", "-1", "443,abc", "44 3", "²", "0x1bb", "443.0"]
)
def test_malformed_port_list_is_rejected_and_never_means_all_ports(value: str) -> None:
    cfg = load({**HOSTS, "OSINT_PROXY_ALLOWED_PORTS": value})
    assert cfg.allowed_ports == frozenset({443})
    assert cfg.errors and any("OSINT_PROXY_ALLOWED_PORTS" in e for e in cfg.validate())


def test_valid_port_list_with_spaces_is_accepted() -> None:
    cfg = load({**HOSTS, "OSINT_PROXY_ALLOWED_PORTS": " 8443 ; 443 "})
    assert cfg.allowed_ports == frozenset({443, 8443}) and cfg.errors == ()
    assert cfg.validate() == []


@pytest.mark.parametrize("value", ["flase", "maybe", "2", "tru", "yes please", "nope", "-1"])
def test_malformed_fail_closed_stays_fail_closed_and_blocks_start(value: str) -> None:
    cfg = load({**HOSTS, "OSINT_PROXY_FAIL_CLOSED": value})
    assert cfg.fail_closed is True
    assert any("OSINT_PROXY_FAIL_CLOSED" in p for p in cfg.validate())


@pytest.mark.parametrize("value", ["0", "false", "No", " OFF "])
def test_explicit_fail_closed_opt_out_is_still_honoured(value: str) -> None:
    cfg = load({**HOSTS, "OSINT_PROXY_FAIL_CLOSED": value})
    assert cfg.fail_closed is False and cfg.errors == ()


def test_malformed_require_allowlist_stays_required() -> None:
    cfg = load({"OSINT_PROXY_REQUIRE_ALLOWLIST": "nah"})
    assert cfg.require_allowlist is True and cfg.errors


def test_malformed_enabled_does_not_silently_return_a_direct_transport() -> None:
    cfg = load({**HOSTS, "OSINT_PROXY_ENABLED": "maybe"})
    assert cfg.enabled is True  # so the factory validates instead of opting out
    with pytest.raises(ProxyError):
        build_transport(cfg, _Inner(), inner_routes_through_proxy=True)


@pytest.mark.parametrize(
    ("key", "value"),
    [
        ("OSINT_PROXY_BIND_PORT", "abc"),
        ("OSINT_PROXY_BIND_PORT", "99999"),
        ("OSINT_PROXY_TIMEOUT", "0"),
        ("OSINT_PROXY_TIMEOUT", "ten"),
        ("OSINT_PROXY_TIMEOUT", "601"),
    ],
)
def test_malformed_numbers_are_reported(key: str, value: str) -> None:
    cfg = load({**HOSTS, key: value})
    assert any(key in p for p in cfg.validate())


def test_unexpected_extra_variables_are_ignored() -> None:
    cfg = load({**HOSTS, "OSINT_PROXY_SOMETHING_ELSE": "x", "UNRELATED": "y"})
    assert cfg.errors == () and cfg.validate() == []


def test_env_never_produces_an_empty_port_set() -> None:
    # An empty set means "any port" in EgressPolicy; only explicit code may ask for that.
    for value in ("abc", ",", "0", "65536", ""):
        assert load({**HOSTS, "OSINT_PROXY_ALLOWED_PORTS": value}).allowed_ports
    assert ProxyConfig().allowed_ports == frozenset({443})


def test_errors_never_echo_the_auth_token() -> None:
    token = "SYNTH-proxy-token-0000"
    cfg = load(
        {
            **HOSTS,
            "OSINT_PROXY_AUTH_TOKEN": token,
            "OSINT_PROXY_FAIL_CLOSED": "flase",
            "OSINT_PROXY_ALLOWED_PORTS": token,
        }
    )
    assert cfg.errors
    assert all(token not in p for p in cfg.validate())
