"""Red-team: configuration must fail closed and refuse open-proxy setups."""

from __future__ import annotations

from ultimate_username.opsec.config import ProxyConfig, load


def test_defaults_are_safe() -> None:
    cfg = load({})
    assert cfg.enabled is False
    assert cfg.bind_host == "127.0.0.1"
    assert cfg.fail_closed is True
    assert cfg.require_allowlist is True


def test_env_parsing() -> None:
    cfg = load(
        {
            "OSINT_PROXY_ENABLED": "true",
            "OSINT_PROXY_BIND_PORT": "9090",
            "OSINT_PROXY_ALLOWED_HOSTS": "github.com, api.github.com;google.com",
            "OSINT_PROXY_ALLOWED_PORTS": "443,8443",
            "OSINT_PROXY_UPSTREAM_URL": "http://127.0.0.1:1080",
        }
    )
    assert cfg.enabled is True
    assert cfg.bind_port == 9090
    assert cfg.allowed_hosts == frozenset({"github.com", "api.github.com", "google.com"})
    assert cfg.allowed_ports == frozenset({443, 8443})
    assert cfg.upstream_url == "http://127.0.0.1:1080"


def test_non_loopback_without_token_is_rejected() -> None:
    cfg = ProxyConfig(bind_host="0.0.0.0", allowed_hosts=frozenset({"x.com"}))
    problems = cfg.validate()
    assert any("open proxy" in p for p in problems)


def test_non_loopback_with_token_ok() -> None:
    cfg = ProxyConfig(
        bind_host="0.0.0.0", auth_token="t", allowed_hosts=frozenset({"x.com"})
    )
    assert cfg.validate() == []


def test_fail_closed_empty_allowlist_rejected() -> None:
    cfg = ProxyConfig(fail_closed=True, require_allowlist=True, allowed_hosts=frozenset())
    problems = cfg.validate()
    assert any("denies all traffic" in p for p in problems)
