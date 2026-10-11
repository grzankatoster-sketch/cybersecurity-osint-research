"""Red-team: diagnostics must not leak secrets or full identifiers (phase 5.D)."""

from __future__ import annotations

from ultimate_username.opsec.redaction import (
    mask_email,
    redact_headers,
    redact_text,
    redact_url,
)


def test_email_is_masked() -> None:
    out = mask_email("contact john.doe@example.com now")
    assert "john.doe@example.com" not in out
    assert out.startswith("contact j***@")


def test_jwt_and_bearer_tokens_removed() -> None:
    jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dBjftJeZ4CVPmB92K27uhbUJU1p1r_wW1g"
    out = redact_text(f"auth {jwt} bearer: sk-S0meSuperSecretValue123456")
    assert "eyJ" not in out
    assert "sk-S0meSuperSecretValue123456" not in out
    assert "<REDACTED>" in out


def test_long_opaque_token_removed() -> None:
    out = redact_text("session=abcdefghijklmnopqrstuvwxyz0123456789ABCD")
    assert "abcdefghijklmnopqrstuvwxyz0123456789ABCD" not in out


def test_sensitive_headers_fully_redacted() -> None:
    redacted = redact_headers(
        {
            "Authorization": "Bearer secret-token-value",
            "Cookie": "session=deadbeef",
            "Set-Cookie": "id=1; HttpOnly",
            "Proxy-Authorization": "Bearer p",
            "User-Agent": "UltimateUsernameEngine/0.1",
        }
    )
    assert redacted["Authorization"] == "<REDACTED>"
    assert redacted["Cookie"] == "<REDACTED>"
    assert redacted["Set-Cookie"] == "<REDACTED>"
    assert redacted["Proxy-Authorization"] == "<REDACTED>"
    assert redacted["User-Agent"] == "UltimateUsernameEngine/0.1"


def test_url_reduced_to_origin() -> None:
    assert (
        redact_url("https://user:pass@api.example.com:8443/path?token=abc#frag")
        == "https://api.example.com:8443"
    )
