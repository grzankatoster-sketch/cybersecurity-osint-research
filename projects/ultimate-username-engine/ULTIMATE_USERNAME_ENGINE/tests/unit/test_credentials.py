"""OPEN-02 regression: catalogue definitions must not read or leak arbitrary environment variables."""

from __future__ import annotations

import pytest

from ultimate_username.credentials import parse_scopes, resolve_credential
from ultimate_username.domain.models import DetectionSpec, Rule, SiteDefinition
from ultimate_username.domain.validation import SiteDefinitionValidator

SECRET = "SYNTH-credential-value-0000"
URL = "https://api.example.test/v1/users/alice"


def env(**extra: str) -> dict[str, str]:
    return {
        "UEE_CRED_EXAMPLE": SECRET,
        "UEE_CREDENTIAL_SCOPES": "UEE_CRED_EXAMPLE=api.example.test",
        **extra,
    }


def test_authorised_credential_for_exact_host_over_https() -> None:
    decision = resolve_credential("UEE_CRED_EXAMPLE", URL, env())
    assert decision.value == SECRET


@pytest.mark.parametrize(
    "name", ["AWS_SECRET_ACCESS_KEY", "GITHUB_TOKEN", "PATH", "uee_cred_example", "UEE_CRED_", "X"]
)
def test_names_outside_the_dedicated_prefix_are_never_read(name: str) -> None:
    decision = resolve_credential(name, URL, {**env(), name: SECRET})
    assert decision.value is None


def test_unauthorised_prefixed_variable_is_not_read() -> None:
    decision = resolve_credential("UEE_CRED_OTHER", URL, {**env(), "UEE_CRED_OTHER": SECRET})
    assert decision.value is None and "not authorised" in decision.reason


def test_no_scopes_means_no_credentials() -> None:
    decision = resolve_credential("UEE_CRED_EXAMPLE", URL, {"UEE_CRED_EXAMPLE": SECRET})
    assert decision.value is None


@pytest.mark.parametrize(
    "url",
    [
        "https://evil.example/collect",
        "https://api.example.test.evil.example/",
        "https://sub.api.example.test/",  # no parent-domain matching
        "https://example.test/",
        "http://api.example.test/",  # plaintext
        "https://api.example.test:8443/",  # non-default port
        "https://user@api.example.test/",  # userinfo
        "https://api.example.test:99999/",  # invalid port
        "ftp://api.example.test/",
    ],
)
def test_credential_is_bound_to_the_authorised_destination(url: str) -> None:
    assert resolve_credential("UEE_CRED_EXAMPLE", url, env()).value is None


@pytest.mark.parametrize("value", ["", "line1\r\nX-Injected: 1", "a\nb"])
def test_empty_or_header_injecting_values_are_refused(value: str) -> None:
    assert resolve_credential("UEE_CRED_EXAMPLE", URL, env(UEE_CRED_EXAMPLE=value)).value is None


def test_reasons_never_contain_the_secret() -> None:
    for url in (URL, "https://evil.example/", "http://api.example.test/"):
        assert SECRET not in resolve_credential("UEE_CRED_EXAMPLE", url, env()).reason


def test_scope_parser_reports_malformed_entries() -> None:
    scopes, errors = parse_scopes(
        "UEE_CRED_A=a.example.test|b.example.test, GITHUB_TOKEN=api.github.com,"
        "UEE_CRED_B=, UEE_CRED_C=https://c.example.test, UEE_CRED_D"
    )
    assert scopes == {"UEE_CRED_A": frozenset({"a.example.test", "b.example.test"})}
    assert len(errors) == 4


def _site(credential_env: str) -> SiteDefinition:
    return SiteDefinition(
        "s",
        "s",
        "https://api.example.test/u/{username}",
        DetectionSpec(Rule("status", "", statuses=(200,)), Rule("status", "", statuses=(404,))),
        credential_env=credential_env,
    )


@pytest.mark.parametrize("name", ["AWS_SECRET_ACCESS_KEY", "HOME", "uee_cred_x", "UEE_CRED_"])
def test_catalogue_validation_rejects_generic_variable_names(name: str) -> None:
    issues = SiteDefinitionValidator().validate(_site(name))
    assert any(i.path == "credential_env" for i in issues)


def test_catalogue_validation_accepts_dedicated_prefix() -> None:
    issues = SiteDefinitionValidator().validate(_site("UEE_CRED_EXAMPLE"))
    assert not any(i.path == "credential_env" for i in issues)
