from __future__ import annotations

import json

import pytest
from conftest import FakeClient, fixture_text

from hibp_monitor.cli import main
from hibp_monitor.domain_search import ENV_KEY, MissingApiKey, aggregate, domain_search, get_api_key
from hibp_monitor.http import HibpError, Response

URL = "https://haveibeenpwned.com/api/v3/breacheddomain/"


def test_no_key_raises_readable_error():
    with pytest.raises(MissingApiKey) as ei:
        get_api_key({})
    assert ENV_KEY in str(ei.value)
    with pytest.raises(MissingApiKey):
        get_api_key({ENV_KEY: "   "})
    assert get_api_key({ENV_KEY: " abc "}) == "abc"


def test_cli_without_key_makes_no_network_call(capsys):
    c = FakeClient()  # kazde zapytanie rzuci AssertionError
    code = main(["domain-search", "example.com"], client=c, environ={})
    err = capsys.readouterr().err
    assert code == 2 and ENV_KEY in err and "ZWERYFIKOWANEJ" in err
    assert c.calls == []


def test_aggregate_counts_unique_accounts_per_breach():
    import json as j
    data = j.loads(fixture_text("domain_search.json"))
    res = aggregate("example.com", data)
    assert res.total_accounts == 3
    assert res.per_breach == {"FikcyjnyNowy": 2, "Adobe": 2} or res.per_breach == {"Adobe": 2, "FikcyjnyNowy": 2}
    assert res.addresses is None and "addresses" not in res.to_dict()


def test_domain_search_sends_key_header_only():
    c = FakeClient({URL: Response(200, fixture_text("domain_search.json"))})
    res = domain_search(c, "Example.com", "sekret-klucz")
    url, headers = c.calls[0]
    assert url == URL + "example.com" and headers["hibp-api-key"] == "sekret-klucz"
    assert "sekret-klucz" not in url
    assert res.total_accounts == 3


@pytest.mark.parametrize("status", [401, 403, 404, 500])
def test_domain_search_errors_do_not_leak_key(status):
    with pytest.raises(HibpError) as ei:
        domain_search(FakeClient(default=Response(status)), "example.com", "sekret-klucz")
    assert "sekret-klucz" not in str(ei.value)


def test_cli_default_hides_addresses_and_flag_shows_them(capsys):
    c = FakeClient({URL: Response(200, fixture_text("domain_search.json"))})
    env = {ENV_KEY: "k"}
    assert main(["domain-search", "example.com", "--json"], client=c, environ=env) == 0
    data = json.loads(capsys.readouterr().out)
    assert data["total_accounts"] == 3 and "addresses" not in data

    assert main(["domain-search", "example.com"], client=c, environ=env) == 0
    out = capsys.readouterr().out
    assert "alice" not in out and "--show-addresses" in out

    assert main(["domain-search", "example.com", "--json", "--show-addresses"], client=c, environ=env) == 0
    data = json.loads(capsys.readouterr().out)
    assert "alice@example.com" in data["addresses"]
