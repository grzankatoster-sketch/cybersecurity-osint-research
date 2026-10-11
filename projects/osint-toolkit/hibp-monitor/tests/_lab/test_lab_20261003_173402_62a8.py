"""Specyfikacja: klucz API wysylany wylacznie do https://haveibeenpwned.com (walidacja hosta przed wyslaniem)."""
from __future__ import annotations

import json

import pytest

from hibp_monitor.cli import main
from hibp_monitor.domain_search import ENV_KEY
from hibp_monitor.http import HibpError, HttpClient, Response

SECRET = "fake-klucz-testowy-456"  # atrapa


def make(responses=None):
    calls, sleeps = [], []
    queue = list(responses or [])

    def transport(url, headers, timeout):
        calls.append((url, dict(headers)))
        if not queue:
            raise AssertionError(f"transport nie powinien byc wolany: {url}")
        return queue.pop(0)

    return HttpClient("test-agent/1", transport=transport, sleep=sleeps.append, max_retries=2), calls, sleeps


@pytest.mark.parametrize("url, host", [
    ("https://evil.test/api/v3/breacheddomain/example.com", "evil.test"),
    ("https://haveibeenpwned.com.evil.test/api/v3/x", "haveibeenpwned.com.evil.test"),
    ("https://evilhaveibeenpwned.com/api/v3/x", "evilhaveibeenpwned.com"),
    ("https://haveibeenpwned.com@evil.test/api/v3/x", "evil.test"),
    ("https://api.pwnedpasswords.com/range/ABCDE", "api.pwnedpasswords.com"),
])
def test_key_is_never_sent_to_foreign_host(url, host):
    c, calls, sleeps = make()
    with pytest.raises(HibpError) as ei:
        c.get(url, {"hibp-api-key": SECRET})
    msg = str(ei.value)
    assert calls == [] and sleeps == []
    assert host in msg and "klucz" in msg.lower() and SECRET not in msg


def test_key_is_not_sent_over_plain_http_even_to_official_host():
    c, calls, _ = make()
    with pytest.raises(HibpError) as ei:
        c.get("http://haveibeenpwned.com/api/v3/breacheddomain/example.com", {"hibp-api-key": SECRET})
    assert calls == [] and SECRET not in str(ei.value) and "klucz" in str(ei.value).lower()


@pytest.mark.parametrize("url", [
    "https://user:pass@haveibeenpwned.com/api/v3/x",
    "https://haveibeenpwned.com:8443/api/v3/x",
    "https://haveibeenpwned.com:abc/api/v3/x",
])
def test_key_rejected_for_userinfo_or_nonstandard_port(url):
    c, calls, _ = make()
    with pytest.raises(HibpError) as ei:
        c.get(url, {"hibp-api-key": SECRET})
    assert calls == [] and SECRET not in str(ei.value)


def test_header_name_is_matched_case_insensitively():
    c, calls, _ = make()
    with pytest.raises(HibpError):
        c.get("https://evil.test/x", {"HIBP-API-KEY": SECRET})
    assert calls == []


@pytest.mark.parametrize("url", [
    "https://haveibeenpwned.com/api/v3/breacheddomain/example.com",
    "https://haveibeenpwned.com:443/api/v3/breacheddomain/example.com",
])
def test_official_https_host_is_allowed(url):
    c, calls, _ = make([Response(200, "{}")])
    assert c.get(url, {"hibp-api-key": SECRET}).status == 200
    assert len(calls) == 1 and calls[0][1]["hibp-api-key"] == SECRET


def test_requests_without_key_are_unchanged():
    c, calls, _ = make([Response(200, "ok"), Response(200, "ok")])
    assert c.get("https://x.test/a").text == "ok"
    assert c.get("http://api.pwnedpasswords.com/range/ABCDE", {"Add-Padding": "true"}).text == "ok"
    assert len(calls) == 2


def test_cli_domain_search_through_real_client_still_works(capsys):
    c, calls, _ = make([Response(200, json.dumps({"alice": ["Adobe"]}))])
    assert main(["domain-search", "example.com"], client=c, environ={ENV_KEY: SECRET}) == 0
    assert calls[0][0] == "https://haveibeenpwned.com/api/v3/breacheddomain/example.com"
    assert "kont z wyciekow: 1" in capsys.readouterr().out


def test_cli_reports_refusal_as_usage_error_without_leaking_key(monkeypatch, capsys):
    import hibp_monitor.domain_search as ds
    monkeypatch.setattr(ds, "BASE", "https://evil.test/api/v3")
    c, calls, _ = make()
    code = main(["domain-search", "example.com"], client=c, environ={ENV_KEY: SECRET})
    cap = capsys.readouterr()
    assert code == 2 and calls == []
    assert "evil.test" in cap.err and SECRET not in cap.out + cap.err
