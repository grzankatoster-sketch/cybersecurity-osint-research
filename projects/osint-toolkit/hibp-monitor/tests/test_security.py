"""Testy poprawek z przegladu bezpieczenstwa (przekierowania, puste odpowiedzi, limit, getpass, znaki sterujace)."""
from __future__ import annotations

import getpass
import io
import json
import urllib.request
import warnings

import pytest
from conftest import FakeClient

from hibp_monitor import http as http_mod
from hibp_monitor.cli import main
from hibp_monitor.domain_search import ENV_KEY
from hibp_monitor.http import HibpError, Response
from hibp_monitor.passwords import RANGE_URL, check_password, parse_range

SECRET = "fake-klucz-testowy-123"  # atrapa; slowo "fake" oznacza ja dla bramki sekretow  gitleaks:allow


# --- 1. przekierowania ---------------------------------------------------

@pytest.mark.parametrize("code", [301, 302, 303, 307, 308])
@pytest.mark.parametrize("target", ["https://evil.test/x", "http://haveibeenpwned.com/api/v3/x"])
def test_redirect_handler_rejects_every_redirect(code, target):
    handler = http_mod.NoRedirectHandler()
    req = urllib.request.Request(
        "https://haveibeenpwned.com/api/v3/breacheddomain/example.com", headers={"hibp-api-key": SECRET}
    )
    with pytest.raises(HibpError) as ei:
        handler.redirect_request(req, io.BytesIO(b""), code, "Moved", {}, target)
    msg = str(ei.value)
    assert SECRET not in msg and "przekierowan" in msg.lower() and str(code) in msg


def test_transport_uses_opener_that_blocks_redirects():
    opener = http_mod._OPENER
    assert any(isinstance(h, http_mod.NoRedirectHandler) for h in opener.handlers)
    assert not any(type(h) is urllib.request.HTTPRedirectHandler for h in opener.handlers)


# --- 2. pusta odpowiedz range -------------------------------------------

@pytest.mark.parametrize("body", ["", "   \n\r\n  \n"])
def test_empty_range_response_is_an_error_not_clean_result(body):
    with pytest.raises(HibpError) as ei:
        parse_range(body)
    assert "pusta" in str(ei.value).lower()
    with pytest.raises(HibpError):
        check_password(FakeClient({RANGE_URL: Response(200, body)}), "password")


# --- 3. limit rozmiaru odpowiedzi ---------------------------------------

def test_read_limited_accepts_up_to_limit_and_rejects_more():
    assert http_mod.read_limited(io.BytesIO(b"a" * 10), 10) == b"a" * 10
    with pytest.raises(HibpError) as ei:
        http_mod.read_limited(io.BytesIO(b"a" * 11), 10)
    assert "limit" in str(ei.value).lower()


def test_max_body_has_headroom_over_real_catalog():
    assert http_mod.MAX_BODY_BYTES >= 10 * 1_117_577  # katalog /breaches ma ok. 1,1 MB


def test_transport_rejects_oversized_body(monkeypatch):
    class FakeResp:
        status = 200
        headers = {}

        def __init__(self, n):
            self._fp = io.BytesIO(b"x" * n)

        def read(self, n=-1):
            return self._fp.read(n)

        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

    class FakeOpener:
        def open(self, req, timeout=None):
            return FakeResp(50)

    monkeypatch.setattr(http_mod, "_OPENER", FakeOpener())
    monkeypatch.setattr(http_mod, "MAX_BODY_BYTES", 40)
    with pytest.raises(HibpError):
        http_mod.urllib_transport("https://x.test/", {}, 1.0)
    monkeypatch.setattr(http_mod, "MAX_BODY_BYTES", 50)
    assert http_mod.urllib_transport("https://x.test/", {}, 1.0).text == "x" * 50


# --- 4. getpass bez ukrytego echa ---------------------------------------

def test_getpass_warning_aborts_without_network(monkeypatch, capsys):
    def noecho_getpass(prompt="Password: ", stream=None):
        warnings.warn("Can not control echo on the terminal.", getpass.GetPassWarning)
        return "haslo-ktore-nie-powinno-byc-uzyte"

    monkeypatch.setattr(getpass, "getpass", noecho_getpass)
    c = FakeClient()  # kazde zapytanie rzuci AssertionError
    code = main(["password"], client=c)
    cap = capsys.readouterr()
    assert code == 2 and c.calls == []
    assert "echa" in cap.err.lower() and "haslo-ktore" not in cap.out + cap.err


# --- 5. znaki sterujace w wyjsciu tekstowym -----------------------------

def test_safe_text_escapes_controls_but_keeps_newline_tab_and_unicode():
    from hibp_monitor.breaches import safe_text
    assert safe_text("a\x1b[31mb\x07c\x00d\x7fe\x9bf") == "a\\x1b[31mb\\x07c\\x00d\\x7fe\\x9bf"
    assert safe_text("zażółć\n\tok\r") == "zażółć\n\tok\\x0d"


def test_catalog_text_output_escapes_api_controls_json_untouched(capsys):
    payload = [{
        "Name": "Evil\x1b]0;pwn\x07", "Title": "Ti\x1b[2Jtle", "BreachDate": "2020-01-01",
        "AddedDate": "2024-01-01T00:00:00Z", "PwnCount": 5, "DataClasses": ["Em\x1bails"],
        "Description": "<b>opis</b>\x1b[31mczerwony\x08",
    }]
    c = FakeClient({"https://haveibeenpwned.com/api/v3/breaches": Response(200, json.dumps(payload))})
    assert main(["breaches", "--catalog"], client=c) == 0
    out = capsys.readouterr().out
    assert "\x1b" not in out and "\x07" not in out and "\x08" not in out
    assert "\\x1b" in out and "Ti\\x1b[2Jtle" in out and "Em\\x1bails" in out

    assert main(["breaches", "--catalog", "--json"], client=c) == 0
    data = json.loads(capsys.readouterr().out)
    assert data["breaches"][0]["title"] == "Ti\x1b[2Jtle"  # JSON bez zmian


def test_domain_search_text_output_escapes_alias_and_breach_names(capsys):
    body = json.dumps({"al\x1b[2Jice": ["Ad\x07obe"]})
    c = FakeClient({"https://haveibeenpwned.com/api/v3/breacheddomain/": Response(200, body)})
    assert main(["domain-search", "example.com", "--show-addresses"], client=c, environ={ENV_KEY: "k"}) == 0
    out = capsys.readouterr().out
    assert "\x1b" not in out and "\x07" not in out
    assert "al\\x1b[2Jice@example.com" in out and "Ad\\x07obe" in out
