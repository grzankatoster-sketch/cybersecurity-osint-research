from __future__ import annotations

import json

import pytest
from conftest import FakeClient, fixture_text

from hibp_monitor.cli import main
from hibp_monitor.http import HibpError, Response
from hibp_monitor.passwords import RANGE_URL, check_password, parse_range, sha1_split

PREFIX = "5BAA6"
SUFFIX = "1E4C9B93F3F0682250B6CF8331B7EE68FD8"


def test_sha1_split_known_vector():
    assert sha1_split("password") == (PREFIX, SUFFIX)


def test_parse_range_skips_padding_rows():
    parsed = parse_range(fixture_text("range_5BAA6.txt"))
    assert parsed[SUFFIX] == 10434004
    assert "00A5F3C1D9B2E4A7C6B8D0F1E2A3B4C5D6E" not in parsed  # count 0 = padding
    assert "D2A7E1B4C3F5A6978E0D1C2B3A495867F10" not in parsed
    assert len(parsed) == 3


def test_parse_range_handles_crlf_and_lowercase_and_rejects_garbage():
    assert parse_range(f"{SUFFIX.lower()}:7\r\n\r\n") == {SUFFIX: 7}
    with pytest.raises(HibpError):
        parse_range("to nie jest wiersz")
    with pytest.raises(HibpError):
        parse_range("ABC:5")


def test_check_password_only_prefix_goes_to_network():
    c = FakeClient({RANGE_URL: Response(200, fixture_text("range_5BAA6.txt"))})
    assert check_password(c, "password") == 10434004
    (url, headers), = c.calls
    assert url == RANGE_URL + PREFIX
    path = url.rsplit("/", 1)[1]
    assert path == PREFIX and SUFFIX not in url and "password" not in path
    assert headers.get("Add-Padding") == "true"


def test_check_password_not_found_when_only_padding_matches():
    padding_only = "1E4C9B93F3F0682250B6CF8331B7EE68FD8:0\n003D68EB55068C33ACE09247EE4C639306B:3\n"
    c = FakeClient({RANGE_URL: Response(200, padding_only)})
    assert check_password(c, "password") == 0  # wiersz z licznikiem 0 to padding, nie trafienie


def test_check_password_http_error_and_empty():
    with pytest.raises(HibpError):
        check_password(FakeClient(default=Response(503)), "x")
    with pytest.raises(ValueError):
        check_password(FakeClient(), "")


def test_cli_password_noninteractive_via_fake_getpass(capsys):
    c = FakeClient({RANGE_URL: Response(200, fixture_text("range_5BAA6.txt"))})
    code = main(["password", "--json"], client=c, getpass_fn=lambda prompt: "password")
    cap = capsys.readouterr()
    assert code == 0
    assert json.loads(cap.out) == {"pwned": True, "count": 10434004}
    # haslo ani jego pelny hash nie pojawia sie ani w wyjsciu, ani w zapytaniu
    assert "password" not in cap.out + cap.err
    assert SUFFIX not in cap.out + cap.err and SUFFIX not in c.calls[0][0]
    assert c.calls[0][0].endswith(PREFIX)


def test_cli_password_text_output_and_empty(capsys):
    c = FakeClient({RANGE_URL: Response(200, fixture_text("range_5BAA6.txt"))})
    assert main(["password"], client=c, getpass_fn=lambda p: "password") == 0
    assert "10 434 004" in capsys.readouterr().out
    assert main(["password"], client=FakeClient(), getpass_fn=lambda p: "") == 2
