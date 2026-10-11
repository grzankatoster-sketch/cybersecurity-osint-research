from __future__ import annotations

import pytest

from hibp_monitor.http import HibpError, HttpClient, Response, parse_retry_after


def make(responses):
    calls, sleeps = [], []
    queue = list(responses)

    def transport(url, headers, timeout):
        calls.append((url, headers))
        return queue.pop(0)

    return HttpClient("test-agent/1", transport=transport, sleep=sleeps.append, max_retries=2), calls, sleeps


def test_user_agent_is_always_sent():
    c, calls, _ = make([Response(200, "ok")])
    c.get("https://x.test/a", {"Add-Padding": "true"})
    assert calls[0][1]["User-Agent"] == "test-agent/1" and calls[0][1]["Add-Padding"] == "true"


def test_429_respects_retry_after_then_succeeds():
    c, calls, sleeps = make([Response(429, "", {"retry-after": "7"}), Response(200, "ok")])
    assert c.get("https://x.test/a").text == "ok"
    assert sleeps == [7.0] and len(calls) == 2


def test_429_gives_up_after_max_retries():
    c, calls, sleeps = make([Response(429, "", {"retry-after": "1"})] * 3)
    with pytest.raises(HibpError) as ei:
        c.get("https://x.test/a")
    assert ei.value.status == 429 and len(calls) == 3 and sleeps == [1.0, 1.0]


def test_retry_after_parsing_is_capped_and_defaults():
    assert parse_retry_after("5") == 5.0
    assert parse_retry_after("99999") == 120.0
    assert parse_retry_after("jutro", default=3.0) == 3.0
    assert parse_retry_after(None, default=4.0) == 4.0
