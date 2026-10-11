import asyncio
import json

import pytest

from ultimate_username.domain.models import TransportResponse
from ultimate_username.dorks import (
    CDX_URL,
    SOCIAL_DOMAINS,
    build_queries,
    cdx_query_url,
    check_wayback,
    parse_cdx,
)
from ultimate_username.transport import FakeTransport

HEADER = ["timestamp", "original", "statuscode"]


def cdx_body(*rows):
    return json.dumps([HEADER, *rows]).encode()


def reply(url, body=b"", status=200):
    return TransportResponse(url, status, body)


def test_build_queries_are_text_only_and_chunked():
    queries = build_queries(["alice"])
    assert queries[0] == '"alice"'
    site_queries = [q for q in queries if "site:" in q.replace("-site:", "")]
    assert len(site_queries) == -(-len(SOCIAL_DOMAINS) // 9)
    assert all(q.startswith('"alice" (site:') for q in site_queries)
    assert queries[-1].startswith("(inurl:alice)")
    assert not any("http" in q for q in queries)
    multi = build_queries(["alice", "alice_"])
    assert multi[0] == '("alice" OR "alice_")'
    assert build_queries([]) == []


def test_cdx_query_url_filters_200_and_collapses():
    url = cdx_query_url("https://github.com/alice?tab=x", limit=3)
    assert url.startswith(CDX_URL + "?")
    assert "url=github.com%2Falice%3Ftab%3Dx" in url
    assert "filter=statuscode%3A200" in url and "collapse=digest" in url and "limit=3" in url


def test_parse_cdx_rows_status_and_empty():
    text = cdx_body(["20200101000000", "https://github.com/alice", "200"]).decode()
    snaps = parse_cdx(text)
    assert snaps[0].timestamp == "20200101000000" and snaps[0].status == "200"
    assert snaps[0].date == "2020-01-01"
    assert snaps[0].archive_url.endswith("/20200101000000/https://github.com/alice")
    assert parse_cdx("") == [] and parse_cdx("[]") == []
    assert parse_cdx(json.dumps([HEADER])) == []


def test_parse_cdx_rejects_malformed():
    for bad in (
        "not json",
        '{"a": 1}',
        '[["timestamp"]]',
        "[[1, 2, 3]]",
        json.dumps([HEADER, ["2020", "https://x/", "200"]]),
        json.dumps([HEADER, ["20200101000000", "", "200"]]),
        json.dumps([HEADER, ["20200101000000"]]),
    ):
        with pytest.raises(ValueError):
            parse_cdx(bad)


def run(transport, urls, budget):
    return asyncio.run(check_wayback(transport, urls, budget))


def test_check_wayback_success_first_last_seen_and_empty():
    a, b = "https://github.com/alice", "https://gitlab.com/alice"
    rows = [
        ["20230505000000", a, "200"],
        ["20190101120000", a, "200"],
        ["20210303000000", a, "200"],
    ]
    transport = FakeTransport(
        {
            cdx_query_url(a): [reply(cdx_query_url(a), cdx_body(*rows))],
            cdx_query_url(b): [reply(cdx_query_url(b), b"")],
        }
    )
    out = run(transport, [a, b], 20)
    assert out["requests"] == 2 and out["budget"] == 20 and out["skipped_over_budget"] == 0
    first, second = out["profiles"]
    assert first["profile_url"] == a
    assert first["first_seen"] == "2019-01-01" and first["last_seen"] == "2023-05-05"
    assert [s["timestamp"] for s in first["snapshots"]] == [
        "20190101120000",
        "20210303000000",
        "20230505000000",
    ]
    assert set(first["snapshots"][0]) == {"timestamp", "original", "status"}
    assert second == {"profile_url": b, "snapshots": [], "first_seen": None, "last_seen": None}


def test_check_wayback_budget_is_a_hard_cap():
    urls = [f"https://github.com/u{i}" for i in range(5)]
    transport = FakeTransport(handler=lambda req, i: reply(req.url, b""))
    out = run(transport, urls, 2)
    assert transport.total == 2 and out["requests"] == 2 and out["skipped_over_budget"] == 3
    assert [p["profile_url"] for p in out["profiles"]] == urls[:2]
    zero = FakeTransport(handler=lambda req, i: reply(req.url, b""))
    assert run(zero, urls, 0)["requests"] == 0 and zero.total == 0


def test_check_wayback_errors_are_per_url_not_empty_results():
    urls = [f"https://github.com/e{i}" for i in range(4)]
    bodies = {
        cdx_query_url(urls[0]): reply("", b"<html>oops</html>"),
        cdx_query_url(urls[1]): reply("", b"", status=429),
        cdx_query_url(urls[2]): reply("", b"", status=503),
        cdx_query_url(urls[3]): TransportResponse("", None, b""),
    }
    transport = FakeTransport(handler=lambda req, i: bodies[req.url])
    out = run(transport, urls, 10)
    errors = [p["error"] for p in out["profiles"]]
    assert "invalid CDX response" in errors[0]
    assert errors[1] == "HTTP 429" and errors[2] == "HTTP 503"
    assert "no response" in errors[3]
    assert all(p["snapshots"] == [] and p["first_seen"] is None for p in out["profiles"])
    assert out["errors"] == 4


def test_check_wayback_survives_closed_transport():
    transport = FakeTransport(handler=lambda req, i: reply(req.url, b""))
    asyncio.run(transport.close())
    out = run(transport, ["https://github.com/alice"], 5)
    assert out["profiles"][0]["error"].startswith("transport error")


def _result(url, verdict, tested=True):
    from ultimate_username.domain.models import (
        AttemptRecord,
        DetectionResult,
        ExecutionState,
        SearchResult,
        Timing,
        Username,
    )

    attempts = (AttemptRecord(1, url, 200, ExecutionState.OK, Timing()),) if tested else ()
    return SearchResult(
        "job",
        "task",
        "site",
        Username("a", "a", "a"),
        DetectionResult(verdict=verdict),
        profile_url=url,
        attempts=attempts,
    )


def test_wayback_targets_hits_and_optional_unknown():
    from ultimate_username.domain.models import Verdict
    from ultimate_username.dorks import wayback_targets

    results = [
        _result("https://a.example/x", Verdict.FOUND),
        _result("https://a.example/x", Verdict.FOUND),
        _result("https://b.example/x", Verdict.PROBABLE),
        _result("https://c.example/x", Verdict.UNKNOWN),
        _result("https://d.example/x", Verdict.NOT_FOUND),
        _result("https://e.example/x", Verdict.FOUND, tested=False),
        _result("ftp://f.example/x", Verdict.FOUND),
    ]
    assert wayback_targets(results) == ["https://a.example/x", "https://b.example/x"]
    assert wayback_targets(results, include_unknown=True)[-1] == "https://c.example/x"
