"""Testy runnera: limit równoległości, mapowanie wyjątków, brak wycieku celu."""
import asyncio

from osint_connectors import (
    Context,
    Finding,
    InputKind,
    RateLimited,
    SourceKind,
    Status,
    Subject,
    run,
    subject_ref,
    summarize,
)
from osint_connectors.errors import TransportError


def _subject():
    return Subject(InputKind.EMAIL, "target@example.com")


class _Found:
    name = "found"
    source_kind = SourceKind.PASSIVE
    supported_inputs = frozenset({InputKind.EMAIL})

    async def check(self, subject, ctx):
        # Celowo zwraca pusty ref — runner musi go uzupełnić.
        return Finding(self.name, self.source_kind, Status.FOUND, 1.0, "")


class _RaisesRateLimit:
    name = "limited"
    source_kind = SourceKind.OFFICIAL_API
    supported_inputs = frozenset({InputKind.EMAIL})

    async def check(self, subject, ctx):
        raise RateLimited("limit")


class _RaisesTransport:
    name = "transport"
    source_kind = SourceKind.OFFICIAL_API
    supported_inputs = frozenset({InputKind.EMAIL})

    async def check(self, subject, ctx):
        raise TransportError("sieć")


class _RaisesUnexpected:
    name = "boom"
    source_kind = SourceKind.OFFICIAL_API
    supported_inputs = frozenset({InputKind.EMAIL})

    async def check(self, subject, ctx):
        raise KeyError("nieoczekiwane")


class _WrongReturn:
    name = "wrong"
    source_kind = SourceKind.PASSIVE
    supported_inputs = frozenset({InputKind.EMAIL})

    async def check(self, subject, ctx):
        return {"exists": True}  # nie Finding


class _Slow:
    name = "slow"
    source_kind = SourceKind.OFFICIAL_API
    supported_inputs = frozenset({InputKind.EMAIL})

    async def check(self, subject, ctx):
        await asyncio.sleep(10)
        return Finding(self.name, self.source_kind, Status.FOUND, 1.0, "")


def test_exception_mapping_and_ref_injection():
    ctx = Context(salt="sol")
    subj = _subject()
    conns = [_Found(), _RaisesRateLimit(), _RaisesTransport(), _RaisesUnexpected(), _WrongReturn()]
    findings = asyncio.run(run(conns, subj, ctx))
    by = {f.connector: f for f in findings}
    assert by["found"].status == Status.FOUND
    assert by["limited"].status == Status.UNKNOWN and by["limited"].error_kind == "rate_limited"
    assert by["transport"].status == Status.ERROR and by["transport"].error_kind == "transport"
    assert by["boom"].status == Status.ERROR and by["boom"].error_kind == "unexpected"
    assert by["wrong"].status == Status.ERROR
    expected_ref = subject_ref(subj, "sol")
    assert all(f.subject_ref == expected_ref for f in findings)  # ref wstrzyknięty wszędzie


def test_timeout_maps_to_error():
    ctx = Context(salt="sol", timeout=0.05)
    findings = asyncio.run(run([_Slow()], _subject(), ctx))
    assert findings[0].status == Status.ERROR
    assert findings[0].error_kind == "timeout"


def test_no_raw_subject_in_findings():
    ctx = Context(salt="sol")
    findings = asyncio.run(run([_Found(), _RaisesRateLimit()], _subject(), ctx))
    blob = str([f.to_dict() for f in findings])
    assert "target@example.com" not in blob


def test_concurrency_limit_respected():
    state = {"cur": 0, "max": 0}

    class _Counting:
        source_kind = SourceKind.OFFICIAL_API
        supported_inputs = frozenset({InputKind.EMAIL})

        def __init__(self, i):
            self.name = f"c{i}"

        async def check(self, subject, ctx):
            state["cur"] += 1
            state["max"] = max(state["max"], state["cur"])
            await asyncio.sleep(0.02)
            state["cur"] -= 1
            return Finding(self.name, self.source_kind, Status.NOT_FOUND, 0.9, "")

    conns = [_Counting(i) for i in range(10)]
    asyncio.run(run(conns, _subject(), Context(salt="sol"), concurrency=3))
    assert state["max"] <= 3


def test_summarize_and_sorted():
    ctx = Context(salt="sol")
    findings = asyncio.run(run([_RaisesRateLimit(), _Found(), _RaisesTransport()], _subject(), ctx))
    assert [f.connector for f in findings] == sorted(f.connector for f in findings)
    counts = summarize(findings)
    assert counts["found"] == 1 and counts["unknown"] == 1 and counts["error"] == 1
