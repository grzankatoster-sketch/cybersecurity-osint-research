import asyncio
import json
from dataclasses import replace

import pytest

from ultimate_username.domain.codec import to_json
from ultimate_username.domain.models import (
    Control,
    DetectionResult,
    DetectionSpec,
    ErrorCode,
    ExecutionState,
    ExtractionResult,
    ExtractionState,
    Rule,
    SearchError,
    SearchResult,
    SiteDefinition,
    TransportResponse,
    Username,
    Verdict,
)
from ultimate_username.engine import UsernameEngine
from ultimate_username.health import check_health
from ultimate_username.registry import SiteRegistry
from ultimate_username.storage import ResultJournal, SnapshotStore, atomic_write, export_results
from ultimate_username.transport import FakeTransport


def result():
    return SearchResult(
        "job",
        "task",
        "site",
        Username("../Żółć", "../Żółć", "../Żółć"),
        DetectionResult(
            state=ExecutionState.NETWORK_ERROR,
            errors=(SearchError(ErrorCode.DNS_NOT_FOUND, "dns", "no host"),),
        ),
    )


def test_atomic_export_failure_preserves_previous_and_cleans_temp(tmp_path):
    target = tmp_path / "results.json"
    target.write_text("old", encoding="utf-8")

    def failing():
        yield "new"
        raise ValueError("renderer failed")

    with pytest.raises(ValueError):
        atomic_write(target, failing())
    assert target.read_text("utf-8") == "old"
    assert list(tmp_path.iterdir()) == [target]


def test_json_export_all_errors_unicode_and_no_detection_recomputation(tmp_path):
    export_results(tmp_path / "out.json", [result()] * 100)
    data = json.loads((tmp_path / "out.json").read_text("utf-8"))
    assert len(data) == 100
    assert data[0]["detection"]["errors"][0]["code"] == "DNS_NOT_FOUND"
    assert data[0]["username"]["raw"] == "../Żółć"
    export_results(tmp_path / "out.csv", [result()], "csv")
    assert "../Żółć" in (tmp_path / "out.csv").read_text("utf-8")


def test_journal_base_survives_enrichment_and_reopen(tmp_path):
    path = tmp_path / "journal.sqlite"
    base = result()
    enriched = replace(base, enrichment=ExtractionResult(ExtractionState.TIMEOUT))
    with ResultJournal(path) as journal:
        journal.append(base)
        journal.append(enriched)
    with ResultJournal(path) as journal:
        assert list(journal.read(base=True)) == [base]
        assert list(journal.read()) == [enriched]
        assert list(journal.read(job_id="other")) == []


def test_snapshot_hash_schema_cas_and_concurrent_writer_failure(tmp_path):
    site = SiteDefinition(
        "x",
        "Example",
        "https://example.test/{username}",
        DetectionSpec(present=Rule("status", statuses=(200,))),
    )
    store = SnapshotStore(tmp_path / "catalog.json")
    digest = store.promote(to_json([site]))
    previous = store.path.read_bytes()
    assert store.load()[0] == digest
    for bad in ["{broken", '[{"unknown":true}]']:
        with pytest.raises(ValueError):
            store.promote(bad)
        assert store.path.read_bytes() == previous
    with pytest.raises(ValueError, match="compare-and-swap"):
        store.promote(to_json([site]), expected_digest="bad")
    lock = store.path.with_suffix(".json.lock")
    lock.touch()
    with pytest.raises(FileExistsError):
        store.promote(to_json([site]))
    assert lock.exists() and store.path.read_bytes() == previous
    envelope = json.loads(previous)
    envelope["registry_json"] = "[]"
    store.path.write_text(json.dumps(envelope), encoding="utf-8")
    with pytest.raises(ValueError, match="checksum"):
        store.load()


def test_health_shared_detector_empty_partial_and_random_collision():
    async def run():
        site = SiteDefinition(
            "x",
            "Example",
            "https://example.test/{username}",
            DetectionSpec(
                Rule("message", "profile"),
                Rule("message", "missing"),
                Rule("redirect", "{profile_url}"),
            ),
        )
        transport = FakeTransport(
            handler=lambda r, i: TransportResponse(
                r.url, 200, b"missing" if r.url.endswith("/absent") else b"profile"
            )
        )
        async with UsernameEngine(SiteRegistry([site]), transport) as engine:
            assert (await check_health(engine, "x")).status == "UNTESTED"
            controls = [Control("alice", Verdict.FOUND), Control("absent", Verdict.NOT_FOUND)]
            healthy = await check_health(engine, "x", controls)
            assert healthy.status == "HEALTHY" and healthy.promotion_allowed
            search = (await engine.search("alice"))[0]
            assert healthy.observations[0].result.detection == search.detection
            partial = await check_health(
                engine, "x", [*controls, Control("bob", Verdict.NOT_FOUND)]
            )
            assert partial.status == "DEGRADED" and not partial.promotion_allowed
            random = await check_health(engine, "x", [Control("random", Verdict.NOT_FOUND, False)])
            assert random.status == "SUSPECT" and not random.promotion_allowed

    asyncio.run(run())


def test_sink_failure_has_terminal_error_instead_of_hanging():
    async def run():
        def failing_sink(result):
            raise OSError("disk full")

        site = SiteDefinition(
            "x",
            "Example",
            "https://example.test/{username}",
            DetectionSpec(present=Rule("status", statuses=(200,))),
        )
        async with UsernameEngine(
            SiteRegistry([site]),
            FakeTransport(handler=lambda r, i: TransportResponse(r.url, 200)),
            sink=failing_sink,
        ) as engine:
            values = await asyncio.wait_for(engine.search("alice"), 2)
            assert len(values) == 1
            assert values[0].detection.state == ExecutionState.INTERNAL_ERROR
            assert engine.sink_errors == 2

    asyncio.run(run())
