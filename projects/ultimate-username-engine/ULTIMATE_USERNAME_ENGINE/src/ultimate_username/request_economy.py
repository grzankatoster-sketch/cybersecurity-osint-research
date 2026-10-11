"""Accounting from committed canonical observations, with persistent local health."""

from __future__ import annotations

import sqlite3
from collections import Counter
from collections.abc import Iterable
from pathlib import Path

from ultimate_username.domain.models import JSONValue, SearchResult, Verdict


def economy(
    results: Iterable[SearchResult],
    *,
    request_budget: int,
    canonical_services: int,
    definitions_considered: int,
) -> dict[str, JSONValue]:
    costs: Counter[str] = Counter()
    blocks: Counter[str] = Counter()
    fallback: Counter[str] = Counter()
    status_codes: Counter[int] = Counter()
    tested = blocked_final = recovered = 0
    for result in results:
        tested += bool(result.attempts)
        blocked_final += result.detection.state in ("BLOCKED", "RATE_LIMITED", "API_REQUIRED")
        for attempt in (*result.attempts, *result.enrichment_attempts):
            costs[attempt.budget_reason] += 1
            # A control probes a random name: its status says nothing about the origin's
            # behaviour towards real profiles, so it stays out of the 403/429 counts.
            if attempt.status is not None and attempt.budget_reason != "CONTROL_CHECK":
                status_codes[attempt.status] += 1
        for step in result.fallback_chain:
            if step.block_class:
                blocks[step.block_class] += 1
            if step.role != "FALLBACK_CHECK" or not step.attempts:
                continue
            fallback["attempted"] += 1
            outcome = (
                "success"
                if step.detection.verdict in (Verdict.FOUND, Verdict.PROBABLE)
                else "not_found"
                if step.detection.verdict == Verdict.NOT_FOUND
                else "blocked"
                if step.detection.state in ("BLOCKED", "RATE_LIMITED")
                else "error"
            )
            fallback[outcome] += 1
        recovered += bool(
            result.primary_definition
            and result.site_id != result.primary_definition
            and result.detection.verdict in (Verdict.FOUND, Verdict.PROBABLE, Verdict.NOT_FOUND)
        )
    used = sum(costs.values())
    return {
        "definitions_considered": definitions_considered,
        "canonical_services": canonical_services,
        "services_tested": tested,
        "services_not_tested": max(0, canonical_services - tested),
        "primary_requests": costs["PRIMARY_CHECK"],
        "fallback_requests": costs["FALLBACK_CHECK"],
        "retries": costs["RETRY"],
        "rescan_requests": costs["RESCAN_CHECK"],
        "enrichment_requests": costs["ENRICHMENT"],
        "control_requests": costs["CONTROL_CHECK"],
        "health_requests": costs["HEALTH_CHECK"],
        "total_requests": used,
        "budget_remaining": request_budget - used,
        "fallback_attempted": fallback["attempted"],
        "fallback_success": fallback["success"],
        "fallback_not_found": fallback["not_found"],
        "fallback_blocked": fallback["blocked"],
        "fallback_error": fallback["error"],
        "recovered_canonical_services": recovered,
        "blocked_canonical_services": blocked_final,
        "no_working_fallback": blocked_final,
        "block_observations": dict(blocks),
        "http_403_responses": status_codes[403],
        "http_429_responses": status_codes[429],
        "duplicate_primary_slots_prevented": max(0, definitions_considered - canonical_services),
        "expansion_suggestion": (
            "Use --mode deep or exhaustive to expand the finite search"
            if tested < canonical_services
            else None
        ),
    }


class DefinitionHealth:
    """SQLite updates are transactional across CLI processes; revisions never mix.

    Counters describe requests/observations, not ground-truth accuracy. No automatic
    primary promotion, including after one successful fallback.
    """

    def __init__(self, path: Path) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        self.db = sqlite3.connect(path, timeout=10)
        self.db.execute("""CREATE TABLE IF NOT EXISTS definition_health (
            revision TEXT, site_id TEXT, checks INTEGER, successful_checks INTEGER,
            blocked_responses INTEGER, timeouts INTEGER, parser_failures INTEGER,
            metadata_success INTEGER, PRIMARY KEY(revision, site_id))""")
        self.db.execute("""CREATE TABLE IF NOT EXISTS health_observations (
            job_id TEXT, task_id TEXT, PRIMARY KEY(job_id, task_id))""")
        self.db.commit()

    def record(self, results: Iterable[SearchResult]) -> None:
        with self.db:
            for result in results:
                inserted = self.db.execute(
                    "INSERT OR IGNORE INTO health_observations VALUES (?,?)",
                    (result.job_id, result.task_id),
                ).rowcount
                if not inserted:
                    continue
                for step in result.fallback_chain:
                    # Control requests probe a random name; they say nothing about the definition.
                    attempts = [a for a in step.attempts if a.budget_reason != "CONTROL_CHECK"]
                    if not attempts:
                        continue
                    values = (
                        result.definition_revision,
                        step.site_id,
                        len(attempts),
                        int(step.detection.verdict != Verdict.UNKNOWN),
                        sum(a.state in ("BLOCKED", "RATE_LIMITED") for a in attempts),
                        sum(a.state == "TIMEOUT" for a in attempts),
                        sum(a.state == "PARSE_ERROR" for a in attempts)
                        + (
                            result.profile_metadata.parser_failures
                            if step.site_id == result.site_id
                            else 0
                        ),
                        int(
                            step.site_id == result.site_id and bool(result.profile_metadata.fields)
                        ),
                    )
                    self.db.execute(
                        """INSERT INTO definition_health VALUES (?,?,?,?,?,?,?,?)
                        ON CONFLICT(revision,site_id) DO UPDATE SET
                        checks=checks+excluded.checks,
                        successful_checks=successful_checks+excluded.successful_checks,
                        blocked_responses=blocked_responses+excluded.blocked_responses,
                        timeouts=timeouts+excluded.timeouts,
                        parser_failures=parser_failures+excluded.parser_failures,
                        metadata_success=metadata_success+excluded.metadata_success""",
                        values,
                    )

    def close(self) -> None:
        self.db.close()
