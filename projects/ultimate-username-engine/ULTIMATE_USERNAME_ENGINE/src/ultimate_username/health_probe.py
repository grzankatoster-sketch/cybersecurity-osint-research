"""Definition health ranking: probe, passive aggregation and data/health.json (SPEC_F3 F3.1).

The probe sends one known-existing name and one random name per definition through the
production engine (exhaustive policy, control request included) and ``judge`` turns the
two results into a state. States feed ``runtime_policy.technical_quality`` and the
selection gate. The pure parts (states, points, file I/O, ``judge``, passive
aggregation) import nothing from the engine so that ``runtime_policy`` can use them.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import os
import random
from collections import Counter
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass, replace
from datetime import date, timedelta
from pathlib import Path
from typing import TYPE_CHECKING

from ultimate_username.domain.models import (
    AttemptRecord,
    DetectionResult,
    ErrorCode,
    ExecutionState,
    SearchResult,
    Verdict,
)

if TYPE_CHECKING:
    from ultimate_username.registry import SiteRegistry
    from ultimate_username.transport import Transport

DEAD = "dead"
BLOCKED = "blocked"
FALSE_POSITIVE = "false_positive"
UNINFORMATIVE = "uninformative"
STALE = "stale"
UNSTABLE = "unstable"
OK = "ok"
UNTESTED = "untested"

STATES = (DEAD, BLOCKED, FALSE_POSITIVE, UNINFORMATIVE, STALE, UNSTABLE, OK, UNTESTED)
SKIP_BY_DEFAULT = frozenset({DEAD, BLOCKED, FALSE_POSITIVE})
HEALTH_POINTS: Mapping[str, int] = {
    OK: 15,
    UNTESTED: 0,
    UNSTABLE: -10,
    STALE: -30,
    UNINFORMATIVE: -40,
    BLOCKED: -50,
    DEAD: -100,
    FALSE_POSITIVE: -100,
}
MAX_AGE_DAYS = 30
MAX_REASON = 300
SOURCES = ("probe", "passive")
CONTROL_REASON = "CONTROL_CHECK"
_NOT_OBSERVED = frozenset(
    {
        ExecutionState.SKIPPED,
        ExecutionState.INVALID_INPUT,
        ExecutionState.CONFIG_ERROR,
        ExecutionState.UNSUPPORTED,
        ExecutionState.CANCELLED,
        ExecutionState.BUDGET_EXHAUSTED,
        ExecutionState.INTERNAL_ERROR,
    }
)
_BLOCK_STATES = frozenset(
    {ExecutionState.BLOCKED, ExecutionState.RATE_LIMITED, ExecutionState.API_REQUIRED}
)
_BLOCK_CODES = frozenset(
    {
        ErrorCode.CHALLENGE,
        ErrorCode.ACCESS_DENIED,
        ErrorCode.LOGIN_REQUIRED,
        ErrorCode.RATE_LIMITED,
        ErrorCode.API_CREDENTIAL_REQUIRED,
    }
)
# Only a name that does not resolve is "dead": refused/reset connections are as likely to be
# our own network, a proxy or a firewall, so they rate "unstable" (F3.6).
_DEAD_CODES = frozenset({ErrorCode.DNS_NOT_FOUND})
# Writing health data is refused when more than this share of the results is dead/blocked.
BROKEN_SHARE_LIMIT = 0.4
_UNINFORMATIVE_REASONS = frozenset({"CONTROL_IDENTICAL", "JS_SHELL"})


@dataclass(frozen=True, slots=True)
class HealthEntry:
    state: str
    reason: str
    checked: date
    known: str = ""
    source: str = "probe"


HealthMap = Mapping[str, HealthEntry]


def health_points(state: str) -> int:
    return HEALTH_POINTS[state]


def broken_share(entries: HealthMap) -> float:
    """Share of dead + blocked ratings; a high value means a failed run, not a bad catalog."""
    if not entries:
        return 0.0
    return sum(e.state in (DEAD, BLOCKED) for e in entries.values()) / len(entries)


# ----------------------------------------------------------------------- judge


@dataclass(frozen=True, slots=True)
class _Obs:
    verdict: Verdict
    state: ExecutionState
    codes: frozenset[ErrorCode]
    reasons: frozenset[str]
    status: int | None
    body: str

    @classmethod
    def build(cls, detection: DetectionResult, attempts: Iterable[AttemptRecord]) -> _Obs | None:
        if detection.state in _NOT_OBSERVED:
            return None
        main = [a for a in attempts if a.budget_reason != CONTROL_REASON]
        codes = {e.code for e in detection.errors} | {a.error.code for a in main if a.error}
        last = main[-1] if main else None
        return cls(
            detection.verdict,
            detection.state,
            frozenset(codes),
            frozenset(detection.reasons),
            last.status if last else None,
            last.body_sha256 if last else "",
        )

    @property
    def decided(self) -> bool:
        return self.verdict != Verdict.UNKNOWN

    @property
    def positive(self) -> bool:
        return self.verdict in (Verdict.FOUND, Verdict.PROBABLE)

    @property
    def dead(self) -> bool:
        return not self.decided and bool(self.codes & _DEAD_CODES)

    @property
    def blocked(self) -> bool:
        return not self.decided and (
            self.state in _BLOCK_STATES
            or bool(self.codes & _BLOCK_CODES)
            or self.status in (401, 403, 429)
        )

    @property
    def unstable(self) -> bool:
        return not self.decided and (
            self.state != ExecutionState.OK or (self.status is not None and self.status >= 500)
        )


def _observation(result: SearchResult | None) -> _Obs | None:
    return None if result is None else _Obs.build(result.detection, result.attempts)


def judge(known: SearchResult | None, random_result: SearchResult | None) -> tuple[str, str]:
    """State of one definition from a known-existing name and a random name.

    Checked in order: dead, blocked, false_positive, uninformative, stale, unstable,
    ok, untested. Dead and blocked need every available observation to agree; a
    missing result (no donor control, no admissible random name) is not an observation.
    """
    k, r = _observation(known), _observation(random_result)
    seen = [o for o in (k, r) if o is not None]
    if not seen:
        return UNTESTED, "NO_OBSERVATION"
    if all(o.dead for o in seen):
        codes = sorted({c.value for o in seen for c in o.codes & _DEAD_CODES})
        return DEAD, "+".join(codes)
    if all(o.blocked for o in seen):
        return BLOCKED, _block_reason(seen)
    if r is not None and r.positive:
        return FALSE_POSITIVE, "RANDOM_NAME_" + r.verdict.value
    if k is not None and k.reasons & _UNINFORMATIVE_REASONS:
        return UNINFORMATIVE, "+".join(sorted(k.reasons & _UNINFORMATIVE_REASONS))
    if (
        k is not None
        and r is not None
        and k.state == r.state == ExecutionState.OK
        and k.body
        and k.body == r.body
        and k.status == r.status
        and k.status not in (404, 410)
    ):
        return UNINFORMATIVE, "IDENTICAL_RESPONSES"
    if k is not None and k.verdict == Verdict.NOT_FOUND:
        return STALE, "KNOWN_NAME_NOT_FOUND"
    if k is not None and k.positive and r is not None and r.blocked:
        return OK, "KNOWN_FOUND_RANDOM_BLOCKED"  # the account is still detected
    for label, o in (("KNOWN", k), ("RANDOM", r)):
        if o is not None and o.unstable:
            return UNSTABLE, f"{label}_{o.state.value}" + (f"_{o.status}" if o.status else "")
        if o is not None and o.blocked:
            return UNSTABLE, f"{label}_BLOCKED"
        if o is not None and o.dead:
            return UNSTABLE, f"{label}_UNREACHABLE"
    if k is None:
        return UNTESTED, "NO_DONOR_CONTROL"
    if not k.positive:
        return UNSTABLE, "KNOWN_NAME_UNKNOWN"
    if r is None:
        return UNTESTED, "NO_RANDOM_NAME"
    if r.verdict == Verdict.NOT_FOUND:
        return OK, "KNOWN_FOUND_RANDOM_NOT_FOUND"
    return OK, "KNOWN_FOUND_RANDOM_UNKNOWN"


def _block_reason(seen: list[_Obs]) -> str:
    parts = sorted(
        {c.value for o in seen for c in o.codes & _BLOCK_CODES}
        | {str(o.status) for o in seen if o.status in (401, 403, 429)}
        | {o.state.value for o in seen if o.state in _BLOCK_STATES}
    )
    return "+".join(parts) or "BLOCKED"


# ------------------------------------------------------------------ file format


def _day(value: object, what: str) -> date:
    if not isinstance(value, str) or len(value) != 10:
        raise ValueError(f"health: {what} must be an ISO date")
    try:
        return date.fromisoformat(value)
    except ValueError as exc:
        raise ValueError(f"health: {what} must be an ISO date") from exc


def parse_health(
    text: str, *, today: date | None = None, max_age_days: int = MAX_AGE_DAYS
) -> dict[str, HealthEntry]:
    """Strictly validated entries; those older than ``max_age_days`` are ignored."""
    now = today or date.today()
    try:
        doc = json.loads(text)
    except ValueError as exc:
        raise ValueError(f"health: invalid JSON: {exc}") from exc
    if not isinstance(doc, dict) or set(doc) - {"meta", "sites"} or "sites" not in doc:
        raise ValueError("health: expected an object with 'meta' and 'sites'")
    meta, sites = doc.get("meta", {}), doc["sites"]
    if not isinstance(meta, dict) or not isinstance(sites, dict):
        raise ValueError("health: 'meta' and 'sites' must be objects")
    if set(meta) - {"checked", "source", "states"}:
        raise ValueError("health: unknown meta fields")
    if "checked" in meta:
        _day(meta["checked"], "meta.checked")
    entries: dict[str, HealthEntry] = {}
    for site_id, raw in sites.items():
        if not site_id or not isinstance(raw, dict):
            raise ValueError("health: every site needs an id and an object")
        if set(raw) - {"state", "reason", "checked", "known", "source"}:
            raise ValueError(f"health: unknown fields for {site_id}")
        state, reason = raw.get("state"), raw.get("reason")
        if state not in STATES:
            raise ValueError(f"health: bad state for {site_id}")
        if not isinstance(reason, str) or len(reason) > MAX_REASON:
            raise ValueError(f"health: bad reason for {site_id}")
        known, source = raw.get("known", ""), raw.get("source", "probe")
        if not isinstance(known, str) or len(known) > 200 or source not in SOURCES:
            raise ValueError(f"health: bad known/source for {site_id}")
        checked = _day(raw.get("checked"), f"{site_id}.checked")
        if checked > now + timedelta(days=1):
            raise ValueError(f"health: {site_id} is dated in the future")
        if (now - checked).days > max_age_days:
            continue
        entries[site_id] = HealthEntry(state, reason, checked, known, source)
    return entries


def load_health(
    path: Path, *, today: date | None = None, max_age_days: int = MAX_AGE_DAYS
) -> dict[str, HealthEntry]:
    """A missing file means no health data (no effect on selection)."""
    if not path.is_file():
        return {}
    return parse_health(
        path.read_text(encoding="utf-8-sig"), today=today, max_age_days=max_age_days
    )


def health_document(
    entries: HealthMap, *, source: str, today: date | None = None
) -> dict[str, object]:
    ordered = sorted(entries.items())
    newest = max((e.checked for _, e in ordered), default=today or date.today())
    return {
        "meta": {
            "checked": newest.isoformat(),
            "source": source,
            "states": dict(sorted(Counter(e.state for _, e in ordered).items())),
        },
        "sites": {
            site_id: {
                "state": e.state,
                "reason": e.reason[:MAX_REASON],
                "checked": e.checked.isoformat(),
                "known": e.known,
                "source": e.source,
            }
            for site_id, e in ordered
        },
    }


def save_health(
    path: Path, entries: HealthMap, *, source: str = "probe", today: date | None = None
) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    text = json.dumps(
        health_document(entries, source=source, today=today), ensure_ascii=False, indent=1
    )
    temp = path.with_name(path.name + ".tmp")
    temp.write_text(text, encoding="utf-8")
    os.replace(temp, path)


def fill_missing(primary: HealthMap, secondary: HealthMap) -> dict[str, HealthEntry]:
    """``secondary`` only for definitions the primary source did not rate."""
    return {**secondary, **primary}


# ---------------------------------------------------------------------- passive


def passive_health(
    results: Iterable[SearchResult], *, today: date | None = None, min_samples: int = 2
) -> dict[str, HealthEntry]:
    """Zero-request health from already collected results (several runs may be mixed).

    Positive evidence is a FOUND/PROBABLE verdict; absence of failure alone is not
    enough, so a definition without hits and without failures stays ``untested``.
    """
    now = today or date.today()
    tally: dict[str, Counter[str]] = {}
    for result in results:
        steps = (
            [(s.site_id, s.detection, s.attempts) for s in result.fallback_chain]
            if result.fallback_chain
            else [(result.site_id, result.detection, result.attempts)]
        )
        for site_id, detection, attempts in steps:
            obs = _Obs.build(detection, attempts)
            if obs is None:
                continue
            counts = tally.setdefault(site_id, Counter())
            counts["n"] += 1
            counts["dead"] += obs.dead
            counts["blocked"] += obs.blocked
            counts["unstable"] += obs.unstable and not obs.blocked and not obs.dead
            counts["hit"] += obs.positive
            counts["uninformative"] += bool(obs.reasons & _UNINFORMATIVE_REASONS)
    entries: dict[str, HealthEntry] = {}
    for site_id, c in sorted(tally.items()):
        n = c["n"]
        detail = f"PASSIVE n={n} hit={c['hit']} blocked={c['blocked']} dead={c['dead']}"
        if n >= min_samples and c["dead"] == n:
            state = DEAD
        elif n >= min_samples and c["blocked"] >= 0.8 * n and c["hit"] == 0:
            state = BLOCKED
        elif n >= min_samples and c["uninformative"] >= 0.5 * n and c["hit"] == 0:
            state = UNINFORMATIVE
        elif n >= min_samples and c["unstable"] >= 0.5 * n and c["hit"] == 0:
            state = UNSTABLE
        elif c["hit"] > 0:
            state = OK
        else:
            state = UNTESTED
        entries[site_id] = HealthEntry(state, detail, now, source="passive")
    return entries


# ------------------------------------------------------------------------ probe


def _seeded(site_id: str, seed: int) -> random.Random:
    digest = hashlib.sha256(f"{seed}:{site_id}".encode()).digest()
    return random.Random(int.from_bytes(digest[:8], "big"))


async def probe_health(
    registry: SiteRegistry,
    transport: Transport,
    site_ids: Iterable[str] | None = None,
    *,
    concurrency: int = 20,
    seed: int = 0,
    today: date | None = None,
    job_timeout: float = 45.0,
    progress: Callable[[str, HealthEntry], None] | None = None,
) -> dict[str, HealthEntry]:
    """Known + random name per definition, both through the production engine.

    The policy is the exhaustive one, narrowed to a single definition: the control
    request stays on, but there is no fallback, enrichment or second service.
    """
    from ultimate_username.control import control_name
    from ultimate_username.domain.metadata import EnrichmentMode
    from ultimate_username.domain.models import Control
    from ultimate_username.engine import SearchOptions, UsernameEngine
    from ultimate_username.runtime_policy import MODES, runtime_selection
    from ultimate_username.scheduler import SchedulerConfig
    from ultimate_username.selection import select_services

    if concurrency < 1:
        raise ValueError("concurrency must be positive")
    now = today or date.today()
    policy = replace(
        MODES["exhaustive"],
        service_budget=1,
        request_budget=12,
        retry_budget=4,
        enrichment_budget=0,
        fallback_limit=0,
        control_budget=4,
        job_timeout=job_timeout,
        retry_min_delay=0.5,
    )
    options = SearchOptions(
        job_timeout=job_timeout,
        request_budget=policy.request_budget,
        enrichment_mode=EnrichmentMode.OFF,
    )
    wanted = sorted(set(site_ids) if site_ids is not None else {e.id for e in registry.entries})
    entries = [registry.get(s) for s in wanted]
    usable = [
        e
        for e in entries
        if e is not None and e.definition and not e.issues and not e.definition.disabled
    ]
    gate = asyncio.Semaphore(concurrency)
    out: dict[str, HealthEntry] = {}

    async with UsernameEngine(
        registry,
        transport,
        config=SchedulerConfig(
            concurrency=concurrency,
            per_origin=2,
            per_job=2,
            queue_capacity=max(128, concurrency * 4),
            max_jobs=max(32, concurrency + 4),
        ),
        random_seed=seed,
    ) as engine:

        async def run(site_id: str, name: str) -> SearchResult | None:
            selection = runtime_selection(
                registry, select_services(registry, name, ids=[site_id]), policy
            )
            if not selection.selected:
                return None
            stream = engine.search_stream(
                name,
                site_ids=selection.selected,
                options=options,
                runtime=policy,
                selection=selection,
            )
            try:
                async for result in stream:
                    return result
                return None
            finally:
                await stream.aclose()

        async def one(entry_id: str) -> None:
            entry = registry.get(entry_id)
            assert entry is not None and entry.definition is not None
            site = entry.definition
            donor: Control | None = next(
                (c for c in site.controls if c.expected == Verdict.FOUND and c.verified), None
            )
            known_name = donor.username if donor else ""
            random_name = control_name(
                _seeded(entry_id, seed), known_name or "probe", site.identifier
            )
            async with gate:
                try:
                    known = await run(entry_id, known_name) if known_name else None
                    other = await run(entry_id, random_name) if random_name else None
                    state, reason = judge(known, other)
                except asyncio.CancelledError:
                    raise
                except Exception as exc:
                    state, reason = UNSTABLE, f"PROBE_EXCEPTION:{type(exc).__name__}"
            health = HealthEntry(state, reason, now, known_name)
            out[entry_id] = health
            if progress is not None:
                progress(entry_id, health)

        await asyncio.gather(*(one(e.id) for e in usable))
    return dict(sorted(out.items()))
