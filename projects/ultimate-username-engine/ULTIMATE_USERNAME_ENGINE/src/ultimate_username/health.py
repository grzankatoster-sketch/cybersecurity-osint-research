"""Health checks compare explicit controls using the exact production detector."""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass

from ultimate_username.domain.models import Control, ExecutionState, SearchResult, Verdict
from ultimate_username.engine import UsernameEngine


@dataclass(frozen=True, slots=True)
class ControlObservation:
    control: Control
    result: SearchResult


@dataclass(frozen=True, slots=True)
class HealthResult:
    site_id: str
    status: str
    observations: tuple[ControlObservation, ...]
    promotion_allowed: bool


async def check_health(
    engine: UsernameEngine, site_id: str, controls: Iterable[Control] | None = None
) -> HealthResult:
    entry = engine.registry.get(site_id)
    if entry is None or entry.definition is None or entry.issues:
        return HealthResult(site_id, "INVALID", (), False)
    chosen = tuple(controls) if controls is not None else entry.definition.controls
    observations: list[ControlObservation] = []
    for control in chosen:
        results = await engine.search_sites(control.username, [site_id])
        observations.extend(ControlObservation(control, result) for result in results)
    if not observations:
        return HealthResult(site_id, "UNTESTED", (), False)
    status = "HEALTHY"
    for observation in observations:
        control, result = observation.control, observation.result
        if not control.verified and result.detection.verdict != control.expected:
            status = "SUSPECT" if status == "HEALTHY" else status
        elif (
            result.detection.state != ExecutionState.OK
            or result.detection.verdict != control.expected
        ):
            status = "DEGRADED"
    verified = {c.expected for c in chosen if c.verified}
    if status == "HEALTHY" and verified != {Verdict.FOUND, Verdict.NOT_FOUND}:
        status = "INCOMPLETE"
    return HealthResult(site_id, status, tuple(observations), status == "HEALTHY")
