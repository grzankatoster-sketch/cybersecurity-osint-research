"""Explicit cost ceilings and deterministic canonical planning. No learned guesses."""

from __future__ import annotations

import math
from collections import Counter, defaultdict
from collections.abc import Mapping
from dataclasses import dataclass, replace
from urllib.parse import urlsplit

from ultimate_username.domain.models import (
    DetectionResult,
    ErrorCode,
    ExecutionState,
    HttpMethod,
    RegistryEntry,
    SiteDefinition,
    TransportResponse,
    Verdict,
)
from ultimate_username.domain.validation import walk_rules
from ultimate_username.health_probe import SKIP_BY_DEFAULT, HealthEntry, health_points
from ultimate_username.profile_adapters import scoped_adapter_route
from ultimate_username.registry import SiteRegistry
from ultimate_username.response_quality import discovery_url, profile_kind
from ultimate_username.selection import CanonicalService, SelectionPlan, SiteQualityScore, quality


@dataclass(frozen=True, slots=True)
class RuntimePolicy:
    service_budget: int = 200
    request_budget: int = 250
    retry_budget: int = 10
    enrichment_budget: int = 0
    job_timeout: float = 300
    fallback_limit: int = 2
    min_quality: int = 0
    diversity_penalty: int = 5
    circuit_threshold: int = 3
    circuit_seconds: float = 60
    rate_limit_seconds: float = 30
    retry_min_delay: float = 1
    # Control requests (docs/SPEC_CONTROL_REQUEST.md). The library default sends none;
    # the named modes below set the per-mode ceilings. Rules that need no request are
    # on by default; each rule has its own switch so its precision can be measured.
    control_budget: int = 0
    control_found: bool = True
    control_absence: bool = True
    control_stale_rule: bool = True
    control_status_absence: bool = True
    control_content_override: bool = True
    control_signatures: bool = True
    # Health ranking (F3.1): quick/normal/deep drop definitions rated dead, blocked or
    # false_positive; exhaustive only orders by them. Without health data this is inert.
    health_skip: bool = False
    # Retry and rescan (F3.4). ``transient_retries``: extra attempts per request for reset,
    # refused, temporary DNS, timeouts and 502/503/504 (they spend ``retry_budget``).
    # ``rescan_errors``: one more pass over services that ended in a network/timeout error.
    transient_retries: int = 0
    rescan_errors: bool = False

    def __post_init__(self) -> None:
        for name in ("service_budget", "request_budget", "circuit_threshold"):
            value = getattr(self, name)
            if type(value) is not int or value < 1:
                raise ValueError(f"{name} must be a positive integer")
        for name in (
            "retry_budget",
            "enrichment_budget",
            "diversity_penalty",
            "control_budget",
            "transient_retries",
        ):
            value = getattr(self, name)
            if type(value) is not int or value < 0:
                raise ValueError(f"{name} must be a nonnegative integer")
        for name in (
            "control_found",
            "control_absence",
            "control_stale_rule",
            "control_status_absence",
            "control_content_override",
            "control_signatures",
            "health_skip",
            "rescan_errors",
        ):
            if type(getattr(self, name)) is not bool:
                raise ValueError(f"{name} must be a boolean")
        if (
            type(self.min_quality) is not int
            or type(self.fallback_limit) is not int
            or not 0 <= self.fallback_limit <= 2
        ):
            raise ValueError("Invalid quality threshold/fallback limit")
        for value in (
            self.job_timeout,
            self.circuit_seconds,
            self.rate_limit_seconds,
            self.retry_min_delay,
        ):
            if not math.isfinite(value) or value <= 0:
                raise ValueError("Runtime time limits must be finite and positive")


OSINT_CUSTOM_DONOR = "osint-custom"
OSINT_CUSTOM_BONUS = 100

MODES = {
    "quick": RuntimePolicy(
        service_budget=50,
        request_budget=50,
        retry_budget=0,
        fallback_limit=0,
        min_quality=30,
        job_timeout=90,
        health_skip=True,
    ),
    "normal": RuntimePolicy(
        service_budget=800,
        # 800 primaries + up to 150 control requests + 60 retries + ~90 for fallback/rescan.
        request_budget=1100,
        retry_budget=60,
        control_budget=150,
        health_skip=True,
        transient_retries=2,
        rescan_errors=True,
    ),
    "deep": RuntimePolicy(
        service_budget=1000,
        request_budget=1300,
        retry_budget=50,
        enrichment_budget=50,
        job_timeout=1200,
        min_quality=-30,
        control_budget=150,
        health_skip=True,
        transient_retries=2,
        rescan_errors=True,
    ),
    "exhaustive": RuntimePolicy(
        service_budget=1_000_000,
        request_budget=20_000,
        retry_budget=200,
        enrichment_budget=200,
        job_timeout=3600,
        min_quality=-100,
        control_budget=2500,
        transient_retries=2,
        rescan_errors=True,
    ),
}


def discovery(site: SiteDefinition) -> bool:
    url = urlsplit(site.probe_url or site.profile_url)
    host = (url.hostname or "").removeprefix("www.")
    return (
        site.discovery_only
        or discovery_url(site.profile_url, site.probe_url or site.profile_url)
        or host
        in {
            "google.com",
            "bing.com",
            "duckduckgo.com",
            "search.yahoo.com",
        }
        and url.path.rstrip("/") in ("", "/search", "/html", "/lite")
    )


def technical_quality(
    entry: RegistryEntry,
    conflict: bool = False,
    health: Mapping[str, HealthEntry] | None = None,
) -> SiteQualityScore:
    base = quality(entry)
    site = entry.definition
    if site is None or entry.issues or site.disabled:
        return base
    additions: list[tuple[str, int]] = []
    positive = site.detection.present
    if positive is None:
        additions.append(("NO_POSITIVE_RULE", -20))
    elif all(r.strategy in ("status", "all", "any", "not") for r in walk_rules(positive)):
        additions.append(("WEAK_STATUS_ONLY_DEFINITION", -25))
    if profile_kind(
        (site.probe_url or site.profile_url).replace("{username}", "calibration"), "calibration"
    ) or scoped_adapter_route(site.profile_url, site.probe_url or site.profile_url):
        additions.append(("REVIEWED_SCOPED_OWNER_ADAPTER", 30))
    if positive and any(
        r.strategy in ("json", "github_profile", "dev_profile") for r in walk_rules(positive)
    ):
        additions.append(("STRUCTURED_RESPONSE_RULE", 10))
    if conflict:
        additions.append(("DONOR_RULE_DISAGREEMENT", -5))
    if discovery(site):
        additions.append(("INDEX_EVIDENCE_ONLY", -30))
    if any("detection-quality-v1:NEEDS_RULE_FIX" in w for w in site.provenance.warnings):
        additions.append(("REVIEWED_RULE_FIX_REQUIRED", -20))
    rated = health.get(entry.id) if health else None
    if rated is not None:
        additions.append(("HEALTH_" + rated.state.upper(), health_points(rated.state)))
    return SiteQualityScore(
        base.value + sum(n for _, n in additions),
        base.reasons + tuple(f"{label}:{n:+d}" for label, n in additions),
    )


def variant_bonus(entry: RegistryEntry) -> int:
    """F3.2/F3.6: ordering key for the variants of ONE service, never part of the score.

    A live-calibrated OSINT definition wins its service over donor variants. The bonus must
    not enter ``score.value``: that would lift the overlay's services over every other
    service in the quality tiers (and the queue head) only because of where they came from.
    """
    site = entry.definition
    if site is None or entry.issues or site.disabled:
        return 0
    return OSINT_CUSTOM_BONUS if site.provenance.donor == OSINT_CUSTOM_DONOR else 0


def public_alternative(primary: SiteDefinition, candidate: SiteDefinition) -> bool:
    """Only a distinct credential-free registry GET to the platform or its API host."""
    endpoint = candidate.probe_url or candidate.profile_url
    old = primary.probe_url or primary.profile_url
    profile_host = (urlsplit(candidate.profile_url).hostname or "").removeprefix("www.")
    probe_host = (urlsplit(endpoint).hostname or "").removeprefix("www.")
    return (
        (endpoint, candidate.query) != (old, primary.query)
        and candidate.method == HttpMethod.GET
        and candidate.context_id == "public"
        and not candidate.credential_env
        and not candidate.query  # unknown auxiliary parameters are not presumed public
        and not candidate.json_body
        and not candidate.form_body
        and not candidate.raw_body
        and all(k.lower() in ("accept", "accept-language") for k, _ in candidate.headers)
        and probe_host in (profile_host, "api." + profile_host)
        and not discovery(candidate)
        and candidate.detection.present is not None
        and not any(
            word in urlsplit(endpoint).query.lower()
            for word in ("key=", "token=", "auth=", "session=", "password=")
        )
    )


def runtime_selection(
    registry: SiteRegistry,
    plan: SelectionPlan,
    policy: RuntimePolicy,
    health: Mapping[str, HealthEntry] | None = None,
    include_broken: bool = False,
) -> SelectionPlan:
    """Quality tiers first; category diversity only within the same score tier.

    ``health`` (data/health.json) adds points to the quality score, so working
    definitions come first and the primary of a service is its healthiest variant.
    When the policy has ``health_skip`` (quick/normal/deep) and ``include_broken`` is
    off, a service whose chosen primary is dead, blocked or a false positive is not
    selected (reason ``HEALTH_<STATE>``). In every mode health only reorders (and
    skips); the quality threshold is evaluated without it. The OSINT-custom preference
    only orders the variants inside one service and is not part of the score. No health
    data leaves the plan unchanged.

    Primary cost is one send. Retries/fallbacks are contingent costs, not fake
    latency predictions, and do not lower the value of a useful primary endpoint.
    """
    tiers: dict[int, list[CanonicalService]] = defaultdict(list)
    below_threshold: list[CanonicalService] = []
    excluded = list(plan.excluded)
    for service in plan.services:
        variants = [registry.get(sid) for sid in (service.primary, *service.alternatives)]
        entries = [e for e in variants if e is not None]
        multi = len(entries) > 1
        entries.sort(
            key=lambda e: (
                -(
                    technical_quality(e, service.rule_conflict, health).value
                    + (variant_bonus(e) if multi else 0)
                ),
                e.id,
            )
        )
        primary = entries[0]
        score = technical_quality(primary, service.rule_conflict, health)
        if multi and variant_bonus(primary):
            score = SiteQualityScore(score.value, score.reasons + ("OSINT_CUSTOM_PREFERRED:+0",))
        rated = health.get(primary.id) if health else None
        gate = policy.health_skip and not include_broken
        if rated is not None and gate and rated.state in SKIP_BY_DEFAULT:
            excluded.append((primary.id, "HEALTH_" + rated.state.upper()))
            below_threshold.append(service)
            continue
        # The mode threshold never sees health points (SPEC): health orders and skips only.
        threshold_value = score.value - (health_points(rated.state) if rated else 0)
        if threshold_value < policy.min_quality:
            excluded.append((primary.id, "MODE_QUALITY_THRESHOLD"))
            below_threshold.append(service)
            continue
        tiers[score.value].append(
            replace(
                service,
                primary=primary.id,
                alternatives=tuple(e.id for e in entries[1:]),
                quality=score,
            )
        )
    ordered: list[CanonicalService] = []
    counts: Counter[str] = Counter()
    for tier_score in sorted(tiers, reverse=True):
        # Small per-tier category queues avoid quadratic scans for exhaustive mode.
        categories: dict[str, list[CanonicalService]] = defaultdict(list)
        for service in sorted(tiers[tier_score], key=lambda s: s.key, reverse=True):
            entry = registry.get(service.primary)
            category = entry.definition.category if entry and entry.definition else "misc"
            categories[category].append(service)
        while categories:
            cat = min(
                categories,
                key=lambda c: (counts[c] * policy.diversity_penalty, categories[c][-1].key),
            )
            ordered.append(categories[cat].pop())
            counts[cat] += 1
            if not categories[cat]:
                del categories[cat]
    chosen = ordered[: policy.service_budget]
    selected = tuple(s.primary for s in chosen)
    selected_set = set(selected)
    # Alternatives are inspectable but never consume an extra primary slot.
    excluded = [(sid, reason) for sid, reason in excluded if sid not in selected_set]
    excluded.extend((s.primary, "SERVICE_BUDGET") for s in ordered[len(chosen) :])
    return replace(
        plan,
        selected=selected,
        planned=len(selected),
        services=tuple(ordered + below_threshold),
        excluded=tuple(excluded),
        quality_order=tuple((s.primary, s.quality) for s in chosen),
    )


def block_class(response: TransportResponse, detection: DetectionResult) -> str:
    codes = {e.code for e in detection.errors}
    if ErrorCode.CHALLENGE in codes:
        return "CHALLENGE"
    if ErrorCode.LOGIN_REQUIRED in codes or response.status == 401:
        return "LOGIN_REQUIRED"
    if response.status == 403:
        return "HTTP_403"
    if response.status == 429:
        return "HTTP_429"
    if response.status == 410:
        return "ENDPOINT_REMOVED"
    # A legal/region inference cannot be made from 403 or 451 alone.
    if detection.state == ExecutionState.BLOCKED:
        return "UNKNOWN_BLOCK"
    return ""


def fallback_allowed(detection: DetectionResult, classification: str) -> bool:
    if detection.verdict == Verdict.NOT_FOUND:
        return False
    if detection.state == ExecutionState.RATE_LIMITED:
        return False
    return (
        detection.state
        in {
            ExecutionState.BLOCKED,
            ExecutionState.API_REQUIRED,
            ExecutionState.PARSE_ERROR,
            ExecutionState.UNSUPPORTED,
            ExecutionState.SERVER_ERROR,
        }
        or classification == "ENDPOINT_REMOVED"
    )
