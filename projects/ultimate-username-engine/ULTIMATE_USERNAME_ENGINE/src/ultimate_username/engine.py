"""Library orchestration. HTTP attempts, classification and lifecycle stay separate."""

from __future__ import annotations

import asyncio
import hashlib
import logging
import random
from collections import Counter, deque
from collections.abc import AsyncGenerator, Callable, Iterable, Iterator
from dataclasses import dataclass, field, replace
from time import monotonic, perf_counter
from uuid import uuid4

from ultimate_username import control as ctl
from ultimate_username.api_adapters import API_BODY_LIMIT, api_kind, select_target
from ultimate_username.credentials import resolve_credential
from ultimate_username.detection import (
    DetectionEngine,
    ResponseView,
    classify_response,
    error_state,
    failure_result,
)
from ultimate_username.domain.metadata import EnrichmentMode, MetadataState, ProfileMetadata
from ultimate_username.domain.models import (
    AttemptRecord,
    DefinitionObservation,
    DetectionResult,
    ErrorCode,
    ExecutionState,
    HttpMethod,
    RedirectHop,
    RegistryEntry,
    RequestPlan,
    SearchError,
    SearchResult,
    SiteDefinition,
    Timing,
    TransportRequest,
    TransportResponse,
    Username,
    Verdict,
)
from ultimate_username.domain.urls import origin, render_url
from ultimate_username.enrichment import merge_metadata
from ultimate_username.enrichment_filters import response_digests
from ultimate_username.extraction import ExtractionService
from ultimate_username.planning import normalize, plan_request
from ultimate_username.policies import (
    RETRY_AFTER_GIVE_UP,
    TRANSIENT_ERRORS,
    redirect_request,
    retry_after,
    retry_wait,
    should_retry,
)
from ultimate_username.profile_service import ProfileService
from ultimate_username.registry import SiteRegistry
from ultimate_username.runtime_policy import (
    RuntimePolicy,
    block_class,
    discovery,
    fallback_allowed,
    public_alternative,
)
from ultimate_username.scheduler import Scheduler, SchedulerConfig, Work
from ultimate_username.selection import CanonicalService, SelectionPlan
from ultimate_username.transport import Transport

logger = logging.getLogger(__name__)

CONTROL_CACHE_LIMIT = 4096
# One short retry of a rate-limited control: Retry-After absent or up to this many seconds,
# waiting at most CONTROL_RATE_RETRY_WAIT (with jitter). A longer limit is not waited out.
CONTROL_RATE_RETRY_AFTER = 10.0
CONTROL_RATE_RETRY_WAIT = 5.0


@dataclass(frozen=True, slots=True)
class Metric:
    event: str
    job_id: str
    site_id: str
    state: str
    elapsed: float = 0
    value: int = 1


@dataclass(frozen=True, slots=True)
class SearchSummary:
    job_id: str
    selected: int
    emitted: int
    states: tuple[tuple[str, int], ...]
    interrupted: bool
    request_counts: tuple[tuple[str, int], ...] = ()
    budget_remaining: int = 0


@dataclass(frozen=True, slots=True)
class SearchOptions:
    job_timeout: float = 300
    request_budget: int = 10000
    enrichment_mode: EnrichmentMode | None = None
    enrichment_request_budget: int = 0

    def __post_init__(self) -> None:
        import math

        if self.enrichment_request_budget < 0:
            raise ValueError("Invalid enrichment request budget")
        if self.enrichment_mode is not None and not isinstance(
            self.enrichment_mode, EnrichmentMode
        ):
            raise ValueError("Invalid enrichment mode")

        if not math.isfinite(self.job_timeout) or self.job_timeout <= 0 or self.request_budget < 1:
            raise ValueError("Invalid search budget")


@dataclass
class _Budget:
    deadline: float
    remaining: int
    enrichment_remaining: int = 0
    retry_remaining: int | None = None
    control_remaining: int = 0
    counts: Counter[str] = field(default_factory=Counter)
    consecutive_failures: Counter[str] = field(default_factory=Counter)
    circuit_until: dict[str, float] = field(default_factory=dict)

    def reserve(self, reason: str) -> bool:
        # No await: the check and decrement are atomic within the asyncio loop.
        if (
            self.remaining <= 0
            or reason == "RETRY"
            and self.retry_remaining == 0
            or reason == "CONTROL_CHECK"
            and self.control_remaining <= 0
        ):
            return False
        self.remaining -= 1
        if reason == "RETRY" and self.retry_remaining is not None:
            self.retry_remaining -= 1
        if reason == "CONTROL_CHECK":
            self.control_remaining -= 1
        self.counts[reason] += 1
        return True


@dataclass(frozen=True, slots=True)
class _Held:
    """The main answer, kept while a control request is in flight."""

    response: TransportResponse
    request: TransportRequest
    detection: DetectionResult
    klass: str
    rules: ctl.RuleOutcome
    facts: ctl.PageFacts
    key: tuple[str, str, str, tuple[tuple[str, str], ...]]


class _SearchWork:
    def __init__(
        self,
        engine: UsernameEngine,
        entry: RegistryEntry,
        raw: str,
        job_id: str,
        budget: _Budget,
        options: SearchOptions,
        *,
        runtime: RuntimePolicy | None = None,
        role: str = "PRIMARY_CHECK",
        task_id: str | None = None,
    ) -> None:
        self.engine, self.entry, self.budget = engine, entry, budget
        self.options = options
        self.runtime, self.role = runtime, role
        self.is_retry = False
        self.suppress_commit = runtime is not None
        self.followup = False
        self.job_id, self.task_id = job_id, task_id or uuid4().hex
        self.ready_at = monotonic()
        self.queued_at = self.ready_at
        self.expires_at = budget.deadline
        self.plan: RequestPlan | None = None
        self._result = SearchResult(
            job_id,
            self.task_id,
            entry.id,
            Username(raw, raw, raw),
            DetectionResult(),
            definition_revision=engine.registry.revision,
        )
        self.attempts: list[AttemptRecord] = []
        self.history: list[RedirectHop] = []
        self.visited: set[str] = set()
        self.retry_count = 0
        self.detection_seconds = 0.0
        self.flags = (
            ctl.ControlFlags(
                runtime.control_found,
                runtime.control_absence,
                runtime.control_stale_rule,
                runtime.control_status_absence,
                runtime.control_content_override,
                runtime.control_signatures,
            )
            if runtime
            else ctl.ControlFlags()
        )
        self.control_active = False
        self.control_plan: RequestPlan | None = None
        self.control_history: list[RedirectHop] = []
        self.control_visited: set[str] = set()
        self.control_retry = 0
        self.control_rate_retried = False
        self.control_name = ""
        self.control_seed = 0
        self._held: _Held | None = None
        self._klass = ""
        self._rules: ctl.RuleOutcome | None = None
        self._preflight: SearchError | None = None
        if entry.issues or entry.definition is None:
            self._preflight = SearchError(
                ErrorCode.INVALID_SITE, "validation", "; ".join(i.message for i in entry.issues)
            )
        else:
            try:
                self.plan = plan_request(raw, entry.definition, self.task_id)
                self.visited.add(self.plan.request.url)
                self.expires_at = min(
                    budget.deadline, self.ready_at + entry.definition.timeout.queue
                )
                self._result = replace(
                    self._result,
                    username=self.plan.username,
                    profile_url=self.plan.profile_url,
                    probe_url=self.plan.request.url,
                )
            except ValueError as exc:
                self._preflight = SearchError(ErrorCode.INVALID_INPUT, "normalization", str(exc))
        self.request = self.plan.request if self.plan else None
        if self.plan and self.plan.site.credential_env:
            # Deny by default: only operator-authorised UEE_CRED_* variables, bound to this host.
            credential = (
                resolve_credential(self.plan.site.credential_env, self.request.url).value
                if self.request
                else None
            )
            if not credential:
                self._preflight = SearchError(
                    ErrorCode.API_CREDENTIAL_REQUIRED,
                    "configuration",
                    "SKIPPED_API_CREDENTIAL_REQUIRED",
                )
            elif self.request:
                site = self.plan.site
                self.request = replace(
                    self.request,
                    headers=self.request.headers
                    + ((site.credential_header, site.credential_prefix + credential),),
                )

    def _commit(self, *, tolerate_error: bool = False) -> None:
        if not self.suppress_commit:
            self.engine._commit(self._result, tolerate_error=tolerate_error)

    @property
    def origin(self) -> str:
        return origin(self.request.url) if self.request else "invalid://local"

    @property
    def concurrency(self) -> int:
        return self.plan.site.rate.concurrency if self.plan else 1

    @property
    def interval(self) -> float:
        return self.plan.site.rate.min_interval if self.plan else 0

    def result(self) -> SearchResult:
        return self._result

    def _observe_origin(
        self,
        response: TransportResponse,
        detection: DetectionResult,
        cooldown_cap: float | None = None,
    ) -> float | None:
        after = retry_after(response.header("Retry-After"))
        if self.runtime:
            failure = response.status in (403, 429) or detection.state in (
                ExecutionState.TIMEOUT,
                ExecutionState.SERVER_ERROR,
            )
            self.budget.consecutive_failures[self.origin] = (
                self.budget.consecutive_failures[self.origin] + 1 if failure else 0
            )
            if self.budget.consecutive_failures[self.origin] >= self.runtime.circuit_threshold:
                self.budget.circuit_until[self.origin] = monotonic() + self.runtime.circuit_seconds
            if response.status == 429:
                after = max(after or 0, self.runtime.rate_limit_seconds)
        if response.status == 429 and after is not None:
            # A hostile "Retry-After: 86400" must not park every job of the origin for a day:
            # beyond RETRY_AFTER_GIVE_UP the retry is dropped, so the cooldown is bounded as well.
            cap = RETRY_AFTER_GIVE_UP if cooldown_cap is None else cooldown_cap
            pause = min(after, cap)
            self.engine.scheduler.cooldown(self.origin, monotonic() + pause)
        return after

    def fail(self, error: SearchError) -> SearchResult:
        if self.followup:
            self._result = replace(
                self._result,
                profile_metadata=ProfileMetadata(
                    MetadataState.ERROR, errors=("ENRICHMENT REQUEST:" + error.code.value,)
                ),
            )
            return self._result
        if error.code == ErrorCode.QUEUE_TIMEOUT and monotonic() >= self.budget.deadline:
            error = SearchError(ErrorCode.JOB_TIMEOUT, "job", "Search deadline exceeded")
        if self.control_active and self._held is not None:
            self._abandon_control(error)
        if (
            self.runtime
            and self.attempts
            and error.code
            in (
                ErrorCode.REQUEST_BUDGET,
                ErrorCode.CIRCUIT_OPEN,
                ErrorCode.QUEUE_TIMEOUT,
                ErrorCode.JOB_TIMEOUT,
            )
        ):
            self._result = replace(
                self._result,
                attempts=tuple(self.attempts),
                detection=replace(
                    self._result.detection,
                    reasons=self._result.detection.reasons + (error.code.value,),
                ),
            )
            return self._result
        self._result = replace(
            self._result, detection=failure_result(error), attempts=tuple(self.attempts)
        )
        self._commit(tolerate_error=True)
        return self._result

    def _abandon_control(self, error: SearchError) -> None:
        """The control could not run to the end: record why and keep the main answer."""
        held = self._held
        assert held is not None
        detail = {
            ErrorCode.QUEUE_TIMEOUT: "CONTROL_UNAVAILABLE_TIMEOUT",
            ErrorCode.JOB_TIMEOUT: "CONTROL_UNAVAILABLE_TIMEOUT",
            ErrorCode.ATTEMPT_TIMEOUT: "CONTROL_UNAVAILABLE_TIMEOUT",
            ErrorCode.REQUEST_BUDGET: "CONTROL_UNAVAILABLE_BUDGET",
            ErrorCode.CIRCUIT_OPEN: "CONTROL_UNAVAILABLE_ORIGIN",
            ErrorCode.CANCELLED: "CONTROL_UNAVAILABLE_CANCELLED",
        }.get(error.code)
        self.control_active, self._held = False, None
        if detail is None:
            return
        self._result = replace(
            self._result,
            detection=self._decide_control(held, None, held.detection, detail),
            final_url=held.response.final_url or held.request.url,
            redirects=tuple(self.history),
        )

    async def step(self) -> bool:
        if self._preflight:
            self.fail(self._preflight)
            return True
        assert self.plan is not None and self.request is not None
        plan, site = self.plan, self.plan.site
        if site.disabled:
            self._result = replace(
                self._result,
                detection=DetectionResult(
                    state=ExecutionState.SKIPPED, reasons=(site.disabled_reason or "DISABLED",)
                ),
            )
            self._commit()
            return True
        remaining = self.budget.deadline - monotonic()
        if self.control_active:
            # A control request is optional: when it cannot run, the main answer stands.
            gone = (
                "CONTROL_UNAVAILABLE_TIMEOUT"
                if remaining <= 0
                else "CONTROL_UNAVAILABLE_BUDGET"
                if self.budget.remaining <= 0 or self.budget.control_remaining <= 0
                else "CONTROL_UNAVAILABLE_ORIGIN"
                if self.budget.circuit_until.get(self.origin, 0) > monotonic()
                else ""
            )
            if gone:
                return self._finish_control(None, gone)
        if remaining <= 0 or self.budget.remaining <= 0:
            code = ErrorCode.JOB_TIMEOUT if remaining <= 0 else ErrorCode.REQUEST_BUDGET
            self.fail(SearchError(code, "budget", "Search budget exhausted"))
            return True
        if self.runtime and self.budget.circuit_until.get(self.origin, 0) > monotonic():
            self.fail(SearchError(ErrorCode.CIRCUIT_OPEN, "origin", "Origin temporarily degraded"))
            return True
        reason = (
            "CONTROL_CHECK"
            if self.control_active
            else "ENRICHMENT"
            if self.followup
            else "RETRY"
            if self.is_retry
            else self.role
        )
        if not self.budget.reserve(reason):
            if self.control_active:
                return self._finish_control(None, "CONTROL_UNAVAILABLE_BUDGET")
            self.fail(
                SearchError(ErrorCode.REQUEST_BUDGET, "budget", "Request/retry budget exhausted")
            )
            return True
        self.is_retry = False
        request = replace(
            self.request,
            timeout=replace(self.request.timeout, total=min(self.request.timeout.total, remaining)),
        )
        started = perf_counter()
        queue_wait = max(0, monotonic() - max(self.queued_at, self.ready_at))
        try:
            async with asyncio.timeout(request.timeout.total):
                response = await self.engine.transport.send(request)
        except TimeoutError:
            response = TransportResponse(
                request.url,
                error=SearchError(
                    ErrorCode.ATTEMPT_TIMEOUT, "transport", "Total attempt deadline exceeded", True
                ),
            )
        except asyncio.CancelledError:
            cancelled = AttemptRecord(
                len(self.attempts) + 1,
                request.url,
                None,
                ExecutionState.CANCELLED,
                Timing(elapsed=perf_counter() - started),
                SearchError(ErrorCode.CANCELLED, "transport", "Cancelled after reservation"),
                budget_reason=reason,
            )
            if self.followup:
                self._result = replace(self._result, enrichment_attempts=(cancelled,))
            else:
                self.attempts.append(cancelled)
            raise
        except Exception as exc:
            response = TransportResponse(
                request.url,
                error=SearchError(ErrorCode.INTERNAL_ERROR, "transport", type(exc).__name__),
            )
        response = replace(
            response,
            history=tuple(self.control_history if self.control_active else self.history),
            timing=replace(response.timing, queue_wait=queue_wait),
        )
        if self.control_active:
            return self._after_control(response, request, started)
        if self.followup:
            self.engine._additional_inputs[self.task_id] = response
            followup_errors = classify_response(ResponseView(response), plan)
            self._observe_origin(
                response,
                failure_result(followup_errors[0]) if followup_errors else DetectionResult(),
            )
            record = AttemptRecord(
                1,
                request.url,
                response.status,
                error_state(followup_errors[0].code) if followup_errors else ExecutionState.OK,
                response.timing,
                followup_errors[0] if followup_errors else None,
                response.header("Retry-After"),
                hashlib.sha256(response.body).hexdigest(),
                response.backend,
                budget_reason="ENRICHMENT",
                block_class=block_class(
                    response,
                    failure_result(followup_errors[0]) if followup_errors else DetectionResult(),
                ),
            )
            self._result = replace(self._result, enrichment_attempts=(record,))
            self.engine._emit(
                Metric(
                    "enrichment_request",
                    self.job_id,
                    site.id,
                    str(response.status),
                    perf_counter() - started,
                )
            )
            return True
        detection_start = perf_counter()
        detection = self.engine.detector.detect(response, plan)
        self._klass, self._rules = "", None
        if discovery(site):
            detection = replace(
                detection,
                verdict=Verdict.UNKNOWN,
                reasons=detection.reasons + ("DISCOVERY_ONLY", "INDEX_EVIDENCE"),
            )
            self._result = replace(self._result, source_kind="INDEX_EVIDENCE")
        elif self.runtime:
            detection = self._classify_unknown(response, plan, detection)
        self.detection_seconds += perf_counter() - detection_start
        after = self._observe_origin(response, detection)
        self.attempts.append(
            AttemptRecord(
                len(self.attempts) + 1,
                request.url,
                response.status,
                detection.state,
                response.timing,
                detection.errors[0] if detection.errors else response.error,
                response.header("Retry-After"),
                hashlib.sha256(response.body).hexdigest(),
                response.backend,
                budget_reason=reason,
                block_class=block_class(response, detection),
                received_bytes=response.received_bytes,
                retained_bytes=len(response.body),
            )
        )
        self.engine._emit(
            Metric("attempt", self.job_id, site.id, detection.state.value, perf_counter() - started)
        )
        self._result = replace(
            self._result,
            detection=detection,
            final_url=response.final_url or request.url,
            attempts=tuple(self.attempts),
        )
        if detection.state == ExecutionState.OK:
            try:
                redirected = redirect_request(request, response, plan, self.visited)
            except ValueError as exc:
                self.fail(SearchError(ErrorCode.REDIRECT_ERROR, "redirect", str(exc)))
                return True
            if redirected:
                self.history.append(
                    RedirectHop(
                        request.url,
                        response.status or 0,
                        response.header("Location") or "",
                        request.method,
                    )
                )
                self.visited.add(redirected.url)
                self.request = redirected
                self.queued_at = monotonic()
                self.expires_at = min(self.budget.deadline, monotonic() + site.timeout.queue)
                return False
        self.retry_count += 1
        can_retry = should_retry(
            plan,
            response,
            detection,
            self.retry_count,
            self.runtime.transient_retries if self.runtime else 0,
        )
        if self.runtime:
            can_retry = (
                can_retry
                and self.budget.retry_remaining != 0
                and self.budget.remaining > 0
                and (response.status != 429 or self.retry_count < 2)
                and self.budget.circuit_until.get(self.origin, 0) <= monotonic()
            )
        wait: float | None = None
        if can_retry:
            delay = min(site.retry.max_delay, site.retry.base_delay * 2 ** (self.retry_count - 1))
            if site.retry.jitter:
                delay *= self.engine.random.random()
            # Bounded pause: no retry parks until the job deadline (see policies.retry_wait).
            wait = retry_wait(
                delay,
                after,
                self.runtime.retry_min_delay if self.runtime else 0,
                self.budget.deadline - monotonic(),
            )
        if wait is not None:
            now = monotonic()
            self.is_retry = True
            self.ready_at = now + wait
            self.queued_at = now
            self.expires_at = min(self.budget.deadline, now + wait + site.timeout.queue)
            self.engine._emit(Metric("retry", self.job_id, site.id, detection.state.value, wait))
            return False
        if self._klass in ("A", "B"):
            started_control, detection = self._begin_control(response, request, detection)
            if started_control:
                return False
        return self._finalize(response, request, detection)

    def _finalize(
        self, response: TransportResponse, request: TransportRequest, detection: DetectionResult
    ) -> bool:
        assert self.plan is not None
        plan, site = self.plan, self.plan.site
        self._result = replace(
            self._result,
            detection=detection,
            final_url=response.final_url or request.url,
            attempts=tuple(self.attempts),
            redirects=tuple(self.history),
        )
        self.engine.detection_seconds += self.detection_seconds
        self._commit()
        legacy = (
            self.options.enrichment_mode is None
            and bool(site.extractors)
            and detection.state == ExecutionState.OK
        )
        enabled = self.options.enrichment_mode in (EnrichmentMode.BASIC, EnrichmentMode.FULL)
        if legacy or enabled and detection.verdict in (Verdict.FOUND, Verdict.PROBABLE):
            self.engine._enrichment_inputs[self.task_id] = (response, plan, self.job_id)
        if enabled and detection.verdict not in (Verdict.FOUND, Verdict.PROBABLE):
            self._result = replace(
                self._result, profile_metadata=ProfileMetadata(MetadataState.UNAVAILABLE)
            )
        if (
            self.options.enrichment_mode == EnrichmentMode.FULL
            and detection.verdict == Verdict.FOUND
            and site.enrichment_urls
            and self.budget.enrichment_remaining > 0
            and self.budget.remaining > 0
        ):
            url = render_url(site.enrichment_urls[0], plan.username.site_specific)
            # No headers, cookies, credentials, redirects or retries from the detection request.
            self.request = TransportRequest(url, timeout=site.timeout, body_limit=site.body_limit)
            self.budget.enrichment_remaining -= 1
            self.followup = True
            self.queued_at = monotonic()
            self.expires_at = min(self.budget.deadline, self.queued_at + site.timeout.queue)
            return False
        if (
            self.options.enrichment_mode in (EnrichmentMode.BASIC, EnrichmentMode.FULL)
            and detection.verdict in (Verdict.FOUND, Verdict.PROBABLE)
            and not site.enrichment_urls
        ):
            return self._api_followup(response, plan)
        return True

    def _api_followup(self, response: TransportResponse, plan: RequestPlan) -> bool:
        """E3: one public profile-API request for a confirmed hit (enrichment budget)."""
        target = select_target(plan.profile_url, plan.username.site_specific, response)
        if target is None:
            return True
        if self.budget.enrichment_remaining <= 0 or self.budget.remaining <= 0:
            self._result = replace(
                self._result,
                profile_metadata=ProfileMetadata(
                    MetadataState.SKIPPED, diagnostics=("ENRICHMENT_BUDGET",)
                ),
            )
            return True
        site = plan.site
        # No headers, cookies, credentials, redirects or retries from the detection request.
        self.request = TransportRequest(
            target.url, timeout=site.timeout, body_limit=min(site.body_limit, API_BODY_LIMIT)
        )
        self.budget.enrichment_remaining -= 1
        self.followup = True
        self.queued_at = monotonic()
        self.expires_at = min(self.budget.deadline, self.queued_at + site.timeout.queue)
        return False

    def _classify_unknown(
        self, response: TransportResponse, plan: RequestPlan, detection: DetectionResult
    ) -> DetectionResult:
        """Rules C and D decide at once; classes A and B are remembered for a control."""
        if (
            detection.state != ExecutionState.OK
            or detection.verdict != Verdict.UNKNOWN
            or detection.response_class != "INSUFFICIENT_EVIDENCE"
            or detection.reasons[:1]
            not in (
                ("INSUFFICIENT_EVIDENCE",),
                ("WEAK_STATUS_ONLY_DEFINITION",),
                ("NO_PROFILE_SPECIFIC_EVIDENCE",),
                ("CONTRADICTORY_EVIDENCE",),
            )
        ):
            return detection
        rules = ctl.rule_outcome(self.engine.detector, response, plan)
        klass = ctl.classify_unknown(detection, rules)
        if rules is None or not klass:
            return detection
        if klass in ("A", "B"):
            self._klass, self._rules = klass, rules
            return detection
        donor = any(c.expected == Verdict.FOUND and c.verified for c in plan.site.controls)
        decision = ctl.decide_no_request(
            klass,
            rules,
            response.status,
            response.final_url or response.requested_url,
            plan.request.url,
            donor,
            self.flags,
        )
        if decision is None:
            return detection
        record = {"kind": decision.reasons[0], "class": klass, "status_real": response.status}
        return ctl.apply_decision(detection, decision, record)

    def _credentialed(self, request: TransportRequest) -> TransportRequest:
        assert self.plan is not None
        site = self.plan.site
        credential = resolve_credential(site.credential_env, request.url).value
        if not credential:
            return request
        header = (site.credential_header, site.credential_prefix + credential)
        return replace(request, headers=request.headers + (header,))

    def _decide_control(
        self,
        held: _Held,
        control: ctl.ControlObservation | None,
        detection: DetectionResult,
        detail: str = "",
    ) -> DetectionResult:
        cmp = ctl.compare(held.facts, held.rules, control)
        decision = ctl.decide_with_control(held.klass, held.facts, held.rules, cmp, self.flags)
        if detail and cmp.kind == ctl.CONTROL_UNAVAILABLE:
            decision = replace(decision, reasons=(*decision.reasons, detail))
        record = ctl.comparison_record(held.klass, held.facts, cmp, control)
        if detail:
            record["detail"] = detail
        return ctl.apply_decision(detection, decision, record)

    def _begin_control(
        self, response: TransportResponse, request: TransportRequest, detection: DetectionResult
    ) -> tuple[bool, DetectionResult]:
        """Classes A and B: decide from the cache or set up one control request."""
        assert self.plan is not None and self.runtime is not None and self._rules is not None
        plan, site, klass, rules = self.plan, self.plan.site, self._klass, self._rules
        self._klass = ""
        if self.runtime.control_budget <= 0 or not ctl.wants_request(klass, self.flags):
            return False, detection
        facts = ctl.page_facts(response, plan.username.site_specific)
        key = (site.id, site.method.value, site.probe_url or site.profile_url, site.query)
        held = _Held(response, request, detection, klass, rules, facts, key)

        def without_control(detail: str) -> tuple[bool, DetectionResult]:
            return False, self._decide_control(held, None, detection, detail)

        early = ctl.signature_decision(klass, facts, self.flags)
        if early:
            record = {"kind": early.reasons[0], "class": klass, "signature": facts.signature}
            return False, ctl.apply_decision(detection, early, record)
        if site.method not in (HttpMethod.GET, HttpMethod.HEAD, HttpMethod.POST):
            return without_control("CONTROL_UNAVAILABLE_METHOD")
        cached = self.engine._control_cache.get(key)
        if cached is not None:
            return False, self._decide_control(held, replace(cached, cached=True), detection)
        if monotonic() >= self.budget.deadline:
            return without_control("CONTROL_UNAVAILABLE_TIMEOUT")
        if self.budget.remaining <= 0 or self.budget.control_remaining <= 0:
            return without_control("CONTROL_UNAVAILABLE_BUDGET")
        seed = self.engine.random.getrandbits(32)
        name = ctl.control_name(random.Random(seed), plan.username.raw, site.identifier)
        if name is None:
            return without_control("CONTROL_UNAVAILABLE_NAME")
        try:
            control_plan = plan_request(name, site, self.task_id)
        except ValueError:
            return without_control("CONTROL_UNAVAILABLE_NAME")
        control_request = control_plan.request
        if (control_request.url, control_request.body) == (plan.request.url, plan.request.body):
            return without_control("CONTROL_UNAVAILABLE_REQUEST")
        self._held = held
        self.control_active = True
        self.control_plan = control_plan
        self.control_name, self.control_seed = name, seed
        self.control_history, self.control_retry = [], 0
        self.control_rate_retried = False
        self.control_visited = {control_request.url}
        self.request = self._credentialed(control_request)
        self.queued_at = monotonic()
        self.expires_at = min(self.budget.deadline, self.queued_at + site.timeout.queue)
        return True, detection

    def _after_control(
        self, response: TransportResponse, request: TransportRequest, started: float
    ) -> bool:
        """The control answer arrived: follow its redirects or retry, then decide."""
        control_plan = self.control_plan
        assert control_plan is not None and self.runtime is not None
        site = control_plan.site
        detection = self.engine.detector.detect(response, control_plan)
        short_limit = (
            response.status == 429
            and not self.control_rate_retried
            and (retry_after(response.header("Retry-After")) or 0) <= CONTROL_RATE_RETRY_AFTER
        )
        after = self._observe_origin(
            response, detection, cooldown_cap=CONTROL_RATE_RETRY_WAIT if short_limit else None
        )
        self.attempts.append(
            AttemptRecord(
                len(self.attempts) + 1,
                request.url,
                response.status,
                detection.state,
                response.timing,
                detection.errors[0] if detection.errors else response.error,
                response.header("Retry-After"),
                hashlib.sha256(response.body).hexdigest(),
                response.backend,
                budget_reason="CONTROL_CHECK",
                block_class=block_class(response, detection),
                received_bytes=response.received_bytes,
                retained_bytes=len(response.body),
            )
        )
        elapsed = perf_counter() - started
        self.engine._emit(
            Metric("control_request", self.job_id, site.id, detection.state.value, elapsed)
        )
        if response.status == 429 or (
            (response.status or 0) >= 400 and response.header("Retry-After") is not None
        ):
            # The control is optional: never wait out a long rate limit for it. One short
            # retry (Retry-After absent or <= CONTROL_RATE_RETRY_AFTER) fits the control
            # budget; otherwise the origin keeps its cooldown and the main answer stands.
            advised = retry_after(response.header("Retry-After"))
            if (
                response.status == 429
                and not self.control_rate_retried
                and (advised is None or advised <= CONTROL_RATE_RETRY_AFTER)
                and self.budget.remaining > 0
                and self.budget.control_remaining > 0
                and self.budget.circuit_until.get(self.origin, 0) <= monotonic()
            ):
                base = advised if advised is not None else self.runtime.rate_limit_seconds
                pause = min(base, CONTROL_RATE_RETRY_WAIT) * (0.5 + self.engine.random.random() / 2)
                if pause < self.budget.deadline - monotonic():
                    self.control_rate_retried = True
                    # The 429 cooldown (_observe_origin) was capped to this wait.
                    now = monotonic()
                    self.ready_at = now + pause
                    self.queued_at = now
                    self.expires_at = min(self.budget.deadline, now + pause + site.timeout.queue)
                    return False
            return self._finish_control(None, "CONTROL_UNAVAILABLE_RATE_LIMITED")
        if detection.state == ExecutionState.OK:
            try:
                redirected = redirect_request(request, response, control_plan, self.control_visited)
            except ValueError:
                return self._finish_control(None, "CONTROL_UNAVAILABLE_REDIRECT")
            if redirected:
                self.control_history.append(
                    RedirectHop(
                        request.url,
                        response.status or 0,
                        response.header("Location") or "",
                        request.method,
                    )
                )
                self.control_visited.add(redirected.url)
                self.request = redirected
                self.queued_at = monotonic()
                self.expires_at = min(self.budget.deadline, self.queued_at + site.timeout.queue)
                return False
        self.control_retry += 1
        if (
            should_retry(control_plan, response, detection, self.control_retry)
            and self.budget.retry_remaining != 0
            and self.budget.remaining > 0
            and self.budget.control_remaining > 0
            and (response.status != 429 or self.control_retry < 2)
            and self.budget.circuit_until.get(self.origin, 0) <= monotonic()
        ):
            delay = min(site.retry.max_delay, site.retry.base_delay * 2 ** (self.control_retry - 1))
            if site.retry.jitter:
                delay *= self.engine.random.random()
            wait = retry_wait(
                delay, after, self.runtime.retry_min_delay, self.budget.deadline - monotonic()
            )
            if wait is not None:
                if self.budget.retry_remaining is not None:
                    self.budget.retry_remaining -= 1
                now = monotonic()
                self.ready_at = now + wait
                self.queued_at = now
                self.expires_at = min(self.budget.deadline, now + wait + site.timeout.queue)
                return False
        return self._finish_control((response, detection), "")

    def _finish_control(
        self, outcome: tuple[TransportResponse, DetectionResult] | None, detail: str
    ) -> bool:
        """Compare (or give up) and resume the main answer's normal ending."""
        held, control_plan = self._held, self.control_plan
        assert held is not None and control_plan is not None
        self.control_active, self._held = False, None
        observation: ctl.ControlObservation | None = None
        if outcome is not None:
            response, control_detection = outcome
            rules = ctl.rule_outcome(self.engine.detector, response, control_plan)
            if (
                control_detection.state != ExecutionState.OK
                or control_detection.response_class in ("CHALLENGE", "LOGIN_REQUIRED")
                or rules is None
            ):
                detail = "CONTROL_UNAVAILABLE_" + control_detection.state.value
            else:
                observation = ctl.ControlObservation(
                    ctl.page_facts(response, self.control_name),
                    rules,
                    self.control_name,
                    self.control_seed,
                    digests=response_digests(response, self.control_name),
                )
                cache = self.engine._control_cache
                if len(cache) < CONTROL_CACHE_LIMIT:
                    cache[held.key] = observation
        detection = self._decide_control(held, observation, held.detection, detail)
        return self._finalize(held.response, held.request, detection)


class _CanonicalWork:
    """One scheduler work item and task ID per canonical service, including fallbacks."""

    def __init__(
        self,
        engine: UsernameEngine,
        entry: RegistryEntry,
        raw: str,
        job_id: str,
        budget: _Budget,
        options: SearchOptions,
        policy: RuntimePolicy,
        key: str,
        alternatives: tuple[str, ...],
        role: str = "PRIMARY_CHECK",
    ) -> None:
        self.engine, self.raw, self.job_id = engine, raw, job_id
        self.budget, self.options, self.policy = budget, options, policy
        self.key, self.primary = key, entry.id
        self.inner = _SearchWork(
            engine, entry, raw, job_id, budget, options, runtime=policy, role=role
        )
        self.task_id = self.inner.task_id
        self.chain: list[DefinitionObservation] = []
        self.previous: SearchResult | None = None
        self.alternatives: list[RegistryEntry] = []
        endpoints: set[tuple[str, tuple[tuple[str, str], ...]]] = set()
        for sid in alternatives:
            alt = engine.registry.get(sid)
            if alt is None or alt.definition is None or entry.definition is None:
                continue
            site = alt.definition
            endpoint = (site.probe_url or site.profile_url, site.query)
            if (
                not alt.issues
                and not site.disabled
                and endpoint not in endpoints
                and public_alternative(entry.definition, site)
            ):
                self.alternatives.append(alt)
                endpoints.add(endpoint)
        self.alternatives = self.alternatives[: policy.fallback_limit]

    @property
    def continuation_priority(self) -> bool:
        return self.inner.role == "FALLBACK_CHECK"

    @property
    def origin(self) -> str:
        return self.inner.origin

    @property
    def concurrency(self) -> int:
        return self.inner.concurrency

    @property
    def interval(self) -> float:
        return self.inner.interval

    @property
    def ready_at(self) -> float:
        return self.inner.ready_at

    @property
    def expires_at(self) -> float:
        return self.inner.expires_at

    def _observation(self) -> DefinitionObservation:
        result = self.inner.result()
        main_attempts = [a for a in result.attempts if a.budget_reason != "CONTROL_CHECK"]
        classification = (
            main_attempts[-1].block_class
            if main_attempts
            else "API_REQUIRES_KEY"
            if result.detection.state == ExecutionState.API_REQUIRED
            else ""
        )
        return DefinitionObservation(
            result.site_id,
            self.inner.role,
            result.detection,
            result.attempts,
            result.probe_url,
            classification,
        )

    def result(self) -> SearchResult:
        current = self.inner.result()
        chain = (*self.chain, self._observation())
        winner = current
        if self.previous and current.detection.verdict == Verdict.UNKNOWN:
            winner = self.previous
        return replace(
            winner,
            task_id=self.task_id,
            canonical_service=self.key,
            primary_definition=self.primary,
            fallback_chain=chain,
            attempts=tuple(a for step in chain for a in step.attempts),
        )

    def fail(self, error: SearchError) -> SearchResult:
        self.inner.fail(error)
        result = self.result()
        self.engine._commit(result, tolerate_error=True)
        return result

    async def step(self) -> bool:
        if not await self.inner.step():
            return False
        observation = self._observation()
        if (
            self.alternatives
            and self.budget.remaining > 0
            and monotonic() < self.budget.deadline
            and fallback_allowed(observation.detection, observation.block_class)
        ):
            self.chain.append(observation)
            self.previous = self.previous or self.inner.result()
            self.inner = _SearchWork(
                self.engine,
                self.alternatives.pop(0),
                self.raw,
                self.job_id,
                self.budget,
                self.options,
                runtime=self.policy,
                role="FALLBACK_CHECK",
                task_id=self.task_id,
            )
            return False
        return True


def _rescan_candidate(result: SearchResult, registry: SiteRegistry) -> bool:
    """A network or timeout failure that a second look may cure; not NXDOMAIN, TLS or blocks.

    Only idempotent requests are repeated (GET/HEAD, or a definition marked ``idempotent``):
    a timed-out POST may have been executed, so it is never sent twice. Both the definition
    the rescan would run and the one that produced the error must qualify.
    """
    detection = result.detection
    if not (
        detection.state in (ExecutionState.NETWORK_ERROR, ExecutionState.TIMEOUT)
        and any(
            e.code in TRANSIENT_ERRORS or e.code == ErrorCode.QUEUE_TIMEOUT
            for e in detection.errors
        )
    ):
        return False
    for site_id in {result.primary_definition or result.site_id, result.site_id}:
        entry = registry.get(site_id)
        site = entry.definition if entry else None
        if site is None:
            return False
        if site.method not in (HttpMethod.GET, HttpMethod.HEAD) and not site.idempotent:
            return False
    return True


class UsernameEngine:
    def __init__(
        self,
        registry: SiteRegistry,
        transport: Transport,
        *,
        config: SchedulerConfig | None = None,
        detector: DetectionEngine | None = None,
        metrics: Callable[[Metric], None] | None = None,
        sink: Callable[[SearchResult], None] | None = None,
        random_seed: int | None = None,
        extraction: ExtractionService | None = None,
        profiles: ProfileService | None = None,
    ) -> None:
        self.registry, self.transport = registry, transport
        self.detector = detector or DetectionEngine()
        self.scheduler: Scheduler[SearchResult] = Scheduler(config)
        self.metrics, self.sink = metrics, sink
        self.random = random.Random(random_seed)
        self.detection_seconds = 0.0
        self.extraction = extraction or ExtractionService()
        self.profiles = profiles or ProfileService()
        self._additional_inputs: dict[str, TransportResponse] = {}
        self._control_cache: dict[
            tuple[str, str, str, tuple[tuple[str, str], ...]], ctl.ControlObservation
        ] = {}
        self._enrichment_inputs: dict[str, tuple[TransportResponse, RequestPlan, str]] = {}
        self.sink_errors = 0
        # Jobs whose results are not journalled (the rescan pass decides what replaces what).
        self._muted_jobs: set[str] = set()
        self.summaries: deque[SearchSummary] = deque(maxlen=100)
        self._closed = False

    def _control_digests(self, site: SiteDefinition) -> frozenset[str]:
        """Name-independent digests of a control page already fetched for this endpoint."""
        key = (site.id, site.method.value, site.probe_url or site.profile_url, site.query)
        cached = self._control_cache.get(key)
        return cached.digests if cached is not None else frozenset()

    def _emit(self, metric: Metric) -> None:
        logger.debug(
            "engine_event",
            extra={
                "event": metric.event,
                "job_id": metric.job_id,
                "site_id": metric.site_id,
                "state": metric.state,
                "elapsed": metric.elapsed,
            },
        )
        if self.metrics:
            try:
                self.metrics(metric)
            except Exception:
                logger.warning("metrics_callback_failed")

    def _commit(
        self, result: SearchResult, *, tolerate_error: bool = False, emit: bool = True
    ) -> None:
        if result.job_id in self._muted_jobs:
            return
        if self.sink:
            try:
                self.sink(result)
            except Exception:
                self.sink_errors += 1
                if not tolerate_error:
                    raise
                logger.error("result_sink_failed", extra={"task_id": result.task_id})
        if emit:
            self._emit(
                Metric("result", result.job_id, result.site_id, result.detection.state.value)
            )

    async def search_stream(
        self,
        username: str,
        *,
        site_ids: Iterable[str] | None = None,
        categories: Iterable[str] | None = None,
        options: SearchOptions | None = None,
        runtime: RuntimePolicy | None = None,
        selection: SelectionPlan | None = None,
    ) -> AsyncGenerator[SearchResult, None]:
        if self._closed:
            raise RuntimeError("Engine closed")
        normalize(username)  # reject globally invalid input even for an empty selection
        opts = options or SearchOptions()
        if runtime:
            if selection is None:
                raise ValueError("Adaptive runtime requires a canonical SelectionPlan")
            opts = replace(
                opts,
                request_budget=min(opts.request_budget, runtime.request_budget),
                job_timeout=min(opts.job_timeout, runtime.job_timeout),
                enrichment_request_budget=min(
                    opts.enrichment_request_budget, runtime.enrichment_budget
                ),
            )
        budget = _Budget(
            monotonic() + opts.job_timeout,
            opts.request_budget,
            opts.enrichment_request_budget,
            runtime.retry_budget if runtime else None,
            runtime.control_budget if runtime else 0,
        )
        job_id = uuid4().hex
        ordered_ids = tuple(site_ids) if site_ids is not None else None
        if runtime and selection and ordered_ids is None:
            ordered_ids = selection.selected
        entries = self.registry.select(ids=ordered_ids, categories=categories)
        if runtime and selection:
            allowed = set(selection.selected[: runtime.service_budget])
            entries = tuple(e for e in entries if e.id in allowed)
        if ordered_ids is not None:
            positions = {sid: index for index, sid in enumerate(ordered_ids)}
            entries = tuple(sorted(entries, key=lambda entry: positions[entry.id]))
        states: Counter[str] = Counter()
        emitted = 0
        interrupted = True
        service_map = {s.primary: s for s in selection.services} if selection else {}

        def work() -> Iterator[Work[SearchResult]]:
            for entry in entries:
                if runtime and entry.id in service_map:
                    service = service_map[entry.id]
                    yield _CanonicalWork(
                        self,
                        entry,
                        username,
                        job_id,
                        budget,
                        opts,
                        runtime,
                        service.key,
                        service.alternatives,
                    )
                else:
                    yield _SearchWork(self, entry, username, job_id, budget, opts)

        current_task_id: str | None = None
        stream = self.scheduler.stream(work())
        held: list[SearchResult] = []

        async def passes() -> AsyncGenerator[SearchResult, None]:
            # F3.4: results of a network/timeout error wait for the closing rescan pass.
            async for item in stream:
                if runtime and runtime.rescan_errors and _rescan_candidate(item, self.registry):
                    # Journalled at once: an interrupted stream must not lose the ERROR. The
                    # rescan result (if better) overwrites this row under the same task id.
                    self._commit(item, tolerate_error=True, emit=False)
                    held.append(item)
                else:
                    yield item
            if held:
                rescan = self._rescan(
                    tuple(held), username, job_id, budget, opts, runtime, service_map
                )
                try:
                    async for item in rescan:
                        yield item
                finally:
                    await rescan.aclose()

        results = passes()
        try:
            async for result in results:
                current_task_id = result.task_id
                material = self._enrichment_inputs.pop(result.task_id, None)
                if material:
                    response, plan, _ = material
                    if opts.enrichment_mode is None:
                        enrichment = await self.extraction.run(
                            response, plan.username.site_specific, plan.site.extractors
                        )
                        result = replace(result, enrichment=enrichment)
                    else:
                        started = perf_counter()
                        self._emit(Metric("enrichment_attempts", job_id, plan.site.id, "START"))
                        metadata = ProfileMetadata()
                        try:
                            async with asyncio.timeout(max(0, budget.deadline - monotonic())):
                                digests = self._control_digests(plan.site)
                                if digests:
                                    metadata = await self.profiles.run(
                                        response,
                                        plan.username.site_specific,
                                        plan.site,
                                        result.detection,
                                        digests,
                                    )
                                else:
                                    metadata = await self.profiles.run(
                                        response,
                                        plan.username.site_specific,
                                        plan.site,
                                        result.detection,
                                    )
                                additional = self._additional_inputs.pop(result.task_id, None)
                                if additional:
                                    if api_kind(additional.requested_url):
                                        extra = await self.profiles.run(
                                            additional,
                                            plan.username.site_specific,
                                            plan.site,
                                            result.detection,
                                            follow_up=True,
                                        )
                                    else:
                                        extra = await self.profiles.run(
                                            additional,
                                            plan.username.site_specific,
                                            plan.site,
                                            result.detection,
                                        )
                                    extra = replace(extra, request_count=1)
                                    if extra.state == MetadataState.UNAVAILABLE:
                                        extra = replace(
                                            extra, errors=("ENRICHMENT REQUEST UNAVAILABLE",)
                                        )
                                    metadata = merge_metadata(metadata, extra)
                                if (
                                    result.profile_metadata.errors
                                    or result.profile_metadata.diagnostics
                                ):
                                    metadata = merge_metadata(metadata, result.profile_metadata)
                        except TimeoutError:
                            timeout_metadata = ProfileMetadata(
                                MetadataState.TIMEOUT,
                                errors=("job deadline during enrichment",),
                                parser_failures=1,
                            )
                            metadata = (
                                merge_metadata(metadata, timeout_metadata)
                                if metadata.candidates
                                else timeout_metadata
                            )
                        result = replace(result, profile_metadata=metadata)
                        for event, count in (
                            ("fields_extracted", len(metadata.fields) + len(metadata.extra_fields)),
                            ("extractor_failures", metadata.extractor_failures),
                            ("parser_failures", metadata.parser_failures),
                            ("metadata_conflicts", len(metadata.conflicts)),
                        ):
                            self._emit(
                                Metric(
                                    event, job_id, plan.site.id, metadata.state.value, value=count
                                )
                            )
                        self._emit(
                            Metric(
                                "enrichment_latency",
                                job_id,
                                plan.site.id,
                                metadata.state.value,
                                perf_counter() - started,
                            )
                        )
                    self._commit(result, tolerate_error=True)
                if not material and opts.enrichment_mode in (
                    EnrichmentMode.BASIC,
                    EnrichmentMode.FULL,
                ):
                    result = replace(
                        result, profile_metadata=ProfileMetadata(MetadataState.UNAVAILABLE)
                    )
                    self._commit(result, tolerate_error=True)
                self._additional_inputs.pop(result.task_id, None)
                if runtime:
                    self._commit(result, tolerate_error=True)
                states[result.detection.state.value] += 1
                emitted += 1
                yield result
            interrupted = False
        finally:
            await results.aclose()
            await stream.aclose()
            if current_task_id:
                self._additional_inputs.pop(current_task_id, None)
            # Outputs still buffered when the caller stops must release retained bodies.
            for task_id, (_, _, owner) in tuple(self._enrichment_inputs.items()):
                if owner == job_id:
                    self._enrichment_inputs.pop(task_id, None)
                    self._additional_inputs.pop(task_id, None)
            self.summaries.append(
                SearchSummary(
                    job_id,
                    len(entries),
                    emitted,
                    tuple(sorted(states.items())),
                    interrupted,
                    tuple(sorted(budget.counts.items())),
                    budget.remaining,
                )
            )

    def _rekey(self, old: str, new: str, owner: str) -> None:
        """Hand the enrichment material of a rescan task to the task id it replaces."""
        material = self._enrichment_inputs.pop(old, None)
        if material:
            self._enrichment_inputs[new] = (material[0], material[1], owner)
        extra = self._additional_inputs.pop(old, None)
        if extra:
            self._additional_inputs[new] = extra

    async def _rescan(
        self,
        held: tuple[SearchResult, ...],
        username: str,
        job_id: str,
        budget: _Budget,
        options: SearchOptions,
        runtime: RuntimePolicy | None,
        service_map: dict[str, CanonicalService],
    ) -> AsyncGenerator[SearchResult, None]:
        """One more pass over services that ended in a network error or timeout.

        Half the concurrency, the same request budget and deadline. The new result replaces
        the error only when its state is OK; the failed requests stay in its attempts.
        Anything else keeps the original result, and nothing worse is ever journalled.
        """
        assert runtime is not None
        if budget.remaining <= 0 or monotonic() >= budget.deadline:
            for original in held:
                yield original
            return
        rescan_id = job_id + ":rescan"
        originals: dict[str, SearchResult] = {}

        def work() -> Iterator[Work[SearchResult]]:
            for original in held:
                entry_id = original.primary_definition or original.site_id
                entry = self.registry.get(entry_id)
                if entry is None:
                    continue
                service = service_map.get(entry_id)
                if service:
                    canonical = _CanonicalWork(
                        self,
                        entry,
                        username,
                        rescan_id,
                        budget,
                        options,
                        runtime,
                        service.key,
                        service.alternatives,
                        role="RESCAN_CHECK",
                    )
                    originals[canonical.task_id] = original
                    yield canonical
                else:
                    single = _SearchWork(
                        self, entry, username, rescan_id, budget, options, role="RESCAN_CHECK"
                    )
                    originals[single.task_id] = original
                    yield single

        config = self.scheduler.config
        half = max(1, min(config.per_job, config.concurrency) // 2)
        done: set[str] = set()
        self._muted_jobs.add(rescan_id)
        stream = self.scheduler.stream(work(), limit=half)
        try:
            async for new in stream:
                found = originals.get(new.task_id)
                if found is None:
                    continue
                original = found
                done.add(original.task_id)
                if new.detection.state == ExecutionState.OK:
                    self._rekey(new.task_id, original.task_id, job_id)
                    yield replace(
                        new,
                        task_id=original.task_id,
                        job_id=job_id,
                        attempts=tuple(
                            replace(a, number=number)
                            for number, a in enumerate(original.attempts + new.attempts, 1)
                        ),
                        fallback_chain=original.fallback_chain + new.fallback_chain,
                    )
                else:
                    self._enrichment_inputs.pop(new.task_id, None)
                    self._additional_inputs.pop(new.task_id, None)
                    yield original
            for original in held:
                if original.task_id not in done:
                    yield original
        finally:
            await stream.aclose()
            self._muted_jobs.discard(rescan_id)
            for task_id in originals:
                self._enrichment_inputs.pop(task_id, None)
                self._additional_inputs.pop(task_id, None)

    async def search(
        self, username: str, *, options: SearchOptions | None = None
    ) -> list[SearchResult]:
        return [result async for result in self.search_stream(username, options=options)]

    async def search_sites(
        self, username: str, sites: Iterable[str], *, options: SearchOptions | None = None
    ) -> list[SearchResult]:
        return [
            result async for result in self.search_stream(username, site_ids=sites, options=options)
        ]

    async def search_many(
        self, usernames: Iterable[str], *, options: SearchOptions | None = None
    ) -> AsyncGenerator[SearchResult, None]:
        # Sequential jobs are deliberately lazy; callers may share this engine concurrently.
        for username in usernames:
            stream = self.search_stream(username, options=options)
            try:
                async for result in stream:
                    yield result
            finally:
                await stream.aclose()

    async def close(self) -> None:
        if not self._closed:
            self._closed = True
            try:
                await self.scheduler.close()
            finally:
                await self.transport.close()

    async def __aenter__(self) -> UsernameEngine:
        return self

    async def __aexit__(self, exc_type: object, exc: object, tb: object) -> None:
        await self.close()
