"""Network-free strategy registry and evidence resolver; errors never mean missing."""

from __future__ import annotations

import codecs
import re
from collections.abc import Callable, Mapping
from dataclasses import dataclass, replace
from types import MappingProxyType
from typing import Protocol
from urllib.parse import urlsplit

import regex

from ultimate_username.domain.json_types import parse_json
from ultimate_username.domain.models import (
    Confidence,
    DetectionEvidence,
    DetectionResult,
    ErrorCode,
    ExecutionState,
    JSONValue,
    Polarity,
    PredicateState,
    RequestPlan,
    Rule,
    SearchError,
    TransportResponse,
    Verdict,
)
from ultimate_username.evidence import extract_signals
from ultimate_username.profile_binding import dev_object, github_object, github_profile_url
from ultimate_username.response_quality import ResponseQuality, response_quality


def error_state(code: ErrorCode) -> ExecutionState:
    if code in {
        ErrorCode.CONNECT_TIMEOUT,
        ErrorCode.READ_TIMEOUT,
        ErrorCode.ATTEMPT_TIMEOUT,
        ErrorCode.QUEUE_TIMEOUT,
        ErrorCode.JOB_TIMEOUT,
    }:
        return ExecutionState.TIMEOUT
    mapping = {
        ErrorCode.RATE_LIMITED: ExecutionState.RATE_LIMITED,
        ErrorCode.ACCESS_DENIED: ExecutionState.BLOCKED,
        ErrorCode.LOGIN_REQUIRED: ExecutionState.BLOCKED,
        ErrorCode.CHALLENGE: ExecutionState.BLOCKED,
        ErrorCode.SERVER_ERROR: ExecutionState.SERVER_ERROR,
        ErrorCode.BODY_LIMIT: ExecutionState.PARSE_ERROR,
        ErrorCode.PARSE_ERROR: ExecutionState.PARSE_ERROR,
        ErrorCode.DETECTION_ERROR: ExecutionState.DETECTION_ERROR,
        ErrorCode.INVALID_SITE: ExecutionState.CONFIG_ERROR,
        ErrorCode.INVALID_INPUT: ExecutionState.INVALID_INPUT,
        ErrorCode.UNSUPPORTED: ExecutionState.UNSUPPORTED,
        ErrorCode.INTERNAL_ERROR: ExecutionState.INTERNAL_ERROR,
        ErrorCode.CANCELLED: ExecutionState.CANCELLED,
        ErrorCode.REQUEST_BUDGET: ExecutionState.BUDGET_EXHAUSTED,
        ErrorCode.API_CREDENTIAL_REQUIRED: ExecutionState.API_REQUIRED,
        ErrorCode.CIRCUIT_OPEN: ExecutionState.DEGRADED,
    }
    return mapping.get(code, ExecutionState.NETWORK_ERROR)


def failure_result(error: SearchError) -> DetectionResult:
    return DetectionResult(
        state=error_state(error.code), reasons=(error.code.value,), errors=(error,)
    )


class ResponseView:
    """One decoded text and at most one parsed JSON object per observation."""

    def __init__(self, response: TransportResponse) -> None:
        self.response = response
        self.parse_error: str | None = None
        self.json_error: str | None = None
        self._json: JSONValue = None
        self._json_loaded = False
        content_type = response.header("Content-Type") or ""
        match = re.search(r"charset\s*=\s*[\"']?([^;\s\"']+)", content_type, re.I)
        encoding = match.group(1) if match else "utf-8"
        try:
            partial = (
                not response.body_complete
                and response.error is not None
                and response.error.code == ErrorCode.BODY_LIMIT
            )
            self.text = codecs.getincrementaldecoder(encoding)(errors="strict").decode(
                response.body, final=not partial
            )
        except (UnicodeError, LookupError) as exc:
            self.text = ""
            self.parse_error = type(exc).__name__

    def json(self) -> JSONValue:
        if not self._json_loaded:
            self._json_loaded = True
            try:
                self._json = parse_json(self.text)
            except (ValueError, RecursionError) as exc:
                self.json_error = type(exc).__name__
        return self._json


@dataclass(frozen=True, slots=True)
class Evaluation:
    state: PredicateState
    evidence: tuple[DetectionEvidence, ...]
    content_signal: bool = False


@dataclass(frozen=True, slots=True)
class DetectionContext:
    plan: RequestPlan
    polarity: Polarity
    rule_id: str
    regex_timeout: float


EvaluateChild = Callable[[Rule, ResponseView, DetectionContext], Evaluation]


class DetectionStrategy(Protocol):
    def evaluate(
        self, rule: Rule, view: ResponseView, context: DetectionContext, child: EvaluateChild
    ) -> Evaluation: ...


def observed(
    rule: Rule,
    context: DetectionContext,
    matched: bool | None,
    value: str,
    *,
    content: bool = False,
    diagnostic: str | None = None,
    complete: bool = True,
) -> Evaluation:
    state = (
        PredicateState.UNOBSERVED
        if matched is None
        else (PredicateState.TRUE if matched else PredicateState.FALSE)
    )
    evidence = DetectionEvidence(
        context.rule_id,
        rule.strategy,
        context.polarity,
        state,
        value[:256],
        "/".join(rule.path) or rule.scope,
        complete,
        diagnostic,
    )
    return Evaluation(state, (evidence,), content and matched is True)


class StatusCodeDetector:
    def evaluate(
        self, rule: Rule, view: ResponseView, context: DetectionContext, child: EvaluateChild
    ) -> Evaluation:
        status = view.response.status
        return observed(
            rule, context, None if status is None else status in rule.statuses, str(status)
        )


class MessageDetector:
    def evaluate(
        self, rule: Rule, view: ResponseView, context: DetectionContext, child: EvaluateChild
    ) -> Evaluation:
        if view.parse_error or not view.response.body_complete:
            return observed(
                rule,
                context,
                None,
                "",
                diagnostic=view.parse_error or "BODY_INCOMPLETE",
                complete=False,
            )
        text = view.text
        if rule.scope == "title":
            match = re.search(r"<title[^>]*>(.*?)</title>", text, re.I | re.S)
            text = match.group(1) if match else ""
        elif rule.scope != "body":
            raise ValueError("Unsupported message scope")
        marker = rule.value.replace("{username}", context.plan.username.site_specific)
        return observed(rule, context, marker in text, marker, content=True)


class RegexDetector:
    def evaluate(
        self, rule: Rule, view: ResponseView, context: DetectionContext, child: EvaluateChild
    ) -> Evaluation:
        if view.parse_error or not view.response.body_complete:
            return observed(
                rule,
                context,
                None,
                "",
                diagnostic=view.parse_error or "BODY_INCOMPLETE",
                complete=False,
            )
        match = regex.search(rule.value, view.text, timeout=context.regex_timeout)
        matches = match is not None
        if match is not None and rule.group is not None:
            matches = match.group(rule.group) == context.plan.username.site_specific
        return observed(
            rule, context, matches, "regex matched" if matches else "no match", content=True
        )


class JsonDetector:
    def evaluate(
        self, rule: Rule, view: ResponseView, context: DetectionContext, child: EvaluateChild
    ) -> Evaluation:
        if not view.response.body_complete or view.parse_error:
            return observed(
                rule,
                context,
                None,
                "",
                diagnostic=view.parse_error or "BODY_INCOMPLETE",
                complete=False,
            )
        value = view.json()
        if view.json_error:
            return observed(rule, context, None, "", diagnostic=view.json_error)
        for part in rule.path:
            if isinstance(value, dict) and part in value:
                value = value[part]
            elif isinstance(value, list) and part.isdigit() and int(part) < len(value):
                value = value[int(part)]
            else:
                return observed(rule, context, False, "path missing", content=True)
        expected = (
            context.plan.username.site_specific
            if rule.value == "{username}"
            else parse_json(rule.value)
        )
        matches = type(value) is type(expected) and value == expected
        return observed(rule, context, matches, str(value), content=True)


class GithubProfileDetector:
    def evaluate(
        self, rule: Rule, view: ResponseView, context: DetectionContext, child: EvaluateChild
    ) -> Evaluation:
        matched = github_object(
            view.json(), view.response, context.plan.username.site_specific
        ) and github_profile_url(context.plan.profile_url, context.plan.username.site_specific)
        return observed(rule, context, matched, "GitHub login + ID + profile URL", content=True)


class DevProfileDetector:
    def evaluate(
        self, rule: Rule, view: ResponseView, context: DetectionContext, child: EvaluateChild
    ) -> Evaluation:
        matched = dev_object(view.json(), view.response, context.plan.username.site_specific) and (
            context.plan.profile_url == "https://dev.to/" + context.plan.username.site_specific
        )
        return observed(
            rule, context, matched, "DEV public user object + username + ID", content=True
        )


class RedirectDetector:
    def evaluate(
        self, rule: Rule, view: ResponseView, context: DetectionContext, child: EvaluateChild
    ) -> Evaluation:
        target = view.response.final_url
        expected = context.plan.profile_url if rule.value == "{profile_url}" else rule.value
        return observed(rule, context, None if not target else target == expected, target)


class HeaderDetector:
    def evaluate(
        self, rule: Rule, view: ResponseView, context: DetectionContext, child: EvaluateChild
    ) -> Evaluation:
        value = view.response.header(rule.scope)
        return observed(rule, context, value == rule.value, value or "absent")


class CompositeDetector:
    def evaluate(
        self, rule: Rule, view: ResponseView, context: DetectionContext, child: EvaluateChild
    ) -> Evaluation:
        results = [
            child(
                r,
                view,
                DetectionContext(
                    context.plan, context.polarity, f"{context.rule_id}.{i}", context.regex_timeout
                ),
            )
            for i, r in enumerate(rule.children)
        ]
        states = [r.state for r in results]
        if rule.strategy == "not":
            if len(states) != 1:
                raise ValueError("not requires exactly one operand")
            state = {
                PredicateState.TRUE: PredicateState.FALSE,
                PredicateState.FALSE: PredicateState.TRUE,
                PredicateState.UNOBSERVED: PredicateState.UNOBSERVED,
            }[states[0]]
        elif rule.strategy == "all":
            state = (
                PredicateState.FALSE
                if PredicateState.FALSE in states
                else (
                    PredicateState.UNOBSERVED
                    if PredicateState.UNOBSERVED in states
                    else PredicateState.TRUE
                )
            )
        else:
            state = (
                PredicateState.TRUE
                if PredicateState.TRUE in states
                else (
                    PredicateState.UNOBSERVED
                    if PredicateState.UNOBSERVED in states
                    else PredicateState.FALSE
                )
            )
        if not results:
            raise ValueError("Empty composite")
        evidence = tuple(e for result in results for e in result.evidence)
        # Negating absence never manufactures a positive content signal.
        signal = rule.strategy != "not" and any(r.content_signal for r in results)
        return Evaluation(state, evidence, signal)


def classify_response(
    view: ResponseView, plan: RequestPlan, quality: ResponseQuality | None = None
) -> tuple[SearchError, ...]:
    response = view.response
    errors: list[SearchError] = []
    quality = quality or response_quality(
        response, view.text, plan.username.site_specific, plan.profile_url
    )
    if response.error is not None and not (
        response.error.code == ErrorCode.BODY_LIMIT and quality.partial_verified
    ):
        errors.append(response.error)
    status = response.status
    if status == 429:
        errors.append(SearchError(ErrorCode.RATE_LIMITED, "http", "HTTP 429", True))
    elif status == 401:
        errors.append(SearchError(ErrorCode.LOGIN_REQUIRED, "http", "HTTP 401"))
    elif status in (403, 999):
        errors.append(SearchError(ErrorCode.ACCESS_DENIED, "http", f"HTTP {status}"))
    elif status is not None and status >= 500:
        errors.append(SearchError(ErrorCode.SERVER_ERROR, "http", f"HTTP {status}", True))
    text = view.text.lower()
    challenge = (
        any(
            marker in text
            for marker in (
                "<title>just a moment",
                "<title>attention required! | cloudflare",
                "<title>vercel security checkpoint",
                "window.pow_challenge_data",
                'id="challenge-form"',
            )
        )
        or bool(re.search(r"/cdn-cgi/challenge-platform/(?!scripts/jsd/)", text))
        or any(marker in view.text for marker in plan.site.detection.block_markers)
    )
    challenge = challenge or (response.header("cf-mitigated") or "").lower() == "challenge"
    quality = quality or response_quality(
        response, view.text, plan.username.site_specific, plan.profile_url
    )
    if challenge or quality.kind == "CHALLENGE":
        errors.append(SearchError(ErrorCode.CHALLENGE, "gate", "Recognized challenge page"))
    path = urlsplit(response.final_url or response.requested_url).path.rstrip("/")
    if (
        any(path == login.rstrip("/") for login in plan.site.detection.login_paths)
        or quality.kind == "LOGIN_REQUIRED"
    ):
        errors.append(SearchError(ErrorCode.LOGIN_REQUIRED, "gate", "Login URL"))
    if not response.body_complete and response.error is None and not quality.partial_verified:
        errors.append(SearchError(ErrorCode.BODY_LIMIT, "response", "Incomplete response body"))
    return tuple(errors)


class DetectionEngine:
    def __init__(
        self,
        strategies: Mapping[str, DetectionStrategy] | None = None,
        *,
        regex_timeout: float = 0.05,
    ) -> None:
        builtin: dict[str, DetectionStrategy] = {
            "status": StatusCodeDetector(),
            "message": MessageDetector(),
            "regex": RegexDetector(),
            "json": JsonDetector(),
            "github_profile": GithubProfileDetector(),
            "dev_profile": DevProfileDetector(),
            "redirect": RedirectDetector(),
            "header": HeaderDetector(),
            "all": CompositeDetector(),
            "any": CompositeDetector(),
            "not": CompositeDetector(),
        }
        if strategies:
            if builtin.keys() & strategies.keys():
                raise ValueError("Duplicate detector strategy ID")
            builtin.update(strategies)
        self.strategies = MappingProxyType(builtin)
        self.regex_timeout = regex_timeout

    def evaluate(self, rule: Rule, view: ResponseView, context: DetectionContext) -> Evaluation:
        return self.strategies[rule.strategy].evaluate(rule, view, context, self.evaluate)

    def detect(self, response: TransportResponse, plan: RequestPlan) -> DetectionResult:
        view = ResponseView(response)
        quality = response_quality(
            response, view.text, plan.username.site_specific, plan.profile_url
        )
        result = self._decide(response, plan, view, quality)
        return replace(
            result,
            signals=extract_signals(response, view.text, plan, quality, result),
            detector=quality.reason if quality.kind == "PROFILE" else "GenericDetector",
        )

    def _decide(
        self,
        response: TransportResponse,
        plan: RequestPlan,
        view: ResponseView,
        quality: ResponseQuality,
    ) -> DetectionResult:
        errors = classify_response(view, plan, quality)
        if errors:
            evidence = tuple(
                DetectionEvidence(
                    f"gate.{i}",
                    "failure_gate",
                    Polarity.OBSTRUCTION,
                    PredicateState.TRUE,
                    error.code.value,
                )
                for i, error in enumerate(errors)
            )
            return DetectionResult(
                state=error_state(errors[0].code),
                evidence=evidence,
                reasons=tuple(e.code.value for e in errors),
                errors=errors,
                response_class="CHALLENGE"
                if any(e.code == ErrorCode.CHALLENGE for e in errors)
                else "LOGIN_REQUIRED"
                if any(e.code == ErrorCode.LOGIN_REQUIRED for e in errors)
                else "RESPONSE_TOO_LARGE"
                if any(e.code == ErrorCode.BODY_LIMIT for e in errors)
                else error_state(errors[0].code).value,
            )
        if quality.kind not in ("UNCLASSIFIED", "PROFILE"):
            return DetectionResult(
                evidence=(
                    DetectionEvidence(
                        "response.class",
                        "response_classifier",
                        Polarity.OBSTRUCTION,
                        PredicateState.TRUE,
                        quality.reason,
                    ),
                ),
                reasons=(quality.reason,),
                response_class=quality.kind,
                confidence=Confidence(
                    strength="INSUFFICIENT", reason="Response is not verified profile evidence"
                ),
            )
        if quality.kind == "PROFILE":
            return DetectionResult(
                verdict=Verdict.FOUND,
                evidence=(
                    DetectionEvidence(
                        "present.reviewed",
                        "reviewed_profile",
                        Polarity.PRESENT,
                        PredicateState.TRUE,
                        quality.reason,
                    ),
                    DetectionEvidence(
                        "binding.reviewed",
                        "reviewed_profile",
                        Polarity.CONTEXT,
                        PredicateState.TRUE,
                        "Requested endpoint and profile owner agree",
                    ),
                ),
                reasons=(quality.reason,),
                confidence=Confidence(
                    strength="STRONG",
                    reason="Scoped owner-bound profile evidence; not a probability",
                ),
                response_class="PROFILE",
                evidence_level=quality.level,
            )
        spec = plan.site.detection
        empty = Evaluation(PredicateState.FALSE, ())
        try:
            positive = (
                self.evaluate(
                    spec.present,
                    view,
                    DetectionContext(plan, Polarity.PRESENT, "present", self.regex_timeout),
                )
                if spec.present
                else empty
            )
            negative = (
                self.evaluate(
                    spec.absent,
                    view,
                    DetectionContext(plan, Polarity.ABSENT, "absent", self.regex_timeout),
                )
                if spec.absent
                else empty
            )
            binding = (
                self.evaluate(
                    spec.binding,
                    view,
                    DetectionContext(plan, Polarity.CONTEXT, "binding", self.regex_timeout),
                )
                if spec.binding
                else empty
            )
        except Exception as exc:
            return failure_result(
                SearchError(
                    ErrorCode.DETECTION_ERROR,
                    "detection",
                    type(exc).__name__,
                    cause_type=type(exc).__name__,
                )
            )
        evidence = positive.evidence + negative.evidence + binding.evidence
        if view.parse_error or view.json_error:
            error = SearchError(
                ErrorCode.PARSE_ERROR,
                "response",
                view.parse_error or view.json_error or "parse error",
            )
            return DetectionResult(
                state=ExecutionState.PARSE_ERROR, evidence=evidence, errors=(error,)
            )
        p, n = positive.state, negative.state
        verdict = Verdict.UNKNOWN
        reasons: tuple[str, ...] = ("INSUFFICIENT_EVIDENCE",)
        strength = "INSUFFICIENT"
        level = 0
        response_class = "INSUFFICIENT_EVIDENCE"
        if p == n == PredicateState.TRUE:
            reasons = ("CONTRADICTORY_EVIDENCE",)
        elif p == PredicateState.TRUE and n == PredicateState.FALSE:
            if response.status is not None and 200 <= response.status < 300:
                # A status or negated absence rule alone has no profile semantics.
                if spec.binding and binding.state != PredicateState.TRUE:
                    reasons = ("OWNER_BINDING_NOT_CONFIRMED",)
                    response_class = (
                        "WRONG_USER"
                        if binding.state == PredicateState.FALSE
                        else "INSUFFICIENT_EVIDENCE"
                    )
                elif positive.content_signal and binding.state == PredicateState.TRUE:
                    verdict, strength, level = Verdict.FOUND, "STRONG", 3
                    response_class = "PROFILE"
                    reasons = ("POSITIVE_EVIDENCE",)
                elif self._profile_signal(view, plan, positive):
                    verdict, strength, level = Verdict.PROBABLE, "MODERATE", 2
                    response_class = "PROFILE_CANDIDATE"
                    reasons = ("PROFILE_SPECIFIC_SIGNAL_WITHOUT_STRONG_BINDING",)
                else:
                    strength, level = "WEAK", 1
                    reasons = (
                        "WEAK_STATUS_ONLY_DEFINITION"
                        if not positive.content_signal
                        else "NO_PROFILE_SPECIFIC_EVIDENCE",
                    )
        elif n == PredicateState.TRUE and p == PredicateState.FALSE:
            if negative.content_signal or spec.negative_verified:
                verdict, strength = Verdict.NOT_FOUND, "COMPOSITE"
                reasons = ("NEGATIVE_EVIDENCE",)
                response_class = "NOT_FOUND"
        return DetectionResult(
            verdict=verdict,
            evidence=evidence,
            reasons=reasons,
            confidence=Confidence(
                strength=strength, reason="Deterministic evidence criteria; no probability model"
            ),
            response_class=response_class,
            evidence_level=level,
        )

    @staticmethod
    def _profile_signal(view: ResponseView, plan: RequestPlan, positive: Evaluation) -> bool:
        if view.text.lstrip().startswith("{"):
            try:
                data = parse_json(view.text)
            except (ValueError, RecursionError):
                data = None
            if isinstance(data, dict):
                identity = data.get("username", data.get("login"))
                bound = identity == plan.username.site_specific or github_object(
                    data, view.response, plan.username.site_specific
                )
                if bound and any(
                    k in data
                    for k in ("followers", "avatar_url", "bio", "created_at", "user_id", "id")
                ):
                    return True
        return positive.content_signal and any(
            e.state == PredicateState.TRUE
            and e.strategy in ("message", "regex")
            and re.search(r"profile|member|player|nickname|account", e.observed, re.I)
            for e in positive.evidence
        )
