"""Typed contracts shared by planning, transport, detection and output."""

from __future__ import annotations

import math
from dataclasses import dataclass
from enum import StrEnum
from typing import TypeAlias

from ultimate_username.domain.metadata import ProfileMetadata

JSONValue: TypeAlias = None | bool | int | float | str | list["JSONValue"] | dict[str, "JSONValue"]
Headers: TypeAlias = tuple[tuple[str, str], ...]


class Verdict(StrEnum):
    FOUND = "FOUND"
    NOT_FOUND = "NOT_FOUND"
    PROBABLE = "PROBABLE"
    UNKNOWN = "UNKNOWN"


class ExecutionState(StrEnum):
    OK = "OK"
    TIMEOUT = "TIMEOUT"
    RATE_LIMITED = "RATE_LIMITED"
    BLOCKED = "BLOCKED"
    NETWORK_ERROR = "NETWORK_ERROR"
    SERVER_ERROR = "SERVER_ERROR"
    PARSE_ERROR = "PARSE_ERROR"
    DETECTION_ERROR = "DETECTION_ERROR"
    CONFIG_ERROR = "CONFIG_ERROR"
    INTERNAL_ERROR = "INTERNAL_ERROR"
    INVALID_INPUT = "INVALID_INPUT"
    UNSUPPORTED = "UNSUPPORTED"
    SKIPPED = "SKIPPED"
    CANCELLED = "CANCELLED"
    BUDGET_EXHAUSTED = "BUDGET_EXHAUSTED"
    API_REQUIRED = "API_REQUIRED"
    DEGRADED = "DEGRADED"


class ErrorCode(StrEnum):
    DNS_NOT_FOUND = "DNS_NOT_FOUND"
    DNS_TEMPORARY = "DNS_TEMPORARY"
    CONNECTION_FAILED = "CONNECTION_FAILED"
    CONNECTION_RESET = "CONNECTION_RESET"
    TLS_ERROR = "TLS_ERROR"
    CONNECT_TIMEOUT = "CONNECT_TIMEOUT"
    READ_TIMEOUT = "READ_TIMEOUT"
    ATTEMPT_TIMEOUT = "ATTEMPT_TIMEOUT"
    QUEUE_TIMEOUT = "QUEUE_TIMEOUT"
    JOB_TIMEOUT = "JOB_TIMEOUT"
    RATE_LIMITED = "RATE_LIMITED"
    ACCESS_DENIED = "ACCESS_DENIED"
    LOGIN_REQUIRED = "LOGIN_REQUIRED"
    CHALLENGE = "CHALLENGE"
    SERVER_ERROR = "SERVER_ERROR"
    BODY_LIMIT = "BODY_LIMIT"
    PARSE_ERROR = "PARSE_ERROR"
    DETECTION_ERROR = "DETECTION_ERROR"
    INVALID_SITE = "INVALID_SITE"
    INVALID_INPUT = "INVALID_INPUT"
    UNSUPPORTED = "UNSUPPORTED"
    REDIRECT_ERROR = "REDIRECT_ERROR"
    INTERNAL_ERROR = "INTERNAL_ERROR"
    CANCELLED = "CANCELLED"
    REQUEST_BUDGET = "REQUEST_BUDGET"
    API_CREDENTIAL_REQUIRED = "API_CREDENTIAL_REQUIRED"
    CIRCUIT_OPEN = "CIRCUIT_OPEN"


class PredicateState(StrEnum):
    TRUE = "TRUE"
    FALSE = "FALSE"
    UNOBSERVED = "UNOBSERVED"


class Polarity(StrEnum):
    PRESENT = "SUPPORTS_PRESENT"
    ABSENT = "SUPPORTS_ABSENT"
    OBSTRUCTION = "OBSTRUCTION"
    CONTEXT = "CONTEXT"


class HttpMethod(StrEnum):
    GET = "GET"
    HEAD = "HEAD"
    POST = "POST"
    PUT = "PUT"


class ExtractionState(StrEnum):
    SUCCESS = "SUCCESS"
    PARTIAL = "PARTIAL"
    EMPTY = "EMPTY"
    ERROR = "ERROR"
    TIMEOUT = "TIMEOUT"
    SKIPPED = "SKIPPED"


@dataclass(frozen=True, slots=True)
class SearchError:
    code: ErrorCode
    phase: str
    message: str
    retryable: bool = False
    cause_type: str | None = None


@dataclass(frozen=True, slots=True)
class TimeoutProfile:
    connect: float = 5.0
    read: float = 10.0
    total: float = 15.0
    queue: float = 60.0


@dataclass(frozen=True, slots=True)
class RetryPolicy:
    max_attempts: int = 1
    base_delay: float = 1.0
    max_delay: float = 30.0
    jitter: bool = True
    retry_statuses: tuple[int, ...] = (500, 502, 503, 504)
    retry_timeouts: bool = True


@dataclass(frozen=True, slots=True)
class IdentifierPolicy:
    strip_whitespace: bool = False
    strip_at: bool = False
    lowercase: bool = False
    unicode_form: str | None = None
    remove_characters: str = ""
    pattern: str | None = None
    max_length: int = 256


@dataclass(frozen=True, slots=True)
class Username:
    raw: str
    canonical: str
    site_specific: str
    transformations: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class Rule:
    """Declarative predicate tree. Custom strategies register names explicitly."""

    strategy: str
    value: str = ""
    statuses: tuple[int, ...] = ()
    path: tuple[str, ...] = ()
    children: tuple[Rule, ...] = ()
    scope: str = "body"
    group: str | None = None


@dataclass(frozen=True, slots=True)
class DetectionSpec:
    present: Rule | None = None
    absent: Rule | None = None
    binding: Rule | None = None
    negative_verified: bool = False
    login_paths: tuple[str, ...] = ("/login", "/signin", "/sign-in")
    block_markers: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class RedirectPolicy:
    follow: bool = False
    max_hops: int = 5
    allowed_origins: tuple[str, ...] = ()
    post_to_get: bool = False


@dataclass(frozen=True, slots=True)
class RateProfile:
    concurrency: int = 1
    min_interval: float = 0.0


@dataclass(frozen=True, slots=True)
class ExtractionRule:
    name: str
    strategy: str
    path: tuple[str, ...] = ()
    pattern: str = ""
    group: int = 1
    expected_host: str | None = None
    prefix: str = ""
    item_path: tuple[str, ...] = ()
    owner_path: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class Provenance:
    donor: str = "native"
    source_record: str = ""
    source_revision: str = ""
    warnings: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class Control:
    username: str
    expected: Verdict
    verified: bool = True


@dataclass(frozen=True, slots=True)
class SiteDefinition:
    id: str
    name: str
    profile_url: str
    detection: DetectionSpec
    probe_url: str | None = None
    category: str = "misc"
    tags: tuple[str, ...] = ()
    method: HttpMethod = HttpMethod.GET
    headers: Headers = ()
    query: tuple[tuple[str, str], ...] = ()
    json_body: str | None = None
    form_body: tuple[tuple[str, str], ...] = ()
    raw_body: str | None = None
    identifier: IdentifierPolicy = IdentifierPolicy()
    timeout: TimeoutProfile = TimeoutProfile()
    retry: RetryPolicy = RetryPolicy()
    rate: RateProfile = RateProfile()
    redirects: RedirectPolicy = RedirectPolicy()
    body_limit: int = 1_048_576
    disabled: bool = False
    disabled_reason: str = ""
    idempotent: bool = False
    context_id: str = "public"
    extractors: tuple[ExtractionRule, ...] = ()
    enrichment_urls: tuple[str, ...] = ()
    controls: tuple[Control, ...] = ()
    provenance: Provenance = Provenance()
    schema_version: int = 1
    credential_env: str = ""
    credential_header: str = "Authorization"
    credential_prefix: str = "Bearer "
    discovery_only: bool = False


@dataclass(frozen=True, slots=True)
class ValidationIssue:
    path: str
    message: str
    code: str = "INVALID_SITE"


@dataclass(frozen=True, slots=True)
class RegistryEntry:
    id: str
    definition: SiteDefinition | None
    issues: tuple[ValidationIssue, ...] = ()


@dataclass(frozen=True, slots=True)
class TransportRequest:
    url: str
    method: HttpMethod = HttpMethod.GET
    headers: Headers = ()
    body: bytes | None = None
    timeout: TimeoutProfile = TimeoutProfile()
    body_limit: int = 1_048_576
    context_id: str = "public"


@dataclass(frozen=True, slots=True)
class RequestPlan:
    task_id: str
    site_id: str
    username: Username
    profile_url: str
    request: TransportRequest
    site: SiteDefinition


@dataclass(frozen=True, slots=True)
class RedirectHop:
    url: str
    status: int
    location: str
    method: HttpMethod


@dataclass(frozen=True, slots=True)
class Timing:
    elapsed: float = 0.0
    queue_wait: float = 0.0
    first_byte: float | None = None


@dataclass(frozen=True, slots=True)
class TransportResponse:
    requested_url: str
    status: int | None = None
    body: bytes = b""
    headers: Headers = ()
    final_url: str = ""
    history: tuple[RedirectHop, ...] = ()
    timing: Timing = Timing()
    error: SearchError | None = None
    body_complete: bool = True
    backend: str = "unknown"
    received_bytes: int = 0

    def header(self, name: str) -> str | None:
        return next((v for k, v in self.headers if k.casefold() == name.casefold()), None)


@dataclass(frozen=True, slots=True)
class DetectionEvidence:
    rule_id: str
    strategy: str
    polarity: Polarity
    state: PredicateState
    observed: str
    locator: str = ""
    complete: bool = True
    diagnostic: str | None = None


@dataclass(frozen=True, slots=True)
class Confidence:
    value: float | None = None
    strength: str = "INSUFFICIENT"
    reason: str = "No calibrated model is available"

    def __post_init__(self) -> None:
        if self.value is not None and (not math.isfinite(self.value) or not 0 <= self.value <= 1):
            raise ValueError("Confidence must be null or finite in [0,1]")


@dataclass(frozen=True, slots=True)
class EvidenceSignal:
    kind: str
    source: str
    strength: str
    weight: int
    independence_group: str
    value: str
    locator: str = ""
    complete: bool = True


@dataclass(frozen=True, slots=True)
class DetectionResult:
    verdict: Verdict = Verdict.UNKNOWN
    state: ExecutionState = ExecutionState.OK
    evidence: tuple[DetectionEvidence, ...] = ()
    reasons: tuple[str, ...] = ()
    errors: tuple[SearchError, ...] = ()
    confidence: Confidence = Confidence()
    response_class: str = "UNCLASSIFIED"
    evidence_level: int = 0
    signals: tuple[EvidenceSignal, ...] = ()
    detector: str = "GenericDetector"

    def __post_init__(self) -> None:
        if self.state != ExecutionState.OK and self.verdict != Verdict.UNKNOWN:
            raise ValueError("An execution error cannot assert account existence or absence")


@dataclass(frozen=True, slots=True)
class FieldObservation:
    name: str
    value_json: str
    source_url: str
    extractor: str
    locator: str = ""
    derivation: str = "EXTRACTED"
    relation: str = "OWNER"

    def value(self) -> JSONValue:
        from ultimate_username.domain.json_types import parse_json

        return parse_json(self.value_json)


@dataclass(frozen=True, slots=True)
class ExtractionResult:
    state: ExtractionState = ExtractionState.SKIPPED
    fields: tuple[FieldObservation, ...] = ()
    errors: tuple[SearchError, ...] = ()


@dataclass(frozen=True, slots=True)
class AttemptRecord:
    number: int
    url: str
    status: int | None
    state: ExecutionState
    timing: Timing
    error: SearchError | None = None
    retry_after: str | None = None
    body_sha256: str = ""
    backend: str = "unknown"
    budget_reason: str = "PRIMARY_CHECK"
    block_class: str = ""
    received_bytes: int = 0
    retained_bytes: int = 0


@dataclass(frozen=True, slots=True)
class DefinitionObservation:
    site_id: str
    role: str
    detection: DetectionResult
    attempts: tuple[AttemptRecord, ...] = ()
    probe_url: str = ""
    block_class: str = ""


@dataclass(frozen=True, slots=True)
class SearchResult:
    job_id: str
    task_id: str
    site_id: str
    username: Username
    detection: DetectionResult
    profile_url: str = ""
    probe_url: str = ""
    final_url: str = ""
    attempts: tuple[AttemptRecord, ...] = ()
    enrichment: ExtractionResult = ExtractionResult()
    profile_metadata: ProfileMetadata = ProfileMetadata()
    enrichment_attempts: tuple[AttemptRecord, ...] = ()
    definition_revision: str = ""
    format_version: int = 1
    redirects: tuple[RedirectHop, ...] = ()
    canonical_service: str = ""
    primary_definition: str = ""
    fallback_chain: tuple[DefinitionObservation, ...] = ()
    source_kind: str = "DIRECT_EVIDENCE"
