"""Bounded, typed observations. Quality describes evidence, not a probability."""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from typing import TypeAlias

FieldValue: TypeAlias = str | int | bool | tuple[str, ...]


class EnrichmentMode(StrEnum):
    OFF = "off"
    BASIC = "basic"
    FULL = "full"


class MetadataState(StrEnum):
    SKIPPED = "SKIPPED"
    UNAVAILABLE = "UNAVAILABLE"
    EMPTY = "EMPTY"
    SUCCESS = "SUCCESS"
    PARTIAL = "PARTIAL"
    ERROR = "ERROR"
    TIMEOUT = "TIMEOUT"


class EvidenceQuality(StrEnum):
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    UNVERIFIED = "UNVERIFIED"


@dataclass(frozen=True, slots=True)
class FieldCandidate:
    name: str
    value: FieldValue
    source_site: str
    source_url: str
    extractor: str
    evidence: str
    observed_at: str
    quality: EvidenceQuality
    priority: int
    validation: str = "VALID"


@dataclass(frozen=True, slots=True)
class FieldCoverage:
    available_fields: tuple[str, ...] = ()
    extracted_fields: tuple[str, ...] = ()
    rejected_fields: tuple[str, ...] = ()
    missing_fields: tuple[str, ...] = ()
    invalid_fields: tuple[str, ...] = ()
    null_fields: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class ProfileMetadata:
    state: MetadataState = MetadataState.SKIPPED
    fields: tuple[FieldCandidate, ...] = ()
    extra_fields: tuple[FieldCandidate, ...] = ()
    candidates: tuple[FieldCandidate, ...] = ()
    conflicts: tuple[str, ...] = ()
    errors: tuple[str, ...] = ()
    parser_failures: int = 0
    extractor_failures: int = 0
    parse_seconds: float = 0.0
    enrichment_seconds: float = 0.0
    html_parse_count: int = 0
    request_count: int = 0
    response_storage: str = "NONE"
    diagnostics: tuple[str, ...] = ()
    coverage: FieldCoverage = FieldCoverage()

    def get(self, name: str) -> FieldValue | None:
        return next((f.value for f in self.fields + self.extra_fields if f.name == name), None)
