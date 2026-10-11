"""Lokalny magazyn JSON z atomowym zapisem, deduplikacja i obowiazkowa proweniencja.

Zasady scalania:
* zrodla: po znormalizowanym URL; zostaje PIERWSZE zrodlo (jego retrieved_at i metadane), a kazde kolejne
  pobranie tego samego URL zapisuje sie jako nowa Observation z nowszym observed_at;
* encje: po id (sumowanie source_ids, previous_names; pierwsza wartosc pola wygrywa, konflikty to ostrzezenia);
* kazda encja musi miec co najmniej jedna Observation (inaczej ProvenanceError).
Surowe rekordy wejsciowe trafiaja do `raw/` obok magazynu tylko w trybie audytowym (jawnie wlaczonym).
"""

from __future__ import annotations

import json
import os
import tempfile
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from .logging_redact import get_logger
from .models import (
    Domain,
    EntityType,
    Incident,
    Observation,
    Organization,
    Person,
    Source,
)
from .parsers import ParseResult

SCHEMA_VERSION = 1
DEFAULT_STORE = Path("org-intel-data") / "store.json"
log = get_logger("org_intel.store")


class StoreError(Exception):
    """Blad magazynu (nieczytelny plik, nieznana wersja schematu)."""


class ProvenanceError(StoreError):
    """Proba zapisu encji bez obserwacji (proweniencji)."""


@dataclass
class ApplySummary:
    added: dict[str, int] = field(default_factory=dict)
    merged: dict[str, int] = field(default_factory=dict)
    warnings: list[str] = field(default_factory=list)
    raw_file: str | None = None

    def _count(self, bucket: dict[str, int], kind: str) -> None:
        bucket[kind] = bucket.get(kind, 0) + 1


class Store:
    def __init__(self, path: Path | str = DEFAULT_STORE, *, audit_mode: bool = False):
        self.path = Path(path)
        self.audit_mode = audit_mode
        self.sources: dict[str, Source] = {}
        self.organizations: dict[str, Organization] = {}
        self.domains: dict[str, Domain] = {}
        self.persons: dict[str, Person] = {}
        self.incidents: dict[str, Incident] = {}
        self.observations: dict[str, Observation] = {}
        self.verifications: dict[str, dict[str, Any]] = {}  # domena -> {token_hash, issued_at, ...}

    # --- wczytywanie / zapis -----------------------------------------------------

    @classmethod
    def load(cls, path: Path | str = DEFAULT_STORE, *, audit_mode: bool = False) -> Store:
        store = cls(path, audit_mode=audit_mode)
        if not store.path.exists():
            return store
        try:
            data = json.loads(store.path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise StoreError(f"Nie można odczytać magazynu {store.path}: {exc}") from None
        if not isinstance(data, dict) or data.get("schema_version") != SCHEMA_VERSION:
            raise StoreError(
                f"Magazyn {store.path} ma nieznaną wersję schematu ({data.get('schema_version') if isinstance(data, dict) else '?'}); "
                f"obsługiwana: {SCHEMA_VERSION}."
            )
        try:
            for key, attr, model in (
                ("sources", "sources", Source),
                ("organizations", "organizations", Organization),
                ("domains", "domains", Domain),
                ("persons", "persons", Person),
                ("incidents", "incidents", Incident),
                ("observations", "observations", Observation),
            ):
                setattr(store, attr, {r["id"]: model.from_dict(r) for r in data.get(key, [])})
            store.verifications = dict(data.get("verifications", {}))
        except (KeyError, TypeError, ValueError) as exc:
            raise StoreError(f"Magazyn {store.path} ma uszkodzoną zawartość: {exc}") from None
        return store

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": SCHEMA_VERSION,
            "sources": [x.to_dict() for x in sorted(self.sources.values(), key=lambda s: s.id)],
            "organizations": [x.to_dict() for x in sorted(self.organizations.values(), key=lambda s: s.id)],
            "domains": [x.to_dict() for x in sorted(self.domains.values(), key=lambda s: s.id)],
            "persons": [x.to_dict() for x in sorted(self.persons.values(), key=lambda s: s.id)],
            "incidents": [x.to_dict() for x in sorted(self.incidents.values(), key=lambda s: s.id)],
            "observations": [x.to_dict() for x in sorted(self.observations.values(), key=lambda s: s.id)],
            "verifications": self.verifications,
        }

    def save(self) -> None:
        """Zapis atomowy: plik tymczasowy w tym samym katalogu + os.replace."""
        self.path.parent.mkdir(parents=True, exist_ok=True)
        fd, tmp = tempfile.mkstemp(dir=self.path.parent, suffix=".tmp")
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as fh:
                json.dump(self.to_dict(), fh, ensure_ascii=False, indent=2, sort_keys=True)
            os.replace(tmp, self.path)
        except BaseException:
            if os.path.exists(tmp):
                os.unlink(tmp)
            raise

    # --- zapytania -----------------------------------------------------------------

    def observations_for(self, etype: EntityType, entity_id: str) -> list[Observation]:
        return sorted(
            (o for o in self.observations.values() if o.entity_type is etype and o.entity_id == entity_id),
            key=lambda o: (o.observed_at, o.id),
        )

    def find_domain(self, domain: str) -> Domain | None:
        return next((d for d in self.domains.values() if d.domain == domain), None)

    # --- import --------------------------------------------------------------------------

    def apply(self, result: ParseResult, *, now: datetime | None = None) -> ApplySummary:
        """Wlacza wynik parsowania do magazynu (w pamieci; wywolujacy zapisuje `save()`)."""
        summary = ApplySummary()
        observed = {(o.entity_type, o.entity_id) for o in result.observations}
        for etype, entities in (
            (EntityType.ORGANIZATION, result.organizations),
            (EntityType.DOMAIN, result.domains),
            (EntityType.PERSON, result.persons),
            (EntityType.INCIDENT, result.incidents),
        ):
            for ent in entities:
                if (etype, ent.id) not in observed:
                    raise ProvenanceError(f"Encja {etype.value} {ent.id} nie ma obserwacji (proweniencji).")
        for src in result.sources:
            if src.id in self.sources:
                summary._count(summary.merged, "sources")  # zostaje pierwsze zrodlo; nowy dowod = Observation
            else:
                self.sources[src.id] = Source.from_dict(src.to_dict())
                summary._count(summary.added, "sources")
        for kind, bucket, entities in (
            ("organizations", self.organizations, result.organizations),
            ("domains", self.domains, result.domains),
            ("persons", self.persons, result.persons),
            ("incidents", self.incidents, result.incidents),
        ):
            for ent in entities:
                if ent.id in bucket:
                    summary.warnings.extend(bucket[ent.id].merge(ent))
                    summary._count(summary.merged, kind)
                else:
                    bucket[ent.id] = type(ent).from_dict(ent.to_dict())
                    summary._count(summary.added, kind)
        for obs in result.observations:
            if obs.id in self.observations:
                summary._count(summary.merged, "observations")
            else:
                self.observations[obs.id] = obs
                summary._count(summary.added, "observations")
        if self.audit_mode and result.raw_records:
            summary.raw_file = str(self._write_raw(result, now))
        return summary

    def _write_raw(self, result: ParseResult, now: datetime | None) -> Path:
        stamp = (now or datetime.now(UTC)).strftime("%Y%m%dT%H%M%SZ")
        raw_dir = self.path.parent / "raw"
        raw_dir.mkdir(parents=True, exist_ok=True)
        target = raw_dir / f"ingest-{stamp}.json"
        n = 1
        while target.exists():
            n += 1
            target = raw_dir / f"ingest-{stamp}-{n}.json"
        payload = {"format": result.format, "records": result.raw_records}
        target.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
        log.info("zapisano surowe rekordy (tryb audytowy): %s", target)
        return target
