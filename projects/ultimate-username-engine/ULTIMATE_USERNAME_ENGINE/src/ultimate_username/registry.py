"""Network-free validated snapshots; invalid and duplicate entries remain observable."""

from __future__ import annotations

import hashlib
from collections import Counter
from collections.abc import Iterable
from functools import cached_property
from pathlib import Path
from types import MappingProxyType

from ultimate_username.domain.codec import from_value, to_json
from ultimate_username.domain.json_types import parse_json
from ultimate_username.domain.models import RegistryEntry, SiteDefinition, ValidationIssue
from ultimate_username.domain.validation import SiteDefinitionValidator

# Donor overlays loaded next to data/catalog.json (F3.2); the catalog itself is never edited.
OVERLAY_FILES = ("osint_custom.json",)


class SiteRegistry:
    def __init__(
        self,
        sites: Iterable[SiteDefinition | RegistryEntry],
        validator: SiteDefinitionValidator | None = None,
    ) -> None:
        validation = validator or SiteDefinitionValidator()
        entries: list[RegistryEntry] = []
        for item in sites:
            if isinstance(item, SiteDefinition):
                entries.append(RegistryEntry(item.id, item, validation.validate(item)))
            elif item.definition is not None:
                entries.append(
                    RegistryEntry(
                        item.id, item.definition, item.issues + validation.validate(item.definition)
                    )
                )
            else:
                entries.append(item)
        counts = Counter(e.id for e in entries)
        self._entries = tuple(
            RegistryEntry(
                entry.id,
                entry.definition,
                entry.issues + (ValidationIssue("id", "Duplicate site ID"),),
            )
            if counts[entry.id] > 1
            else entry
            for entry in entries
        )
        self._lookup = MappingProxyType({e.id: e for e in self._entries if counts[e.id] == 1})

    @cached_property
    def revision(self) -> str:
        """Content hash; computed on first use (hashing the whole catalog costs seconds)."""
        return hashlib.sha256(to_json(self._entries).encode()).hexdigest()

    @property
    def entries(self) -> tuple[RegistryEntry, ...]:
        return self._entries

    @property
    def categories(self) -> tuple[str, ...]:
        return tuple(sorted({e.definition.category for e in self._entries if e.definition}))

    def get(self, site_id: str) -> RegistryEntry | None:
        return self._lookup.get(site_id)

    def select(
        self,
        ids: Iterable[str] | None = None,
        categories: Iterable[str] | None = None,
        include_disabled: bool = True,
    ) -> tuple[RegistryEntry, ...]:
        selected_ids = None if ids is None else frozenset(ids)
        selected_categories = None if categories is None else frozenset(categories)
        return tuple(
            entry
            for entry in self._entries
            if (selected_ids is None or entry.id in selected_ids)
            and (
                selected_categories is None
                or (entry.definition and entry.definition.category in selected_categories)
            )
            and (include_disabled or not entry.definition or not entry.definition.disabled)
        )

    @classmethod
    def from_json(cls, text: str) -> SiteRegistry:
        return cls(_parse_entries(text))

    @classmethod
    def from_path(cls, path: Path, overlays: bool = True) -> SiteRegistry:
        """Load a registry file; next to ``catalog.json`` the ``OVERLAY_FILES`` are appended.

        Overlays are separate donor files (``osint_custom.json``): the catalog stays
        append-only and an id present in both stays visible as a duplicate.
        """
        entries = list(_parse_entries(path.read_text(encoding="utf-8-sig")))
        if overlays and path.name == "catalog.json":
            for name in OVERLAY_FILES:
                extra = path.with_name(name)
                if extra.is_file():
                    entries.extend(_parse_entries(extra.read_text(encoding="utf-8-sig")))
        return cls(entries)


def _parse_entries(text: str) -> list[RegistryEntry]:
    data = parse_json(text)
    if not isinstance(data, list):
        raise ValueError("Registry root must be an array")
    entries: list[RegistryEntry] = []
    for index, record in enumerate(data):
        site_id = f"invalid-{index}"
        if isinstance(record, dict) and isinstance(record.get("id"), str):
            candidate = record["id"]
            if isinstance(candidate, str):
                site_id = candidate
        try:
            site = from_value(SiteDefinition, record)
            entries.append(RegistryEntry(site.id, site))
        except (ValueError, TypeError) as exc:
            entries.append(RegistryEntry(site_id, None, (ValidationIssue("record", str(exc)),)))
    return entries
