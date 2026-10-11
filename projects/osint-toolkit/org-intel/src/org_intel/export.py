"""Eksport magazynu: JSON (z atrybucja HIBP) i CSV (osobny plik na typ encji).

Domyslnie adresy e-mail osob sa maskowane (j***@domena); pelne tylko z include_emails=True.
Skrot tokenow weryfikacji nie jest eksportowany. CSV: ochrona przed formula injection.
"""

from __future__ import annotations

import csv
import dataclasses
import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from . import models
from .logging_redact import mask_email
from .models import SourceType
from .store import Store

HIBP_ATTRIBUTION = {
    "text": "Dane o incydentach pochodzą z publicznego katalogu Have I Been Pwned (https://haveibeenpwned.com), "
    "udostępnionego na licencji Creative Commons Attribution 4.0.",
    "source": "Have I Been Pwned",
    "url": "https://haveibeenpwned.com",
    "license": "CC BY 4.0",
    "license_url": "https://creativecommons.org/licenses/by/4.0/",
}

_INJECTION_PREFIXES = ("=", "+", "-", "@", "\t", "\r")


def sanitize_cell(value: Any) -> Any:
    """Wartosci tekstowe zaczynajace sie od = + - @ tab/CR dostaja przedrostek ' (CSV/formula injection)."""
    if isinstance(value, str) and value.startswith(_INJECTION_PREFIXES):
        return "'" + value
    return value


def _cell(value: Any) -> Any:
    if value is None:
        return ""
    if isinstance(value, bool):
        return str(value).lower()
    if isinstance(value, list):
        return sanitize_cell(";".join(str(x) for x in value))
    if isinstance(value, int | float):
        return value
    return sanitize_cell(str(value))


def _person_rows(store: Store, include_emails: bool) -> list[dict[str, Any]]:
    rows = []
    for p in sorted(store.persons.values(), key=lambda x: x.id):
        d = p.to_dict()
        if d["public_email"] and not include_emails:
            d["public_email"] = mask_email(d["public_email"])
        rows.append(d)
    return rows


def _sections(store: Store, include_emails: bool) -> dict[str, list[dict[str, Any]]]:
    data = store.to_dict()
    return {
        "sources": data["sources"],
        "organizations": data["organizations"],
        "domains": data["domains"],
        "persons": _person_rows(store, include_emails),
        "incidents": data["incidents"],
        "observations": data["observations"],
    }


def build_json(store: Store, *, include_emails: bool = False, now: datetime | None = None) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "schema_version": store.to_dict()["schema_version"],
        "exported_at": (now or datetime.now(UTC)).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "emails_masked": not include_emails,
    }
    if any(s.source_type is SourceType.HIBP_CATALOG for s in store.sources.values()):
        payload["attribution"] = [HIBP_ATTRIBUTION]
    payload.update(_sections(store, include_emails))
    return payload


def export_json(store: Store, out: Path | str, *, include_emails: bool = False, now: datetime | None = None) -> Path:
    path = Path(out)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(build_json(store, include_emails=include_emails, now=now), ensure_ascii=False, indent=2),
        encoding="utf-8",
    )
    return path


def export_csv(store: Store, out_dir: Path | str, *, include_emails: bool = False) -> list[Path]:
    """Zapisuje sources.csv, organizations.csv, domains.csv, persons.csv, incidents.csv, observations.csv."""
    directory = Path(out_dir)
    directory.mkdir(parents=True, exist_ok=True)
    written: list[Path] = []
    for name, rows in _sections(store, include_emails).items():
        path = directory / f"{name}.csv"
        columns = list(rows[0].keys()) if rows else _empty_columns(name)
        with path.open("w", encoding="utf-8-sig", newline="") as fh:
            writer = csv.writer(fh)
            writer.writerow(columns)
            for row in rows:
                writer.writerow([_cell(row.get(c)) for c in columns])
        written.append(path)
    if any(s.source_type is SourceType.HIBP_CATALOG for s in store.sources.values()):
        attr = directory / "ATTRIBUTION.txt"
        attr.write_text(HIBP_ATTRIBUTION["text"] + "\n", encoding="utf-8")
        written.append(attr)
    return written


def _empty_columns(section: str) -> list[str]:
    cls = {
        "sources": models.Source,
        "organizations": models.Organization,
        "domains": models.Domain,
        "persons": models.Person,
        "incidents": models.Incident,
        "observations": models.Observation,
    }[section]
    return [f.name for f in dataclasses.fields(cls)]
