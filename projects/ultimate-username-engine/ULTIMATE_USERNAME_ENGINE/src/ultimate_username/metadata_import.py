"""Blackbird metadata conversion; image fields remain URLs, never hidden downloads."""

from __future__ import annotations

from dataclasses import dataclass

from ultimate_username.domain.models import ExtractionRule, JSONValue
from ultimate_username.importers import obj, string


@dataclass(frozen=True, slots=True)
class MetadataImport:
    service: str
    rule: ExtractionRule | None
    status: str
    diagnostics: tuple[str, ...] = ()


def path_parts(value: JSONValue) -> tuple[str, ...]:
    if value is None:
        return ()
    if not isinstance(value, list) or any(type(x) not in (int, str) for x in value):
        raise ValueError("Path must contain string keys or integer indexes")
    return tuple(str(x) for x in value)


def import_metadata(raw: JSONValue) -> tuple[MetadataImport, ...]:
    result: list[MetadataImport] = []
    for service, values in obj(obj(raw).get("sites")).items():
        if not isinstance(values, list):
            result.append(MetadataImport(service, None, "INVALID", ("Expected array",)))
            continue
        for value in values:
            try:
                data = obj(value)
                unknown = set(data) - {"schema", "type", "name", "path", "prefix", "item-path"}
                if unknown:
                    raise ValueError("Unsupported fields: " + ",".join(sorted(unknown)))
                schema = string(data, "schema")
                if schema not in ("JSON", "HTML"):
                    raise ValueError("Unsupported metadata schema")
                if string(data, "type") not in ("String", "Array", "Image"):
                    raise ValueError("Unsupported metadata type")
                rule = ExtractionRule(
                    string(data, "name"),
                    "json" if schema == "JSON" else "regex",
                    path=path_parts(data.get("path")) if schema == "JSON" else (),
                    pattern=string(data, "path") if schema == "HTML" else "",
                    prefix=string(data, "prefix"),
                    item_path=path_parts(data.get("item-path")),
                )
                result.append(
                    MetadataImport(
                        service,
                        rule,
                        "IMPORTED",
                        ("Requires explicit profile context before attaching to a site",),
                    )
                )
            except (ValueError, TypeError) as exc:
                result.append(MetadataImport(service, None, "UNSUPPORTED", (str(exc),)))
    return tuple(result)
