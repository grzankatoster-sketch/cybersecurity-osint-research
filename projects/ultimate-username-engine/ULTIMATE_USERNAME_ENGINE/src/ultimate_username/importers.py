"""Offline, loss-accounted legacy conversion. No execution/import of donor code."""

from __future__ import annotations

import hashlib
import json
import re
from collections import defaultdict
from dataclasses import dataclass, fields, replace
from pathlib import Path
from urllib.parse import parse_qsl, urlsplit

from ultimate_username.domain.codec import to_json
from ultimate_username.domain.json_types import parse_json
from ultimate_username.domain.models import (
    Control,
    DetectionSpec,
    HttpMethod,
    IdentifierPolicy,
    JSONValue,
    Provenance,
    RedirectPolicy,
    Rule,
    SiteDefinition,
    Verdict,
)
from ultimate_username.domain.validation import SiteDefinitionValidator


@dataclass(frozen=True, slots=True)
class ImportRecord:
    donor: str
    name: str
    status: str
    site: SiteDefinition | None
    diagnostics: tuple[str, ...]
    field_map: tuple[tuple[str, str], ...]
    source_json: str


@dataclass(frozen=True, slots=True)
class ImportBatch:
    donor: str
    source_sha256: str
    records: tuple[ImportRecord, ...]

    @property
    def sites(self) -> tuple[SiteDefinition, ...]:
        return tuple(r.site for r in self.records if r.status == "IMPORTED" and r.site)


@dataclass(frozen=True, slots=True)
class DefinitionConflict:
    key: str
    variant_ids: tuple[str, ...]
    donors: tuple[str, ...]
    differing_fields: tuple[str, ...]
    resolution: str = "REQUIRES_CONTROLLED_VALIDATION; no variant selected automatically"


def obj(value: JSONValue) -> dict[str, JSONValue]:
    if not isinstance(value, dict):
        raise ValueError("Expected object")
    return value


def string(data: dict[str, JSONValue], key: str, default: str = "") -> str:
    value = data.get(key, default)
    if not isinstance(value, str):
        raise ValueError(f"{key}: expected string")
    return value


def strings(value: JSONValue) -> tuple[str, ...]:
    if isinstance(value, str):
        return (value,) if value else ()
    if value is None:
        return ()
    if not isinstance(value, list) or any(not isinstance(v, str) for v in value):
        raise ValueError("Expected string or string array")
    return tuple(v for v in value if isinstance(v, str))


def pairs(value: JSONValue) -> tuple[tuple[str, str], ...]:
    if value is None:
        return ()
    data = obj(value)
    if any(not isinstance(v, str) for v in data.values()):
        raise ValueError("Headers/query require string values")
    return tuple((k, v) for k, v in data.items() if isinstance(v, str))


def boolean(data: dict[str, JSONValue], key: str, default: bool = False) -> bool:
    value = data.get(key, default)
    if not isinstance(value, bool):
        raise ValueError(f"{key}: expected boolean")
    return value


def status(data: dict[str, JSONValue], key: str, default: int) -> int:
    value = data.get(key, default)
    if type(value) is not int:
        raise ValueError(f"{key}: expected HTTP status integer")
    assert isinstance(value, int)
    return value


def combine(strategy: str, rules: list[Rule]) -> Rule | None:
    return rules[0] if len(rules) == 1 else Rule(strategy, children=tuple(rules)) if rules else None


def messages(value: JSONValue) -> Rule | None:
    return combine("any", [Rule("message", text) for text in strings(value) if text])


def template(value: str, data: dict[str, JSONValue]) -> str:
    return (
        value.replace("{}", "{username}")
        .replace("{account}", "{username}")
        .replace("{urlMain}", string(data, "urlMain"))
        .replace("{urlSubpath}", string(data, "urlSubpath"))
    )


def replace_payload(value: JSONValue) -> JSONValue:
    if isinstance(value, str):
        return value.replace("{}", "{username}").replace("{account}", "{username}")
    if isinstance(value, list):
        return [replace_payload(x) for x in value]
    if isinstance(value, dict):
        return {k: replace_payload(v) for k, v in value.items()}
    return value


MAPPED_MG = set(
    "url urlMain urlSubpath urlProbe usernameClaimed usernameUnclaimed tags engine "
    "checkType presenseStrs absenceStrs disabled regexCheck headers requestMethod "
    "requestPayload requestHeadOnly getParams errors errorUrl".split()
)
METADATA_MG = set("source mirrors alexaRank similarSearch protection ignore403".split())
UNSUPPORTED_MG = set("activation encoding caseSentitive presenceStrs engineData".split())
MAPPED_SH = set(
    "url urlProbe errorType errorMsg errorCode errorUrl request_method request_payload "
    "headers regexCheck username_claimed username_unclaimed".split()
)
METADATA_SH = set("urlMain isNSFW __comment__ tags".split())
MAPPED_WM = set(
    "name uri_check uri_pretty e_code e_string m_code m_string post_body headers "
    "strip_bad_char known cat valid".split()
)
METADATA_WM = {"protection"}


def merge_engine(
    site: dict[str, JSONValue], engines: dict[str, JSONValue]
) -> tuple[dict[str, JSONValue], list[str]]:
    result = dict(site)
    notes: list[str] = []
    name = string(site, "engine")
    if not name:
        return result, notes
    if name not in engines:
        raise ValueError(f"Unknown engine: {name}")
    inherited = obj(obj(engines[name]).get("site"))
    for key, value in inherited.items():
        if key not in result:
            # Explicitly correct legacy missing dict assignment; record the semantic change.
            result[key] = value
            if isinstance(value, dict):
                notes.append(f"ENGINE_DICT_ASSIGNED:{key}")
        elif isinstance(value, list) and isinstance(result[key], list):
            local = result[key]
            assert isinstance(local, list)
            result[key] = [*local, *value]
        elif isinstance(value, dict) and isinstance(result[key], dict):
            local_object = obj(result[key])
            conflicts = [k for k, v in value.items() if k in local_object and local_object[k] != v]
            if conflicts:
                notes.append(f"AMBIGUOUS_ENGINE_MERGE:{key}:{','.join(conflicts)}")
            result[key] = {**local_object, **value}
        elif result[key] != value:
            notes.append(f"LOCAL_SCALAR_OVERRIDE:{key}")
    return result, notes


def _convert(
    donor: str, name: str, data: dict[str, JSONValue], revision: str
) -> tuple[SiteDefinition, list[str]]:
    notes: list[str] = []
    sid = donor + ":" + hashlib.sha256(name.encode()).hexdigest()[:16]
    headers = pairs(data.get("headers"))
    controls: list[Control] = []
    method = HttpMethod.GET
    payload: str | None = None
    form: tuple[tuple[str, str], ...] = ()
    query: tuple[tuple[str, str], ...] = ()
    positive: Rule | None = None
    negative: Rule | None = None
    follow = False
    identifier = IdentifierPolicy()
    block_markers: tuple[str, ...] = ()
    if donor == "whatsmyname":
        profile = template(string(data, "uri_pretty") or string(data, "uri_check"), data)
        probe = template(string(data, "uri_check"), data)
        pos = [Rule("status", statuses=(status(data, "e_code", 200),))]
        neg = [Rule("status", statuses=(status(data, "m_code", 404),))]
        for key, rules in [("e_string", pos), ("m_string", neg)]:
            marker = string(data, key)
            if marker:
                rules.append(Rule("message", marker.replace("{account}", "{username}")))
            else:
                notes.append(f"EMPTY_MARKER_OMITTED:{key}; status is not proof")
        positive, negative = combine("all", pos), combine("all", neg)
        known = strings(data.get("known"))
        if not known or any(not x for x in known):
            raise ValueError("known: at least one non-empty control is required")
        controls.extend(Control(x, Verdict.FOUND) for x in known)
        identifier = IdentifierPolicy(remove_characters=string(data, "strip_bad_char"))
        category, disabled = string(data, "cat", "misc"), not boolean(data, "valid", True)
        tags: tuple[str, ...] = ()
        if string(data, "post_body"):
            method = HttpMethod.POST
            raw = string(data, "post_body")
            ctype = next((v for k, v in headers if k.lower() == "content-type"), "")
            if "json" in ctype or raw.lstrip().startswith(("{", "[")):
                payload = json.dumps(replace_payload(parse_json(raw)), ensure_ascii=False)
            elif "x-www-form-urlencoded" in ctype:
                form = tuple(
                    (k, v.replace("{account}", "{username}"))
                    for k, v in parse_qsl(raw, keep_blank_values=True, strict_parsing=True)
                )
            else:
                raise ValueError("UNSUPPORTED: ambiguous POST body encoding")
    else:
        profile = template(string(data, "url"), data)
        probe = template(string(data, "urlProbe"), data) or profile
        mg = donor == "maigret"
        kinds = strings(data.get("checkType" if mg else "errorType"))
        if not kinds or any(k not in ("message", "status_code", "response_url") for k in kinds):
            raise ValueError("UNSUPPORTED: detection type")
        present_rules: list[Rule] = []
        absent_rules: list[Rule] = []
        if "message" in kinds:
            positive = messages(data.get("presenseStrs")) if mg else None
            negative = messages(data.get("absenceStrs" if mg else "errorMsg"))
            if positive:
                present_rules.append(positive)
            if negative:
                absent_rules.append(negative)
        if "status_code" in kinds or "response_url" in kinds:
            present_rules.append(Rule("status", statuses=tuple(range(200, 300))))
            codes = data.get("errorCode", [404])
            if type(codes) is int:
                codes = [codes]
            if not isinstance(codes, list) or any(type(n) is not int for n in codes):
                raise ValueError("errorCode: expected integer or integer array")
            absent_rules.append(
                Rule("status", statuses=tuple(n for n in codes if isinstance(n, int)))
            )
        positive = combine("all", present_rules)
        negative = combine("any", absent_rules)
        follow = "response_url" not in kinds
        if string(data, "errorUrl"):
            notes.append("METADATA_ONLY:errorUrl; redirect is not absence proof")
        method = HttpMethod(string(data, "requestMethod" if mg else "request_method", "GET"))
        if mg and boolean(data, "requestHeadOnly"):
            method = HttpMethod.HEAD
        raw_payload = data.get("requestPayload" if mg else "request_payload")
        if raw_payload is not None:
            payload = json.dumps(replace_payload(raw_payload), ensure_ascii=False)
        query = pairs(data.get("getParams"))
        pattern = string(data, "regexCheck")
        if pattern:
            # Legacy uses search; canonical validator uses fullmatch.
            identifier = IdentifierPolicy(pattern="(?s:.*?)(?:" + pattern + ")(?s:.*)")
            notes.append("REGEX_SEARCH_SEMANTICS_PRESERVED")
        for key, expected in [
            ("usernameClaimed" if mg else "username_claimed", Verdict.FOUND),
            ("usernameUnclaimed" if mg else "username_unclaimed", Verdict.NOT_FOUND),
        ]:
            value = string(data, key)
            if value:
                controls.append(Control(value, expected))
        tags = strings(data.get("tags"))
        category = tags[0] if tags else "misc"
        disabled = boolean(data, "disabled") if mg else False
        errors = data.get("errors")
        if errors:
            block_markers = tuple(obj(errors))
        if mg and string(data, "protocol", "https") not in ("http", "https"):
            raise ValueError("UNSUPPORTED: non-HTTP protocol")
        if mg and string(data, "type", "username") != "username":
            raise ValueError("UNSUPPORTED: identifier is not a username")
    # Imported historical markers have no verified profile binding. They cannot emit FOUND.
    spec = DetectionSpec(positive, negative, block_markers=block_markers)
    definition = SiteDefinition(
        sid,
        name,
        profile,
        spec,
        probe_url=probe,
        category=category,
        tags=tags,
        method=method,
        headers=headers,
        query=query,
        json_body=payload,
        form_body=form,
        identifier=identifier,
        redirects=RedirectPolicy(follow),
        disabled=disabled,
        disabled_reason="Disabled in donor snapshot" if disabled else "",
        controls=tuple(controls),
        provenance=Provenance(donor, name, revision, tuple(notes)),
    )
    return definition, notes


def import_data(donor: str, raw: JSONValue, *, revision: str = "") -> ImportBatch:
    if donor not in ("maigret", "sherlock", "whatsmyname"):
        raise ValueError("Unknown donor")
    root = obj(raw)
    engines = obj(root.get("engines", {})) if donor == "maigret" else {}
    items: list[tuple[str, JSONValue]]
    if donor == "whatsmyname":
        values = root.get("sites")
        if not isinstance(values, list):
            raise ValueError("sites must be array")
        items = [
            (str(v.get("name", f"invalid-{i}")) if isinstance(v, dict) else f"invalid-{i}", v)
            for i, v in enumerate(values)
        ]
    else:
        items = [
            (k, v)
            for k, v in (obj(root.get("sites")) if donor == "maigret" else root).items()
            if not k.startswith("$")
        ]
    mapped = {
        "maigret": MAPPED_MG | {"protocol", "type"},
        "sherlock": MAPPED_SH,
        "whatsmyname": MAPPED_WM,
    }[donor]
    metadata = {"maigret": METADATA_MG, "sherlock": METADATA_SH, "whatsmyname": METADATA_WM}[donor]
    records: list[ImportRecord] = []
    seen: set[str] = set()
    for name, value in items:
        site: SiteDefinition | None = None
        notes: list[str] = []
        field_map: tuple[tuple[str, str], ...] = ()
        outcome = "IMPORTED"
        try:
            data = obj(value)
            if donor == "maigret":
                data, merge_notes = merge_engine(data, engines)
                notes.extend(merge_notes)
            field_map = tuple(
                (k, "MAPPED" if k in mapped else "METADATA" if k in metadata else "UNSUPPORTED")
                for k in sorted(data)
            )
            unknown = [k for k, kind in field_map if kind == "UNSUPPORTED"]
            if unknown:
                notes.append("UNSUPPORTED_FIELDS:" + ",".join(unknown))
                outcome = "UNSUPPORTED"
            if any(n.startswith("AMBIGUOUS_ENGINE_MERGE") for n in notes):
                outcome = "UNSUPPORTED"
            site, conversion_notes = _convert(donor, name, data, revision)
            notes.extend(conversion_notes)
            issues = SiteDefinitionValidator().validate(site)
            if issues:
                notes.extend(f"INVALID:{i.path}:{i.message}" for i in issues)
                outcome = "INVALID"
            if name in seen:
                outcome = "INVALID"
                notes.append("DUPLICATE_SOURCE_NAME")
            seen.add(name)
            site = replace(site, provenance=replace(site.provenance, warnings=tuple(notes)))
        except (ValueError, TypeError, KeyError) as exc:
            notes.append(str(exc))
            outcome = "UNSUPPORTED" if "UNSUPPORTED" in str(exc) else "INVALID"
        records.append(
            ImportRecord(
                donor,
                name,
                outcome,
                site,
                tuple(notes),
                field_map,
                json.dumps(value, ensure_ascii=False, sort_keys=True),
            )
        )
    return ImportBatch(donor, revision, tuple(records))


def import_file(donor: str, path: Path) -> ImportBatch:
    data = path.read_bytes()
    return import_data(
        donor, parse_json(data.decode("utf-8-sig")), revision=hashlib.sha256(data).hexdigest()
    )


def find_conflicts(sites: tuple[SiteDefinition, ...]) -> tuple[DefinitionConflict, ...]:
    groups: dict[str, list[SiteDefinition]] = defaultdict(list)
    for site in sites:
        host = (urlsplit(site.profile_url).hostname or "").lower().removeprefix("www.")
        name = re.sub(r"[^\w]", "", site.name.casefold())
        groups[f"name:{name}"].append(site)
        groups[
            f"template:{host}:{urlsplit(site.profile_url).path}?{urlsplit(site.profile_url).query}"
        ].append(site)
    result: list[DefinitionConflict] = []
    seen: set[tuple[str, ...]] = set()
    for key, group in sorted(groups.items()):
        ids = tuple(sorted(s.id for s in group))
        if len(group) < 2 or ids in seen:
            continue
        seen.add(ids)
        differences = tuple(
            f.name
            for f in fields(SiteDefinition)
            if f.name not in {"id", "provenance"}
            and len({to_json(getattr(s, f.name)) for s in group}) > 1
        )
        result.append(
            DefinitionConflict(key, ids, tuple(s.provenance.donor for s in group), differences)
        )
    return tuple(result)
