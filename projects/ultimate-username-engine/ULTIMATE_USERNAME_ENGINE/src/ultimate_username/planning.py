"""Pure username normalization and request serialization, with no network access."""

from __future__ import annotations

import json
import unicodedata
from dataclasses import replace
from typing import Literal, cast
from urllib.parse import urlencode, urlsplit, urlunsplit

import regex

from ultimate_username.domain.json_types import parse_json
from ultimate_username.domain.models import (
    IdentifierPolicy,
    JSONValue,
    RequestPlan,
    SiteDefinition,
    TransportRequest,
    Username,
)
from ultimate_username.domain.urls import render_url


def normalize(raw: str, policy: IdentifierPolicy | None = None) -> Username:
    policy = policy or IdentifierPolicy()
    if not raw or not raw.strip() or len(raw) > 4096:
        raise ValueError("Username is empty or exceeds global input bound")
    if any(unicodedata.category(char) in ("Cc", "Cs") for char in raw):
        raise ValueError("Username contains a control character or surrogate")
    value = raw
    changes: list[str] = []
    transformations = [
        ("strip_whitespace", raw.strip() if policy.strip_whitespace else value),
    ]
    for name, transformed in transformations:
        if value != transformed:
            value = transformed
            changes.append(name)
    if policy.strip_at and value.startswith("@"):
        value = value[1:]
        changes.append("strip_at")
    if policy.lowercase and value != value.lower():
        value = value.lower()
        changes.append("lowercase")
    if policy.unicode_form is not None:
        if policy.unicode_form not in ("NFC", "NFD", "NFKC", "NFKD"):
            raise ValueError("Invalid Unicode normalization form")
        form = cast(Literal["NFC", "NFD", "NFKC", "NFKD"], policy.unicode_form)
        transformed = unicodedata.normalize(form, value)
        if transformed != value:
            value = transformed
            changes.append(policy.unicode_form)
    if policy.remove_characters:
        transformed = "".join(c for c in value if c not in policy.remove_characters)
        if transformed != value:
            value = transformed
            changes.append("remove_characters")
    if not value or len(value) > policy.max_length:
        raise ValueError("Username violates site length policy")
    if policy.pattern is not None and regex.fullmatch(policy.pattern, value, timeout=0.05) is None:
        raise ValueError("Username violates site syntax")
    return Username(raw, raw, value, tuple(changes))


def interpolate(value: JSONValue, username: str) -> JSONValue:
    if isinstance(value, str):
        return value.replace("{username}", username)
    if isinstance(value, list):
        return [interpolate(item, username) for item in value]
    if isinstance(value, dict):
        return {key: interpolate(item, username) for key, item in value.items()}
    return value


def plan_request(raw: str, site: SiteDefinition, task_id: str) -> RequestPlan:
    username = normalize(raw, site.identifier)
    value = username.site_specific
    profile = render_url(site.profile_url, value)
    probe = render_url(site.probe_url or site.profile_url, value)
    if site.query:
        parts = urlsplit(probe)
        query = urlencode([(k, v.replace("{username}", value)) for k, v in site.query])
        probe = urlunsplit(parts._replace(query="&".join(filter(None, (parts.query, query)))))
    headers = list(site.headers)
    body: bytes | None = None
    content_type: str | None = None
    if site.json_body is not None:
        body = json.dumps(
            interpolate(parse_json(site.json_body), value), ensure_ascii=False
        ).encode()
        content_type = "application/json"
    elif site.form_body:
        body = urlencode([(k, v.replace("{username}", value)) for k, v in site.form_body]).encode()
        content_type = "application/x-www-form-urlencoded"
    elif site.raw_body is not None:
        body = site.raw_body.encode()
    if content_type is not None and not any(k.casefold() == "content-type" for k, _ in headers):
        headers.append(("Content-Type", content_type))
    request = TransportRequest(
        probe, site.method, tuple(headers), body, site.timeout, site.body_limit, site.context_id
    )
    return RequestPlan(task_id, site.id, username, profile, request, site)


def with_remaining_timeout(request: TransportRequest, remaining: float) -> TransportRequest:
    return replace(
        request, timeout=replace(request.timeout, total=min(request.timeout.total, remaining))
    )
