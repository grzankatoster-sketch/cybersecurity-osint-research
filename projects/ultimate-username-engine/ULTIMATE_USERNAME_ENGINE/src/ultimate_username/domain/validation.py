"""Semantic validation complements strict field/type decoding at the JSON boundary."""

from __future__ import annotations

import math
import re
from collections.abc import Iterator

import regex

from ultimate_username.domain.json_types import parse_json
from ultimate_username.domain.models import HttpMethod, Rule, SiteDefinition, ValidationIssue
from ultimate_username.domain.urls import origin, validate_template

BUILTIN_STRATEGIES = frozenset(
    {
        "status",
        "message",
        "regex",
        "redirect",
        "json",
        "header",
        "all",
        "any",
        "not",
        "github_profile",
        "dev_profile",
    }
)


def walk_rules(rule: Rule, depth: int = 0) -> Iterator[Rule]:
    if depth > 32:
        raise ValueError("Detection tree exceeds depth 32")
    yield rule
    for child in rule.children:
        yield from walk_rules(child, depth + 1)


class SiteDefinitionValidator:
    def __init__(self, strategies: frozenset[str] = BUILTIN_STRATEGIES) -> None:
        self.strategies = strategies

    def validate(self, site: SiteDefinition) -> tuple[ValidationIssue, ...]:
        issues: list[ValidationIssue] = []

        def fail(path: str, message: str) -> None:
            issues.append(ValidationIssue(path, message))

        if not site.id or not site.name:
            fail("id/name", "Required non-empty identity")
        if site.schema_version != 1:
            fail("schema_version", "Unsupported schema version")
        if not isinstance(site.method, HttpMethod):
            fail("method", "Unsupported HTTP method")
        if site.credential_env:
            if not re.fullmatch(r"UEE_CRED_[A-Z0-9_]{1,64}", site.credential_env):
                # Catalogues are untrusted: they may only name dedicated UEE_CRED_* variables,
                # which the operator must still authorise per host (credentials.py).
                fail("credential_env", "Expected a UEE_CRED_* environment variable name")
            if (
                not re.fullmatch(r"[A-Za-z0-9-]+", site.credential_header)
                or site.credential_header.lower() in ("host", "cookie", "content-length")
                or any(c in site.credential_prefix for c in "\r\n")
                or any(k.lower() == site.credential_header.lower() for k, _ in site.headers)
            ):
                fail("credential_header", "Invalid or duplicated credential header")
        for key, template in [("profile_url", site.profile_url), ("probe_url", site.probe_url)]:
            if template is not None:
                try:
                    validate_template(template)
                except (ValueError, UnicodeError) as exc:
                    fail(key, str(exc))
        for key in ("connect", "read", "total", "queue"):
            value = getattr(site.timeout, key)
            if not isinstance(value, (int, float)) or not math.isfinite(value) or value <= 0:
                fail(f"timeout.{key}", "Must be finite and positive")
        retry = site.retry
        if type(retry.max_attempts) is not int or not 1 <= retry.max_attempts <= 100:
            fail("retry.max_attempts", "Expected integer in [1,100]")
        if not all(math.isfinite(n) and n >= 0 for n in (retry.base_delay, retry.max_delay)):
            fail("retry", "Delay must be finite and nonnegative")
        if retry.max_delay < retry.base_delay:
            fail("retry", "max_delay cannot be lower than base_delay")
        if any(s < 500 or s > 599 for s in retry.retry_statuses):
            fail("retry.retry_statuses", "Only selected 5xx; 429 has a separate cooldown policy")
        if site.rate.concurrency < 1 or type(site.rate.concurrency) is not int:
            fail("rate.concurrency", "Expected positive integer")
        if not math.isfinite(site.rate.min_interval) or site.rate.min_interval < 0:
            fail("rate.min_interval", "Expected finite nonnegative interval")
        if not 0 <= site.redirects.max_hops <= 20:
            fail("redirects.max_hops", "Expected [0,20]")
        for allowed in site.redirects.allowed_origins:
            try:
                origin(allowed)
            except (ValueError, UnicodeError) as exc:
                fail("redirects.allowed_origins", str(exc))
        if not 1 <= site.body_limit <= 16 * 1024 * 1024:
            fail("body_limit", "Expected [1,16777216] bytes")
        for key, value in site.headers:
            if not key or any(c in key + value for c in "\r\n"):
                fail("headers", "Empty header name or newline")
        if len({key.casefold() for key, _ in site.headers}) != len(site.headers):
            fail("headers", "Duplicate header names")
        body_count = sum(
            (site.json_body is not None, bool(site.form_body), site.raw_body is not None)
        )
        if body_count > 1:
            fail("body", "Choose exactly one body representation")
        if body_count and site.method in (HttpMethod.GET, HttpMethod.HEAD):
            fail("body", "GET/HEAD bodies are not supported")
        if site.raw_body is not None and "{username}" in site.raw_body:
            fail("raw_body", "Dynamic bodies require typed JSON or form encoding")
        if site.json_body is not None:
            try:
                parse_json(site.json_body)
            except ValueError as exc:
                fail("json_body", str(exc))
        policy = site.identifier
        if not 1 <= policy.max_length <= 4096:
            fail("identifier.max_length", "Expected [1,4096]")
        if policy.unicode_form not in (None, "NFC", "NFD", "NFKC", "NFKD"):
            fail("identifier.unicode_form", "Invalid Unicode normalization")
        if policy.pattern is not None:
            try:
                regex.compile(policy.pattern)
            except regex.error as exc:
                fail("identifier.pattern", str(exc))
        spec = site.detection
        if spec.present is None and spec.absent is None:
            fail("detection", "At least one evidence rule is required")
        if spec.present is not None and spec.present == spec.absent:
            fail("detection", "Identical positive and negative predicates")
        for label, root in [
            ("present", spec.present),
            ("absent", spec.absent),
            ("binding", spec.binding),
        ]:
            if root is None:
                continue
            try:
                rules = tuple(walk_rules(root))
                if len(rules) > 128:
                    fail(f"detection.{label}", "Too many predicates")
                for rule in rules:
                    self._rule(rule, f"detection.{label}", issues)
                    if site.method == HttpMethod.HEAD and rule.strategy in (
                        "message",
                        "regex",
                        "json",
                        "github_profile",
                        "dev_profile",
                    ):
                        fail("method", "HEAD cannot provide body evidence")
            except ValueError as exc:
                fail(f"detection.{label}", str(exc))
        for extraction in site.extractors:
            if extraction.strategy not in ("json", "regex", "discourse", "xenforo", "patreon_rsc"):
                fail("extractors", "Unknown extractor")
            if extraction.strategy == "regex":
                try:
                    compiled = regex.compile(extraction.pattern)
                    if not 0 <= extraction.group <= compiled.groups:
                        fail("extractors.group", "Regex does not define the requested capture")
                except regex.error as exc:
                    fail("extractors.pattern", str(exc))
        if len(site.enrichment_urls) > 1:
            fail("enrichment_urls", "At most one public follow-up endpoint per profile")
        for url in site.enrichment_urls:
            try:
                validate_template(url)
                if origin(url) != origin(site.profile_url):
                    fail("enrichment_urls", "Follow-up endpoint must share the profile origin")
            except ValueError as exc:
                fail("enrichment_urls", str(exc))
        return tuple(issues)

    def _rule(self, rule: Rule, path: str, issues: list[ValidationIssue]) -> None:
        def fail(message: str) -> None:
            issues.append(ValidationIssue(path, message))

        if rule.strategy not in self.strategies:
            fail(f"Unknown strategy: {rule.strategy}")
        if rule.strategy in ("all", "any") and not rule.children:
            fail("Empty composite")
        if rule.strategy == "not" and len(rule.children) != 1:
            fail("not requires one child")
        if rule.strategy not in ("all", "any", "not") and rule.children:
            fail("Leaf rule cannot have children")
        if rule.strategy in ("message", "regex", "redirect", "header") and not rule.value:
            fail("Empty predicate is not evidence")
        if rule.strategy == "status" and (
            not rule.statuses
            or any(type(s) is not int or not 100 <= s <= 599 for s in rule.statuses)
        ):
            fail("Invalid status set")
        if rule.strategy == "regex":
            try:
                compiled = regex.compile(rule.value)
                if rule.group is not None and rule.group not in compiled.groupindex:
                    fail("Missing named regex group")
            except regex.error as exc:
                fail(str(exc))
        if rule.strategy == "json":
            if not rule.path:
                fail("JSON predicate requires a path")
            if rule.value != "{username}":
                try:
                    parse_json(rule.value)
                except ValueError:
                    fail("JSON expected value must be JSON or {username}")
