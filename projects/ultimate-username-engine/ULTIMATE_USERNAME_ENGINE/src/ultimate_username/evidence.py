"""Explainable signals: ordinal weights express support, never probabilities.

Correlated URL/title/OG reflections are not summed into a FOUND threshold.
Only adapter contracts or explicit content + owner binding can prove a profile.
"""

from __future__ import annotations

import re
from urllib.parse import unquote, urlsplit

from ultimate_username.domain.models import (
    DetectionResult,
    EvidenceSignal,
    RequestPlan,
    TransportResponse,
)
from ultimate_username.profile_adapters import same_profile
from ultimate_username.response_quality import PageSignals, ResponseQuality


def extract_signals(
    response: TransportResponse,
    text: str,
    plan: RequestPlan,
    quality: ResponseQuality,
    result: DetectionResult,
) -> tuple[EvidenceSignal, ...]:
    signals: list[EvidenceSignal] = []
    source = response.final_url or response.requested_url
    username = plan.username.site_specific

    def add(
        kind: str,
        value: str,
        locator: str,
        group: str = "page-reflection",
        weight: int = 1,
        strength: str = "WEAK",
        complete: bool = True,
    ) -> None:
        signals.append(
            EvidenceSignal(kind, source, strength, weight, group, value[:512], locator, complete)
        )

    def matched(value: str) -> bool:
        return bool(
            re.search(r"(?<![\w.-])" + re.escape(username) + r"(?![\w.-])", unquote(value), re.I)
        )

    for kind, url in (
        ("URL_USERNAME_MATCH", plan.profile_url),
        ("FINAL_URL_USERNAME_MATCH", source),
    ):
        if matched(urlsplit(url).path):
            add(kind, url, "url", "request-route")
    page = PageSignals(text) if "<" in text[:1000] else None
    if page:
        for canonical in page.canonicals:
            if same_profile(canonical, plan.profile_url):
                add("CANONICAL_USERNAME_MATCH", canonical, "link[rel=canonical]")
        for kind, value, locator in (
            ("PAGE_TITLE_USERNAME_MATCH", page.title, "title"),
            (
                "META_DESCRIPTION_USERNAME_MATCH",
                page.meta.get("description", ""),
                "meta[name=description]",
            ),
            ("OG_TITLE_USERNAME_MATCH", page.meta.get("og:title", ""), "meta[property=og:title]"),
            ("OG_URL_USERNAME_MATCH", page.meta.get("og:url", ""), "meta[property=og:url]"),
        ):
            if matched(value):
                add(kind, value, locator)
    if quality.kind == "PROFILE":
        fields = dict(quality.fields)
        add(
            "EMBEDDED_JSON_USERNAME_MATCH" if quality.locator else "PROFILE_SCHEMA_MATCH",
            quality.reason,
            quality.locator or "reviewed-object",
            "owner-object",
            3,
            "STRONG",
        )
        for name, kind in (
            ("user_id", "PROFILE_ID_PRESENT"),
            ("avatar_url", "PROFILE_AVATAR_PRESENT"),
            ("display_name", "PROFILE_DISPLAY_NAME_PRESENT"),
        ):
            if fields.get(name):
                add(
                    kind,
                    str(fields[name]),
                    quality.locator + "." + name,
                    "owner-object",
                    2,
                    "MODERATE",
                )
    for evidence in result.evidence:
        if evidence.state.value == "TRUE":
            positive = evidence.polarity.value == "SUPPORTS_PRESENT"
            add(
                "DETECTION_RULE_MATCH",
                evidence.observed,
                evidence.rule_id,
                "declared-rule",
                2 if positive else -2,
                "MODERATE",
                evidence.complete,
            )
    for hop in response.history:
        add(
            "REDIRECT_HOP",
            f"{hop.status} {hop.url} -> {hop.location}",
            "response.history",
            "request-route",
            0,
        )
    if response.history:
        initial = response.history[0].url
        if same_profile(source, plan.profile_url):
            add("REDIRECT_TO_CANONICAL_PROFILE", source, "response.final_url", "request-route")
        if urlsplit(initial).netloc != urlsplit(source).netloc:
            add("REDIRECT_HOST_CHANGED", source, "response.final_url", "request-route", 0)
    classes = {
        "CHALLENGE": "CHALLENGE_MARKER",
        "LOGIN_REQUIRED": "LOGIN_PAGE_MARKER",
        "GENERIC_PAGE": "KNOWN_GENERIC_PAGE_MARKER",
        "DISCOVERY_ONLY": "SEARCH_PAGE_MARKER",
        "NOT_FOUND": "KNOWN_NOT_FOUND_MARKER",
        "WRONG_USER": "OWNER_MISMATCH",
        "REDIRECT_ONLY": "REDIRECT_TO_GENERIC_PAGE",
    }
    if result.response_class in classes:
        add(
            classes[result.response_class],
            ";".join(result.reasons),
            "response-classifier",
            "obstruction",
            -3,
            "STRONG",
        )
    if response.error or not response.body_complete:
        add(
            "PARTIAL_RESPONSE",
            response.error.code.value if response.error else "INCOMPLETE",
            "transport",
            "transport",
            -1,
            "STRONG",
            False,
        )
    if quality.partial_verified:
        add("COMPLETE_EVIDENCE_UNIT", quality.locator, "closed-script", "owner-object", 3, "STRONG")
    return tuple(signals)
