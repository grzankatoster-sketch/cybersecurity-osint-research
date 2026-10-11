"""Small analyst records and a measured funnel; full results remain in the journal."""

from __future__ import annotations

import json
from collections import Counter
from collections.abc import Iterable

from ultimate_username.domain.codec import to_value
from ultimate_username.domain.models import (
    JSONValue,
    Polarity,
    PredicateState,
    SearchResult,
    Verdict,
)
from ultimate_username.field_model import FieldGroup, field_spec
from ultimate_username.registry import SiteRegistry
from ultimate_username.selection import SelectionPlan


def useful_fields(result: SearchResult) -> dict[str, JSONValue]:
    return {
        f.name: to_value(f.value)
        for f in result.profile_metadata.fields + result.profile_metadata.extra_fields
        if field_spec(f.name).group != FieldGroup.TECHNICAL
        and f.name not in result.profile_metadata.conflicts
    }


def field_sources(result: SearchResult) -> dict[str, JSONValue]:
    """Where each shown profile field came from (page, extractor, locator, quality)."""
    shown = set(useful_fields(result))
    sources: dict[str, JSONValue] = {}
    for f in result.profile_metadata.fields + result.profile_metadata.extra_fields:
        if f.name in shown:
            sources[
                {"user_id": "account_id", "external_links": "external_urls"}.get(f.name, f.name)
            ] = {
                "source_url": f.source_url,
                "extractor": f.extractor,
                "locator": f.evidence,
                "quality": f.quality.value,
            }
    return sources


def matched_rules(result: SearchResult) -> list[JSONValue]:
    """Rules that fired (TRUE evidence) without the control record, which has its own key."""
    return [
        {
            "rule_id": e.rule_id,
            "strategy": e.strategy,
            "polarity": e.polarity.value,
            "locator": e.locator,
            "observed": e.observed[:300],
        }
        for e in result.detection.evidence
        if e.state == PredicateState.TRUE and e.rule_id != "control"
    ]


def control_record(result: SearchResult) -> JSONValue:
    """The control-request record (kind, statuses, diffs, control name) or None."""
    for e in result.detection.evidence:
        if e.rule_id == "control" and e.state == PredicateState.TRUE:
            try:
                parsed = json.loads(e.observed)
            except ValueError:
                return {"kind": e.locator}
            return parsed if isinstance(parsed, dict) else {"kind": e.locator}
    return None


def analyst_record(result: SearchResult, registry: SiteRegistry) -> dict[str, JSONValue]:
    entry = registry.get(result.site_id)
    site = entry.definition if entry else None
    tested = bool(result.attempts)
    state = result.detection.state.value
    status = result.detection.verdict.value if state == "OK" else state
    if not tested:
        status = "NOT_TESTED"
    elif result.source_kind == "INDEX_EVIDENCE" and state == "OK":
        status = "DISCOVERY_ONLY"
    groups: dict[str, JSONValue] = {}
    observed = useful_fields(result)
    for name in result.profile_metadata.coverage.null_fields:
        if field_spec(name).group != FieldGroup.TECHNICAL and name not in observed:
            observed[name] = None
    for name, value in observed.items():
        group = field_spec(name).group.value
        bucket = groups.setdefault(group, {})
        if isinstance(bucket, dict):
            bucket[{"user_id": "account_id", "external_links": "external_urls"}.get(name, name)] = (
                value
            )
    evidence: list[JSONValue] = list(result.detection.reasons)
    if any(
        e.strategy == "github_profile" and e.state == PredicateState.TRUE
        for e in result.detection.evidence
    ):
        evidence = ["Structured GitHub profile: username, account ID and profile URL matched"]
    elif any(
        e.strategy == "dev_profile" and e.state == PredicateState.TRUE
        for e in result.detection.evidence
    ):
        evidence = [
            "Structured DEV user: requested username, public user type and account ID matched"
        ]
    return {
        "site": site.name if site else result.site_id,
        "status": status,
        "tested": tested,
        "source": "fallback"
        if result.primary_definition and result.site_id != result.primary_definition
        else "primary",
        "source_kind": result.source_kind,
        "response_class": result.detection.response_class,
        "evidence_level": result.detection.evidence_level,
        "detector": result.detection.detector,
        "signals": to_value(result.detection.signals),
        "requested_url": result.probe_url,
        "final_url": result.final_url,
        "http_status": next(
            (a.status for a in reversed(result.attempts) if a.budget_reason != "CONTROL_CHECK"),
            None,
        ),
        "redirect_chain": to_value(result.redirects),
        "request_count": len(result.attempts) + len(result.enrichment_attempts),
        "received_body_bytes": sum(
            a.received_bytes for a in result.attempts + result.enrichment_attempts
        ),
        "retained_body_bytes": sum(
            a.retained_bytes for a in result.attempts + result.enrichment_attempts
        ),
        "request_seconds": sum(
            a.timing.elapsed for a in result.attempts + result.enrichment_attempts
        ),
        "username": useful_fields(result).get("username", result.username.raw),
        "profile_url": useful_fields(result).get("profile_url", result.profile_url),
        "metadata_state": result.profile_metadata.state.value,
        "useful_metadata": groups,
        "field_sources": field_sources(result),
        "evidence": matched_rules(result),
        "control": control_record(result),
        "confidence": {
            "strength": result.detection.confidence.strength,
            "probability": result.detection.confidence.value,
        },
        "evidence_summary": evidence,
        "issues": list(
            dict.fromkeys(
                [e.code.value for e in result.detection.errors]
                + (["METADATA_CONFLICT:" + f for f in result.profile_metadata.conflicts])
                + (list(result.profile_metadata.diagnostics) if not useful_fields(result) else [])
            )
        ),
    }


def analyst_document(
    results: Iterable[SearchResult],
    registry: SiteRegistry,
    *,
    username: str,
    selection: SelectionPlan | None = None,
    only_matches: bool = False,
) -> dict[str, JSONValue]:
    counts: Counter[str] = Counter()
    reasons: Counter[str] = Counter()
    profiles: list[JSONValue] = []
    for result in results:
        counts["emitted"] += 1
        counts["execution_" + result.detection.state.value.lower()] += 1
        counts["tested" if result.attempts else "not_tested"] += 1
        counts["request_attempts"] += len(result.attempts)
        counts["enrichment_request_attempts"] += len(result.enrichment_attempts)
        counts["http_responses"] += sum(a.status is not None for a in result.attempts)
        counts["positive_evidence"] += any(
            e.polarity == Polarity.PRESENT and e.state == PredicateState.TRUE
            for e in result.detection.evidence
        )
        if result.attempts:
            counts[result.detection.verdict.value.lower()] += 1
            counts["state_" + result.detection.state.value.lower()] += 1
        else:
            reasons[result.detection.state.value] += 1
        fields = useful_fields(result)
        counts["profiles_with_metadata"] += bool(fields)
        counts["useful_metadata_fields"] += len(fields)
        matched = result.detection.verdict in (Verdict.FOUND, Verdict.PROBABLE)
        # Thousands of NOT_TESTED placeholders are represented by aggregate reasons.
        if result.attempts and (matched or not only_matches):
            profiles.append(analyst_record(result, registry))
    for key in (
        "emitted",
        "tested",
        "not_tested",
        "request_attempts",
        "http_responses",
        "found",
        "probable",
        "not_found",
        "unknown",
        "positive_evidence",
        "profiles_with_metadata",
        "useful_metadata_fields",
        "enrichment_request_attempts",
        "state_blocked",
        "state_timeout",
        "state_rate_limited",
        "state_parse_error",
        "state_unsupported",
        "execution_invalid_input",
        "execution_config_error",
        "execution_budget_exhausted",
        "execution_unsupported",
    ):
        counts.setdefault(key, 0)
    selected_ids = set(selection.selected) if selection else set()
    excluded = (
        Counter(reason for sid, reason in selection.excluded if sid not in selected_ids)
        if selection
        else Counter()
    )
    return {
        "view": "ANALYST",
        "username": username,
        "profiles": profiles,
        "summary": {
            "registry_definitions": len(registry.entries),
            "canonical_services_in_scope": len(selection.services) if selection else None,
            "enabled_in_scope": selection.enabled if selection else None,
            "valid_enabled_in_scope": selection.valid if selection else None,
            "compatible_in_scope": selection.compatible if selection else None,
            "selected": len(selection.selected) if selection else counts["emitted"],
            "planned": selection.planned if selection else None,
            "no_positive_rule_in_scope": selection.no_positive_rule if selection else None,
            "conflict_groups_in_scope": sum(s.rule_conflict for s in selection.services)
            if selection
            else None,
            "counts": dict(counts),
            "not_tested_reasons": dict(reasons),
            "excluded_before_search": dict(excluded),
            "technical_only_fields_shown": 0,
        },
    }


def render_analyst(document: dict[str, JSONValue]) -> str:
    # JSON keeps control characters escaped; profile-supplied text cannot inject terminal escapes.
    return json.dumps(document, ensure_ascii=False, indent=2, allow_nan=False) + "\n"


def render_console(document: dict[str, JSONValue]) -> str:
    """Profiles first, concise summary last; full values are kept in the analyst JSON."""

    def text(value: JSONValue) -> str:
        rendered = json.dumps(value, ensure_ascii=False)
        return rendered[:1200] + ("..." if len(rendered) > 1200 else "")

    lines: list[str] = []
    profiles = document.get("profiles")
    if isinstance(profiles, list):
        for profile in profiles:
            if not isinstance(profile, dict):
                continue
            lines.append(f"{text(profile.get('site'))} | {text(profile.get('status'))}")
            lines.append("  Profile: " + text(profile.get("profile_url")))
            lines.append("  Username: " + text(profile.get("username")))
            groups = profile.get("useful_metadata")
            if isinstance(groups, dict):
                for group, fields in groups.items():
                    if isinstance(fields, dict):
                        populated = [(k, v) for k, v in fields.items() if v is not None]
                        if populated:
                            lines.append("  " + group)
                            lines.extend("    " + k + ": " + text(v) for k, v in populated)
            lines.append("  Evidence: " + text(profile.get("evidence_summary")))
            if profile.get("source") == "fallback":
                lines.append("  Source: public fallback endpoint")
            if profile.get("issues"):
                lines.append("  Issues: " + text(profile.get("issues")))
            lines.append("")
    summary = document.get("summary")
    if isinstance(summary, dict):
        lines.append("Summary for " + text(document.get("username")))
        lines.append(
            "  Registry: "
            + text(summary.get("registry_definitions"))
            + " | Canonical services in scope: "
            + text(summary.get("canonical_services_in_scope"))
            + " | Selected: "
            + text(summary.get("selected"))
        )
        counts = summary.get("counts")
        if isinstance(counts, dict):
            for key in (
                "tested",
                "found",
                "probable",
                "not_found",
                "unknown",
                "state_blocked",
                "state_timeout",
                "state_rate_limited",
                "not_tested",
                "profiles_with_metadata",
                "useful_metadata_fields",
            ):
                lines.append("  " + key + ": " + text(counts.get(key, 0)))
        lines.append("  Not tested reasons: " + text(summary.get("not_tested_reasons")))
        if summary.get("excluded_before_search"):
            lines.append("  Excluded before search: " + text(summary.get("excluded_before_search")))
    request_economy = document.get("request_economy")
    if isinstance(request_economy, dict):
        lines.append("Request economy:")
        lines.extend("  " + k + ": " + text(v) for k, v in request_economy.items())
    return "\n".join(lines) + "\n"
