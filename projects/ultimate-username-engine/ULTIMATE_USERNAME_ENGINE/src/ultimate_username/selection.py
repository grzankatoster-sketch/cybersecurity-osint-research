"""Conservative service grouping and explainable static definition quality.

No hostname-only merges, no popularity score and no invented live health history.
Alternative definitions remain inspectable; access denial never triggers fallback.
"""

from __future__ import annotations

from collections import defaultdict
from collections.abc import Iterable
from dataclasses import dataclass, replace
from urllib.parse import urlsplit

from ultimate_username.domain.models import DetectionSpec, RegistryEntry, Rule, SiteDefinition
from ultimate_username.domain.validation import walk_rules
from ultimate_username.planning import plan_request
from ultimate_username.registry import SiteRegistry


@dataclass(frozen=True, slots=True)
class SiteQualityScore:
    value: int
    reasons: tuple[str, ...]
    historical_failure_rate: float | None = None
    last_live_validation: str | None = None


@dataclass(frozen=True, slots=True)
class CanonicalService:
    key: str
    primary: str
    alternatives: tuple[str, ...]
    quality: SiteQualityScore
    rule_conflict: bool


@dataclass(frozen=True, slots=True)
class SelectionPlan:
    registry_entries: int
    enabled: int
    valid: int
    compatible: int
    selected: tuple[str, ...]
    services: tuple[CanonicalService, ...]
    excluded: tuple[tuple[str, str], ...]
    quality_order: tuple[tuple[str, SiteQualityScore], ...]
    planned: int
    no_positive_rule: int


def service_key(site: SiteDefinition) -> str:
    url = urlsplit(site.profile_url)
    # www is a reviewed alias only for GitHub; other subdomains can be distinct services.
    host = url.netloc.lower()
    if host == "www.github.com":
        host = "github.com"
    return host + url.path.rstrip("/") + ("?" + url.query if url.query else "")


def quality(entry: RegistryEntry) -> SiteQualityScore:
    site = entry.definition
    if site is None or entry.issues or site.disabled:
        return SiteQualityScore(-100, ("INVALID_OR_DISABLED",))
    points = 10
    reasons = ["VALID_DEFINITION:+10"]
    for rule, label, amount in (
        (site.detection.present, "POSITIVE_RULE", 10),
        (site.detection.absent, "NEGATIVE_RULE", 10),
        (site.detection.binding, "OWNER_BINDING", 30),
    ):
        if rule:
            points += amount
            reasons.append(f"{label}:+{amount}")
    if site.detection.present and any(
        r.strategy in ("json", "message", "regex", "github_profile", "dev_profile")
        for r in walk_rules(site.detection.present)
    ):
        points += 15
        reasons.append("CONTENT_EVIDENCE:+15")
    if site.extractors or (
        site.detection.present
        and site.detection.present.strategy in ("github_profile", "dev_profile")
    ):
        points += 15
        reasons.append("DECLARED_EXTRACTION_OR_REVIEWED_ADAPTER:+15")
    return SiteQualityScore(points, tuple(reasons))


def prepared_registry(registry: SiteRegistry) -> SiteRegistry:
    """Versioned, narrow runtime overlays; the donor catalog is not rewritten."""
    entries: list[RegistryEntry | SiteDefinition] = []
    for entry in registry.entries:
        site = entry.definition
        if site is None or entry.issues:
            entries.append(entry)
            continue
        if (
            site.probe_url == "https://api.github.com/users/{username}"
            and service_key(site) == "github.com/{username}"
            and "runtime-quality-v1:github-bound-json" not in site.provenance.warnings
        ):
            spec = DetectionSpec(
                present=Rule("github_profile"),
                absent=Rule(
                    "all",
                    children=(
                        Rule("status", statuses=(404,)),
                        Rule("json", value='"Not Found"', path=("message",)),
                    ),
                ),
                binding=Rule("github_profile"),
            )
            site = replace(
                site,
                detection=spec,
                provenance=replace(
                    site.provenance,
                    warnings=site.provenance.warnings + ("runtime-quality-v1:github-bound-json",),
                ),
            )
        if (
            site.probe_url == "https://dev.to/api/users/by_username?url={username}"
            and service_key(site) == "dev.to/{username}"
            and "runtime-quality-v1:dev-bound-json" not in site.provenance.warnings
        ):
            site = replace(
                site,
                detection=DetectionSpec(
                    present=Rule("dev_profile"),
                    binding=Rule("dev_profile"),
                    absent=Rule("status", statuses=(404,)),
                ),
                provenance=replace(
                    site.provenance,
                    warnings=site.provenance.warnings + ("runtime-quality-v1:dev-bound-json",),
                ),
            )
        roots = (site.detection.absent,) if site.detection.absent else ()
        if any("Twitch is the world" in rule.value for root in roots for rule in walk_rules(root)):
            site = replace(
                site,
                disabled=True,
                disabled_reason="QUARANTINE: generic Twitch description is not absence evidence",
            )
        host = urlsplit(site.profile_url).hostname or ""
        if host in ("f3.cool", "www.authorstream.com"):
            site = replace(
                site,
                disabled=True,
                disabled_reason=(
                    "QUARANTINE: reviewed parked-domain /lander shell; detection-quality-v1"
                ),
            )
        needs_fix = {
            "forum.moonbeam.network",
            "www.engadget.com",
            "www.hozpitality.com",
            "www.mcbans.com",
            "www.mercadolivre.com.br",
            "www.shelf.im",
            "dating.rambler.ru",
        }
        warning = "detection-quality-v1:NEEDS_RULE_FIX:reviewed non-profile response"
        repaired = host in {
            "www.shelf.im",
            "dating.rambler.ru",
            "www.engadget.com",
            "www.mcbans.com",
        }
        if repaired:
            warnings = tuple(w for w in site.provenance.warnings if w != warning)
            marker = "recall-v2:reviewed-owner-adapter"
            if marker not in warnings:
                warnings += (marker,)
            if (
                host == "www.mcbans.com"
                and site.probe_url != "https://www.mcbans.com/api/players/{username}"
            ):
                warnings += (
                    "recall-v2:ORIGINAL_PROBE_URL:" + (site.probe_url or site.profile_url),
                )
                site = replace(
                    site,
                    probe_url="https://www.mcbans.com/api/players/{username}",
                    detection=DetectionSpec(
                        present=Rule("status", statuses=(200,)),
                        absent=Rule(
                            "all",
                            children=(
                                Rule("status", statuses=(404,)),
                                Rule("json", value='"Player not found!"', path=("error",)),
                            ),
                        ),
                    ),
                )
            if (
                host == "www.engadget.com"
                and site.profile_url != "https://www.engadget.com/author/{username}/"
            ):
                warnings += ("recall-v2:ORIGINAL_PROFILE_URL:" + site.profile_url,)
                site = replace(
                    site, profile_url="https://www.engadget.com/author/{username}/", probe_url=None
                )
            site = replace(site, provenance=replace(site.provenance, warnings=warnings))
        if host in needs_fix and not repaired and warning not in site.provenance.warnings:
            site = replace(
                site,
                provenance=replace(site.provenance, warnings=site.provenance.warnings + (warning,)),
            )
        entries.append(site)
    return SiteRegistry(entries)


def select_services(
    registry: SiteRegistry,
    username: str,
    *,
    ids: Iterable[str] | None = None,
    categories: Iterable[str] | None = None,
    mode: str = "quality",
) -> SelectionPlan:
    if mode not in ("quality", "all"):
        raise ValueError("Unknown selection mode")
    entries = registry.select(ids=ids, categories=categories)
    grouped: dict[str, list[RegistryEntry]] = defaultdict(list)
    excluded: list[tuple[str, str]] = []
    enabled = valid = compatible = 0
    for entry in entries:
        site = entry.definition
        if site is not None and not site.disabled:
            enabled += 1
        if site is None or entry.issues:
            excluded.append((entry.id, "INVALID"))
            continue
        if site.disabled:
            excluded.append(
                (
                    entry.id,
                    "QUARANTINE" if site.disabled_reason.startswith("QUARANTINE") else "DISABLED",
                )
            )
            continue
        valid += 1
        try:
            plan_request(username, site, "selection")
        except ValueError:
            excluded.append((entry.id, "INCOMPATIBLE_USERNAME"))
            continue
        compatible += 1
        grouped[service_key(site)].append(entry)
    services: list[CanonicalService] = []
    for key, variants in grouped.items():
        ordered = sorted(variants, key=lambda e: (-quality(e).value, e.id))
        primary = ordered[0]
        services.append(
            CanonicalService(
                key,
                primary.id,
                tuple(e.id for e in ordered[1:]),
                quality(primary),
                len({repr(e.definition.detection) for e in ordered if e.definition}) > 1,
            )
        )
    services.sort(key=lambda s: (-s.quality.value, s.key))
    if mode == "all" or ids is not None:
        # Explicit IDs are an intentional diagnostic selection: preserve every requested definition.
        selected = tuple(e.id for e in entries)
    else:
        selected = tuple(s.primary for s in services)
        excluded.extend((alt, "ALTERNATIVE_DEFINITION") for s in services for alt in s.alternatives)
    score_map = {e.id: quality(e) for e in entries}
    compatible_ids = {e.id for variants in grouped.values() for e in variants}
    return SelectionPlan(
        len(registry.entries),
        enabled,
        valid,
        compatible,
        selected,
        tuple(services),
        tuple(excluded),
        tuple((sid, score_map[sid]) for sid in selected),
        len(compatible_ids.intersection(selected)),
        sum(e.definition is not None and e.definition.detection.present is None for e in entries),
    )
