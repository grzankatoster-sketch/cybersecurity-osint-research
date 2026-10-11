"""Ocena jakosci zrodla i pewnosci obserwacji.

Pewnosc obserwacji = min(jakosc zrodla, pewnosc zadeklarowana w rekordzie), a jakosc zrodla =
min(baza z typu zrodla, `reliability` zadeklarowane przez uzytkownika).
"""

from __future__ import annotations

from urllib.parse import urlsplit

from .models import Confidence, IncidentStatus, Source, SourceType

_ORDER = {Confidence.LOW: 0, Confidence.MEDIUM: 1, Confidence.HIGH: 2}

_BASE: dict[SourceType, Confidence] = {
    SourceType.OFFICIAL_REGISTRY: Confidence.HIGH,
    SourceType.COMPANY_WEBSITE: Confidence.HIGH,
    SourceType.OFFICIAL_DOCUMENT: Confidence.MEDIUM,  # HIGH tylko dla hostow urzedowych (ponizej)
    SourceType.CERT_ADVISORY: Confidence.HIGH,
    SourceType.HIBP_CATALOG: Confidence.MEDIUM,
    SourceType.CT_LOG: Confidence.MEDIUM,
    SourceType.PASSIVE_DNS: Confidence.LOW,
    SourceType.MANUAL: Confidence.LOW,
}
_OFFICIAL_HOST_SUFFIXES = ("gov.pl", "nask.pl", "cert.pl", "ms.gov.pl", "europa.eu")


def min_confidence(*items: Confidence) -> Confidence:
    return min(items, key=_ORDER.__getitem__)


def max_confidence(*items: Confidence) -> Confidence:
    return max(items, key=_ORDER.__getitem__)


def base_confidence(source_type: SourceType, url: str = "") -> Confidence:
    base = _BASE[source_type]
    if source_type is SourceType.OFFICIAL_DOCUMENT:
        host = (urlsplit(url).hostname or "").lower()
        if any(host == s or host.endswith("." + s) for s in _OFFICIAL_HOST_SUFFIXES):
            return Confidence.HIGH
    return base


def source_quality(source: Source) -> Confidence:
    return min_confidence(base_confidence(source.source_type, source.url), source.reliability)


def observation_confidence(
    source: Source,
    declared: Confidence | None = None,
    incident_status: list[IncidentStatus] | None = None,
) -> Confidence:
    """`incident_status` podajemy tylko dla obserwacji incydentu.

    fabricated / spam_list -> low. W katalogu HIBP brak flagi verified -> low (incydent niepotwierdzony)."""
    conf = source_quality(source)
    if incident_status is not None:
        flagged = IncidentStatus.FABRICATED in incident_status or IncidentStatus.SPAM_LIST in incident_status
        unverified_hibp = (
            source.source_type is SourceType.HIBP_CATALOG and IncidentStatus.VERIFIED not in incident_status
        )
        if flagged or unverified_hibp:
            conf = Confidence.LOW
    if declared is not None:
        conf = min_confidence(conf, declared)
    return conf
