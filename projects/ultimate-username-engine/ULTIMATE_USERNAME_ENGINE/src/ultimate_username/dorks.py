"""Search-engine dork queries (text only) and Wayback CDX lookups for profile URLs.

Both are opt-in (``--dorks``, ``--wayback``). Dorks are never sent anywhere: the engine only lists
the query strings for a human to open. Wayback requests go through the engine's transport and have
their own budget, separate from the search request budget.
Port of the OSINT engine's ``dorks.py``.
"""

from __future__ import annotations

import asyncio
import json
import re
from collections.abc import Iterable
from dataclasses import dataclass
from urllib.parse import urlencode, urlsplit

from ultimate_username.domain.models import (
    JSONValue,
    SearchResult,
    TimeoutProfile,
    TransportRequest,
    Verdict,
)
from ultimate_username.transport import Transport

# Services where the username most often appears in the profile URL (for site: dorks)
SOCIAL_DOMAINS = (
    "facebook.com", "instagram.com", "x.com", "twitter.com", "tiktok.com", "youtube.com",
    "linkedin.com", "reddit.com", "github.com", "pinterest.com", "twitch.tv", "medium.com",
    "threads.com", "threads.net", "t.me", "wykop.pl", "filmweb.pl", "olx.pl", "allegro.pl",
)  # fmt: skip

CDX_URL = "https://web.archive.org/cdx/search/cdx"
CDX_TIMEOUT = TimeoutProfile(connect=5.0, read=20.0, total=30.0)


def _or_group(prefix: str, values: Iterable[str]) -> str:
    return "(" + " OR ".join(f"{prefix}{v}" for v in values) + ")"


def build_queries(
    names: list[str], domains: tuple[str, ...] = SOCIAL_DOMAINS, chunk: int = 9
) -> list[str]:
    """Exact name (and variants) in quotes + ``site:`` groups of ``chunk`` domains (long queries
    get truncated by engines) + an ``inurl:`` form for profile paths."""
    if not names:
        return []
    phrase = _or_group("", [f'"{n}"' for n in names]) if len(names) > 1 else f'"{names[0]}"'
    queries = [phrase]
    for i in range(0, len(domains), chunk):
        queries.append(f"{phrase} {_or_group('site:', domains[i : i + chunk])}")
    queries.append(_or_group("inurl:", names) + " -site:pinterest.com")
    return queries


def cdx_query_url(profile_url: str, limit: int = 5) -> str:
    """CDX query: only status-200 captures, collapsed by content digest."""
    parts = urlsplit(profile_url)
    target = parts.netloc + parts.path
    if parts.query:
        target += "?" + parts.query
    params = {
        "url": target,
        "output": "json",
        "fl": "timestamp,original,statuscode",
        "filter": "statuscode:200",
        "collapse": "digest",
        "limit": str(limit),
    }
    return CDX_URL + "?" + urlencode(params)


@dataclass(frozen=True, slots=True)
class Snapshot:
    timestamp: str  # YYYYMMDDhhmmss
    original: str
    status: str = ""

    @property
    def date(self) -> str:
        t = self.timestamp
        return f"{t[0:4]}-{t[4:6]}-{t[6:8]}" if len(t) >= 8 else t

    @property
    def archive_url(self) -> str:
        return f"https://web.archive.org/web/{self.timestamp}/{self.original}"


_CDX_TIMESTAMP = re.compile(r"\d{14}")
_CDX_MAX_FIELD = 2000


def parse_cdx(text: str) -> list[Snapshot]:
    """CDX JSON: a header row of strings, then data rows. Empty body = no captures.
    Any schema violation (bad JSON, types, timestamp not 14 digits, short row) raises ValueError:
    that is an archive error, not "no captures"."""
    text = text.strip()
    if not text:
        return []
    rows = json.loads(text)
    if not isinstance(rows, list):
        raise ValueError("CDX: expected a list")
    if not rows:
        return []
    header = rows[0]
    if not isinstance(header, list) or not all(isinstance(h, str) for h in header):
        raise ValueError("CDX: header is not a list of strings")
    try:
        ti, oi = header.index("timestamp"), header.index("original")
    except ValueError as e:
        raise ValueError(f"CDX: missing columns in header {header[:8]}") from e
    si = header.index("statuscode") if "statuscode" in header else None
    out = []
    for r in rows[1:]:
        if not isinstance(r, list) or len(r) < len(header):
            raise ValueError("CDX: row is not a list matching the header")
        ts, original = r[ti], r[oi]
        if not isinstance(ts, str) or not _CDX_TIMESTAMP.fullmatch(ts):
            raise ValueError("CDX: timestamp must have 14 digits")
        if not isinstance(original, str) or not original or len(original) > _CDX_MAX_FIELD:
            raise ValueError("CDX: invalid original field")
        status = r[si] if si is not None else ""
        out.append(Snapshot(ts, original, status if isinstance(status, str) else ""))
    return out


def wayback_targets(results: Iterable[SearchResult], include_unknown: bool = False) -> list[str]:
    """Profile URLs worth an archive lookup: confirmed hits (FOUND/PROBABLE) and, on request,
    UNKNOWN ones (the profile may exist but could not be confirmed). Only http(s), de-duplicated."""
    wanted = {Verdict.FOUND, Verdict.PROBABLE} | ({Verdict.UNKNOWN} if include_unknown else set())
    urls: list[str] = []
    for result in results:
        if not result.attempts or result.detection.verdict not in wanted:
            continue
        url = result.profile_url
        if urlsplit(url).scheme in ("http", "https") and url not in urls:
            urls.append(url)
    return urls


def _profile_entry(url: str, snapshots: list[Snapshot]) -> dict[str, JSONValue]:
    ordered = sorted(snapshots, key=lambda s: s.timestamp)
    return {
        "profile_url": url,
        "snapshots": [
            {"timestamp": s.timestamp, "original": s.original, "status": s.status} for s in ordered
        ],
        "first_seen": ordered[0].date if ordered else None,
        "last_seen": ordered[-1].date if ordered else None,
    }


def _error_entry(url: str, message: str) -> dict[str, JSONValue]:
    return {**_profile_entry(url, []), "error": message}


async def _lookup(transport: Transport, url: str) -> dict[str, JSONValue]:
    query = cdx_query_url(url)
    try:
        response = await transport.send(TransportRequest(query, timeout=CDX_TIMEOUT))
    except (OSError, RuntimeError, TimeoutError) as exc:
        return _error_entry(url, f"transport error: {type(exc).__name__}")
    if response.error is not None:
        return _error_entry(url, f"transport error: {response.error.code.value}")
    if response.status is None:
        return _error_entry(url, "no response")
    if response.status != 200:
        return _error_entry(url, f"HTTP {response.status}")
    try:
        snapshots = parse_cdx(response.body.decode("utf-8", errors="replace"))
    except ValueError as exc:
        return _error_entry(url, f"invalid CDX response: {str(exc)[:80]}")
    return _profile_entry(url, snapshots)


async def check_wayback(
    transport: Transport, urls: Iterable[str], budget: int, *, concurrency: int = 2
) -> dict[str, JSONValue]:
    """Look up each profile URL in the Wayback CDX; at most ``budget`` requests (hard cap).

    Returns ``{budget, requests, skipped_over_budget, errors, profiles:[{profile_url, snapshots,
    first_seen, last_seen[, error]}]}``. A failed lookup carries ``error`` and is never reported
    as "no captures"."""
    unique = list(dict.fromkeys(urls))
    chosen = unique[: max(0, budget)]
    gate = asyncio.Semaphore(max(1, concurrency))

    async def one(url: str) -> dict[str, JSONValue]:
        async with gate:
            return await _lookup(transport, url)

    entries = await asyncio.gather(*(one(u) for u in chosen))
    profiles: list[JSONValue] = [*entries]
    return {
        "budget": max(0, budget),
        "requests": len(chosen),
        "skipped_over_budget": len(unique) - len(chosen),
        "errors": sum("error" in e for e in entries),
        "profiles": profiles,
    }
