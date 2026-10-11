"""Pure retry and redirect policies; the scheduler owns all waiting."""

from __future__ import annotations

import math
from dataclasses import replace
from datetime import UTC, datetime
from email.utils import parsedate_to_datetime
from urllib.parse import unquote, urljoin, urlsplit

from ultimate_username.domain.models import (
    DetectionResult,
    ErrorCode,
    HttpMethod,
    RequestPlan,
    TransportRequest,
    TransportResponse,
)
from ultimate_username.domain.urls import (
    host_without_www,
    is_public_host,
    origin,
    registrable_domain,
)


def retry_after(value: str | None, *, now: datetime | None = None) -> float | None:
    if value is None:
        return None
    try:
        seconds = float(value)
        return max(0, seconds) if math.isfinite(seconds) else None
    except ValueError:
        try:
            date = parsedate_to_datetime(value)
            if date.tzinfo is None:
                date = date.replace(tzinfo=UTC)
            return max(0, (date - (now or datetime.now(UTC))).total_seconds())
        except (ValueError, TypeError, OverflowError):
            return None


# Transient failures (F3.4): a runtime policy may retry these a few times even when the site
# definition allows a single attempt. Permanent ones (DNS_NOT_FOUND, TLS_ERROR) never qualify.
TRANSIENT_ERRORS = frozenset(
    {
        ErrorCode.DNS_TEMPORARY,
        ErrorCode.CONNECTION_FAILED,
        ErrorCode.CONNECTION_RESET,
        ErrorCode.CONNECT_TIMEOUT,
        ErrorCode.READ_TIMEOUT,
        ErrorCode.ATTEMPT_TIMEOUT,
    }
)
TRANSIENT_STATUSES = (502, 503, 504)


# Retry pacing. A retry must never park until the job deadline: backoff is capped, a server
# asking for a pause beyond RETRY_AFTER_GIVE_UP (seconds, or an HTTP date far ahead) gets no
# retry at all, and a retry that could not start before the deadline is not scheduled.
MAX_RETRY_DELAY = 10.0
RETRY_AFTER_GIVE_UP = 60.0


def retry_wait(
    backoff: float, after: float | None, min_delay: float, remaining: float
) -> float | None:
    """Seconds to wait before a retry, or None when it should not be scheduled."""
    if after is not None and after > RETRY_AFTER_GIVE_UP:
        return None
    delay = max(min(backoff, MAX_RETRY_DELAY), after or 0, min_delay)
    return delay if delay < remaining else None


def is_transient(response: TransportResponse, result: DetectionResult) -> bool:
    if response.status in TRANSIENT_STATUSES:
        return True
    return any(e.code in TRANSIENT_ERRORS and e.retryable for e in result.errors)


def should_retry(
    plan: RequestPlan,
    response: TransportResponse,
    result: DetectionResult,
    attempts: int,
    transient_retries: int = 0,
) -> bool:
    policy = plan.site.retry
    transient = transient_retries > 0 and is_transient(response, result)
    limit = max(policy.max_attempts, 1 + transient_retries) if transient else policy.max_attempts
    if attempts >= limit:
        return False
    if (
        plan.request.method not in (HttpMethod.GET, HttpMethod.HEAD, HttpMethod.PUT)
        and not plan.site.idempotent
    ):
        return False
    if any(
        e.code in {ErrorCode.CHALLENGE, ErrorCode.ACCESS_DENIED, ErrorCode.LOGIN_REQUIRED}
        for e in result.errors
    ):
        return False
    if response.status == 429 or response.status in policy.retry_statuses:
        return True
    if transient and response.status in TRANSIENT_STATUSES:
        return True
    for error in result.errors:
        if error.code in {
            ErrorCode.READ_TIMEOUT,
            ErrorCode.CONNECT_TIMEOUT,
            ErrorCode.ATTEMPT_TIMEOUT,
        }:
            return policy.retry_timeouts
        if error.retryable and error.code in {
            ErrorCode.DNS_TEMPORARY,
            ErrorCode.CONNECTION_FAILED,
            ErrorCode.CONNECTION_RESET,
        }:
            return True
    return False


def _name_in_path(path: str, names: set[str]) -> bool:
    """A name is a path segment, or (3+ characters) a fragment of one; case-insensitive."""
    segments = [s for s in unquote(unquote(path)).lower().split("/") if s]
    return any(n == s or (len(n) >= 3 and n in s) for n in names for s in segments)


def safe_cross_origin(source: str, target: str, plan: RequestPlan) -> bool:
    """Harmless origin changes that need no explicit allowed origin.

    The target must be a public host on a standard port (or the source port) and one of:
    the same host up to a ``www.`` prefix, the same registrable domain, or a path that still
    names the profile (domain aliases, language prefixes). Raises ValueError for a
    non-public target (loopback, private ranges, local names).
    """
    src, dst = urlsplit(source), urlsplit(target)
    src_host = (src.hostname or "").encode("idna").decode("ascii").lower()
    dst_host = (dst.hostname or "").encode("idna").decode("ascii").lower()
    if not is_public_host(dst_host):
        raise ValueError("Redirect to a non-public host rejected")
    if dst.port not in (None, 80, 443, src.port):
        return False
    if host_without_www(src_host) == host_without_www(dst_host):
        return True
    if registrable_domain(src_host) == registrable_domain(dst_host):
        return True
    user = plan.username
    names = {n.lower() for n in (user.raw, user.canonical, user.site_specific) if n}
    return _name_in_path(dst.path, names)


def redirect_request(
    request: TransportRequest, response: TransportResponse, plan: RequestPlan, visited: set[str]
) -> TransportRequest | None:
    if response.status not in (301, 302, 303, 307, 308) or not plan.site.redirects.follow:
        return None
    location = response.header("Location")
    if not location:
        raise ValueError("Redirect missing Location")
    target = urljoin(request.url, location)
    target_origin = origin(target)
    old_origin = origin(request.url)
    if target in visited:
        raise ValueError("Redirect loop")
    if len(visited) > plan.site.redirects.max_hops:
        raise ValueError("Redirect hop budget exhausted")
    if old_origin.startswith("https:") and target_origin.startswith("http:"):
        raise ValueError("HTTPS downgrade redirect")
    if target_origin != old_origin and target_origin not in {
        origin(x) for x in plan.site.redirects.allowed_origins
    }:
        if not safe_cross_origin(request.url, target, plan):
            raise ValueError("Cross-origin redirect requires explicit allowed origin")
    method, body = request.method, request.body
    headers = request.headers
    change_to_get = response.status == 303 and method != HttpMethod.HEAD
    if response.status in (301, 302) and method == HttpMethod.POST:
        if not plan.site.redirects.post_to_get:
            raise ValueError("POST 301/302 requires explicit post_to_get policy")
        change_to_get = True
    if change_to_get:
        method, body = HttpMethod.GET, None
        headers = tuple(
            (k, v)
            for k, v in headers
            if k.lower() not in {"content-type", "content-length", "transfer-encoding"}
        )
    if target_origin != old_origin:
        # Only explicitly safe public headers cross origin; no custom credential leakage.
        headers = tuple(
            (k, v)
            for k, v in headers
            if k.lower() in {"accept", "accept-language", "user-agent", "content-type"}
        )
        if body is not None:
            raise ValueError("Cross-origin body replay rejected")
    return replace(request, url=target, method=method, body=body, headers=headers)
