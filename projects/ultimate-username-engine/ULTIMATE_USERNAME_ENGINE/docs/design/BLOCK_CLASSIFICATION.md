# Block and failure classes

> English translation of [`BLOCK_CLASSIFICATION.md`](../../BLOCK_CLASSIFICATION.md) (Polish original, kept alongside; the original has no date, it belongs to the 2026-10-09 stage). The text up to the "Translator's status notes" heading is a faithful translation of the original; the notes at the end compare it with the code in this repository.

| Evidence | Class / state | Behaviour |
|---|---|---|
| HTTP 403 | HTTP_403 / BLOCKED | The observation is kept; possibly a separate public endpoint from the registry. |
| HTTP 429 | HTTP_429 / RATE_LIMITED | No fallback; origin cooldown, at most one retry if the definition and the budget allow. |
| HTTP 401 or a recognised login path | LOGIN_REQUIRED / BLOCKED | No login attempt; a separate public endpoint is permitted. |
| A recognised challenge marker | CHALLENGE / BLOCKED | No interaction with the challenge; only a separate public endpoint, if one exists. |
| HTTP 410 | ENDPOINT_REMOVED | A signal of an endpoint problem; fallback permitted, unless detection has already returned an unambiguous NOT_FOUND. |
| Explicit credential_env without a value | API_REQUIRES_KEY / API_REQUIRED | SKIPPED_API_CREDENTIAL_REQUIRED; zero primary requests; a public fallback is possible. |
| BLOCKED without more specific evidence | UNKNOWN_BLOCK / BLOCKED | We do not add a presumed cause. |
| Consecutive 403 / 429 / timeout / 5xx of an origin | DEGRADED, CIRCUIT_OPEN | The following attempts are held until the circuit breaker window expires. |

A known challenge or login takes precedence over the general status class.
`http_403_responses` and `http_429_responses` in the economy count the actual HTTP codes
independently, enrichment included. HTTP 403 does not prove a regional restriction,
and HTTP 451 alone does not indicate a region. Therefore REGION_UNAVAILABLE is not
assigned without a verified adapter that supplies such evidence.
A 404 does not automatically mean "endpoint removed" — it may concern the account.

The 429 cooldown: the maximum of a valid Retry-After and the configured minimum
(default 30 s). Numbers and HTTP dates are supported. A long cooldown may end
with the job deadline without a retry; we keep RATE_LIMITED. The other origins may continue.
A retry requires a free global slot, the retry budget and the definition's policy.
The remaining retries have by default at least 1 s spacing.

The circuit breaker is local to a job and an origin: after 3 consecutive failures
it opens for 60 s. A successful response resets the series. It does not launch additional
"health probes"; after expiry the ordinary pending work may try again.
Parallel attempts that have already started may finish, so the number of responses
above the threshold is bounded by concurrency and is not always exactly 3.

API key: a definition may contain `credential_env`, `credential_header` and
`credential_prefix`. The value is taken from the environment only while the request is being worked on.
We do not write it to results or traces. Headers and ENV names are validated;
values containing CR/LF are rejected. The header does not pass to a fallback, and a redirect
between origins keeps the existing list of safe headers.
The current catalogue received no keys and no automatic paid integrations.

Index sources: an explicit `discovery_only` and recognised search routes of
Google/Bing/DuckDuckGo/Yahoo receive `INDEX_EVIDENCE`. Their verdict remains
UNKNOWN; in ANALYST a checked result with state OK carries the label DISCOVERY_ONLY. We do not
automatically follow links from a search-engine page. The list of recognised hosts is
narrow; another index source requires an explicit marking of the definition.

## Translator's status notes

These notes are not part of the original. They were checked against the code of this repository (`policies.py`, `engine.py`, `runtime_policy.py`, `domain/validation.py`).

- **Cooldown is now capped.** `engine._SearchWork._observe_origin` raises a 429 pause to at least `rate_limit_seconds` (30 s) but caps the origin cooldown at `RETRY_AFTER_GIVE_UP` = 60 s. `policies.retry_wait` returns no retry at all when `Retry-After` exceeds 60 s, and a backoff delay is capped at `MAX_RETRY_DELAY` = 10 s. A hostile `Retry-After: 86400` therefore cannot park an origin for a day (regression test: `tests/unit/test_security_review_fixes.py::test_429_retry_after_cooldown_is_capped_at_the_give_up_limit`). The statement above that a long cooldown "may end with the job deadline" describes the earlier behaviour.
- **Control-request retry.** A rate-limited control request has its own short retry limit (`CONTROL_RATE_RETRY_AFTER`, `CONTROL_RATE_RETRY_WAIT` in `engine.py`); it is not covered by this document.
- **Transient retries.** The NORMAL, DEEP and EXHAUSTIVE modes allow two extra attempts for transient failures (reset, refused, temporary DNS, timeouts, HTTP 502/503/504; `policies.TRANSIENT_ERRORS`, `TRANSIENT_STATUSES`), within the retry budget. 401/403/429 responses, challenges and login walls are not retried (`policies.should_retry`).
- **Credentials.** `credential_env` accepts any environment variable name that matches `[A-Za-z_][A-Za-z0-9_]*`; there is no allowlist of variable names and no restriction on the host that receives the header. Registry files that declare it must be treated as trusted input (see [SECURITY_ARCHITECTURE.md](../../../docs/SECURITY_ARCHITECTURE.md), gap G-4).
- **Status names.** `HTTP_403`, `HTTP_429`, `ENDPOINT_REMOVED`, `UNKNOWN_BLOCK` and `API_REQUIRES_KEY` are block classes recorded in the attempt records (`block_class`); `BLOCKED`, `RATE_LIMITED`, `DEGRADED` and `API_REQUIRED` are values of `ExecutionState`, and `CIRCUIT_OPEN` is an `ErrorCode` (`domain/models.py`).
