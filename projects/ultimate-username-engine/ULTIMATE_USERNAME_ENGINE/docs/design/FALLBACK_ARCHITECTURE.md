# Public fallback — 2026-10-09

> English translation of [`FALLBACK_ARCHITECTURE.md`](../../FALLBACK_ARCHITECTURE.md) (Polish original, kept alongside). The text up to the "Translator's status notes" heading is a faithful translation of the original and describes the design **as of 2026-10-09**; the notes at the end compare it with the code in this repository.

A canonical service still means a conservative group of the profile URL template:
host + path + query, with a previously verified www alias for GitHub.
We do not equate different paths and subdomains with one platform without evidence.

Within a group the technically best definition is the primary. The others are sorted
by the same explicit quality. The chain receives at most two distinct
endpoints that satisfy `public_alternative`; no URLs are guessed.

## Qualification of an alternative

- A valid, enabled definition of the same group that is compatible with the username.
- A probe URL/query different from the primary's; repeated alternative endpoints
  are removed before execution.
- GET, `public` context, no body and no required key.
- Headers limited to Accept / Accept-Language; no cookies, Authorization,
  additional `query` parameters and no suspicious key/session parameters in the URL.
- The profile host or its `api.` host; a search-engine source does not qualify.
- A positive rule exists. Status alone can give at most PROBABLE under the
  ordinary resolver, not an automatic FOUND.

This is an explicit, conservative technical qualification of the definition. It does not mean
a current validation of the availability of every endpoint. The current catalogue has **118 groups / 121
distinct alternative endpoints** that satisfy these conditions. The catalogue is not
automatically extended with external index providers.

## Execution

403/BLOCKED, a missing required key, PARSE_ERROR, UNSUPPORTED, SERVER_ERROR
or a confirmed HTTP 410 may trigger an alternative. NOT_FOUND and 429 do not
trigger it. A timeout is subject to a bounded retry / circuit breaker;
no automatic fallback was added after every timeout or ordinary UNKNOWN.

A single `_CanonicalWork` keeps the task ID and the shared budget. After a primary failure
it moves to the next admitted definition, without copying the session or the
headers of the primary. The bounded scheduler gives the fallback continuation priority
over the buffer of new primaries. Without it a small budget could run out before
a planned alternative received a slot. The limits of the origin, of global concurrency,
of the number of fallbacks and of the deadline still apply.

The final result is a single one. If the alternative gives FOUND, PROBABLE or NOT_FOUND,
it becomes the source of the result. If it remains inconclusive, we keep the block
or the error of the primary. DEBUG shows independent `DefinitionObservation`s with detection,
attempts, probe URL, role and block class. The attempts list of the result covers the whole
chain, while the metadata concern the selected source. ANALYST shows `source: fallback`
without duplicating the profile. No fallback raises a verdict without evidence.

Control example: primary JSON → 403/BLOCKED, public HTML → content + binding →
FOUND. Cost: one PRIMARY_CHECK and one FALLBACK_CHECK; one canonical result.
Opposite example: primary NOT_FOUND → finished after one request.

## Telemetry and definition health

`request_economy` reports fallback_attempted, success, not_found, blocked, error,
recovered_canonical_services and the observed block classes. Success means
FOUND/PROBABLE, and recovered resolutions also include NOT_FOUND.
An inconclusive fallback is counted as error, not as success.

`DefinitionHealth` records locally in `definition-health.sqlite` next to the journal:
checks, successful_checks, blocked_responses, timeouts, parser_failures,
metadata_success. The key includes the revision and the site ID; job/task protects against
double counting on import. SQLite transactions protect parallel CLI runs.
Checks are started attempts; successful_checks means a definition result of
FOUND/PROBABLE/NOT_FOUND, not independently confirmed correctness. The parser counters also cover
enrichment errors of the selected source.

**Health ranking remains disabled.** The collected attempts are local, dependent on the
username, the time and the network. We do not promote a definition after one success, or after several
retries of the same attempt. Before enabling ranking, a sufficient number of independent
observations and a time window must be established; the current code does not invent such data.

CAPTCHA solving, session transfer, browser impersonation and proxy rotation
have not been implemented. Limitations remain observations in the result.

## Translator's status notes

These notes are not part of the original. They were checked against the code of this repository.

- **Catalogue-dependent figure.** "118 groups / 121 endpoints" refers to the catalogue that is not shipped with this repository (it must be rebuilt locally; see the main README). The figure was not re-measured.
- **Separate health file.** The document describes the per-run `definition-health.sqlite` (written by `request_economy.DefinitionHealth` next to the journal). A different mechanism, `data/health.json` (`health_probe.py`, `health-probe` / `health-passive` commands), rates definitions with one of the states `dead`, `blocked`, `false_positive`, `uninformative`, `stale`, `unstable`, `ok` or `untested` and is used by the QUICK, NORMAL and DEEP modes to skip definitions rated dead, blocked or false positive (EXHAUSTIVE only orders by it). The statement "Health ranking remains disabled" refers to the first mechanism, not to this file.
- **Retries and rescan.** NORMAL, DEEP and EXHAUSTIVE now enable `transient_retries=2` and a closing rescan of services that ended in a network error (`runtime_policy.MODES`); this goes beyond the "bounded retry / circuit breaker" described above.
- **Cooldown.** See the status notes of `BLOCK_CLASSIFICATION.md` for the cap on the 429 cooldown.
- **Referenced identifiers** (`public_alternative`, `PRIMARY_CHECK`, `FALLBACK_CHECK`, `recovered_canonical_services`) are the names used by the 2026-10-09 implementation; the control-request checks and the closing rescan added later use their own budget reason `CONTROL_CHECK` and role `RESCAN_CHECK` (`engine.py`).
