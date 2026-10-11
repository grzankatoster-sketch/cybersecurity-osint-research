# Search budget — 2026-10-09

> English translation of [`BUDGET_ARCHITECTURE.md`](../../BUDGET_ARCHITECTURE.md) (Polish original, kept alongside). The text up to the "Translator's status notes" heading is a faithful translation of the original and describes the design **as of 2026-10-09**. Several numeric limits changed afterwards; the notes at the end compare the document with the current code in this repository (`src/ultimate_username/runtime_policy.py`, `cli.py`).

## Audit before the change

Flow: `cli.Command.search` → `select_services` → `UsernameEngine.search_stream`
→ `plan_request` → `Scheduler.stream` → `_SearchWork.step` → `_Budget.remaining -= 1`
→ `transport.send` → detection/retry/redirect/enrichment → journal → ANALYST.

| Question | Behaviour of the previous version |
|---|---|
| What did the request budget limit? | Transport calls, not services and not the number of definitions as such. |
| Did a retry cost anything? | Yes, every further transport call. |
| Did a fallback cost anything? | There was no automatic fallback. |
| Could donors cost several units? | Yes, with `--selection all` and with an explicit choice of definitions. The default quality selection already deduplicated. |
| When was the budget reserved? | After preflight, directly before `send`, with no `await` between the check and the decrement. |
| Cancellation? | Before the reservation: 0. After the reservation: 1, not refunded. There was no record of an attempt cancelled during transport. |
| BLOCKED / TIMEOUT / 429? | Every started attempt cost 1, whatever the outcome. A queue timeout before an attempt cost 0. |
| Redirect? | Every hop cost 1. |
| Enrichment? | BASIC used the same body; a FULL follow-up used up the global limit and a separate enrichment limit. |

The default CLI limit was 10,000. The deadline covered the requests and the processing of metadata. The limits were and remain **per username/job**. Three usernames are three budgets. An important correction of the problem description: "the first N records" was a historical model; the starting version of this stage already had ranking and canonical services.

## Implemented model

`RuntimePolicy` → canonical selection with scoring → service budget limit
→ one `_CanonicalWork` per service → primary / at most two fallbacks
→ shared `_Budget` → the existing bounded scheduler.

The service budget limits the number of admitted profile groups. The request budget is
a hard ceiling for all started requests, redirects included. The retry budget
and the enrichment budget are sublimits of the same ceiling, not additional pools.
The separation is justified: a retry should not use up the whole scan, and FULL should
not increase the cost of collecting metadata without bound.

The reservation is atomic within one asyncio loop. A request cancelled after the
reservation now has an `AttemptRecord` with CANCELLED; we do not assume that the packet
reached the server, only that the transport call was started. BASIC still costs 0
additional requests. An enrichment slot is reserved when a follow-up is planned;
the global unit only when the attempt starts. An unused slot is not reported
as an executed request.

| Mode | Services max | Requests max | Retries max | Enrichment follow-ups max | Deadline | Fallbacks/service | Min. score |
|---|---:|---:|---:|---:|---:|---:|---:|
| QUICK | 50 | 50 | 0 | 0 | 90 s | 0 | 30 |
| NORMAL | 200 | 250 | 10 | 0 | 300 s | 2 | 0 |
| DEEP | 1000 | 1300 | 50 | 50 | 1200 s | 2 | -30 |
| EXHAUSTIVE | 1 000 000 | 20 000 | 200 | 200 | 3600 s | 2 | -100 |

EXHAUSTIVE covers all 7557 compatible groups of the current catalogue.
A million is a finite safety fuse for future catalogues, not a planned number
of requests. The default concurrency 20 / per-origin 2 / per-job 10 remain;
a definition may impose a lower limit. The enrichment budget is used only with
`--enrich full` and only with a declared allowed follow-up URL.
A retry additionally requires the consent of the policy of the given definition; merely setting 10
does not force ten repetitions.

The profiles are explicit configuration in `runtime_policy.MODES`, not an estimate of
optimality for the entire internet. `--runtime-config file.json` loads a strict
`RuntimePolicy` (omitted fields take the NORMAL defaults); it replaces the mode profile.
The explicit flags `--request-budget`, `--service-budget`, `--retry-budget`,
`--enrichment-request-budget`, `--job-timeout` take precedence.

## Ranking, diversity and cost

Base scoring: a valid definition +10, positive +10, negative +10,
owner binding +30, content instead of status alone +15, a declared parser or
verified adapter +15. New components: structured JSON rule +10,
no positive -20, positive based on status only -15,
inconsistent donor rules -5, index evidence -30. Invalid and disabled
definitions do not enter the plan. Every component is recorded in `.selection.json`.

We do not grant a "current validation" bonus or "stale" penalties without a measurement. A declaration
of a rule does not prove its correctness live. Static scoring is a heuristic of
technical quality, not the probability that an account exists.

The highest quality thresholds go first (among others binding/JSON), then the remaining
admitted definitions. Category diversity works within equal thresholds:
a category that has been represented less so far is preferred, without equal quotas.
It does not lower the priority of quality in favour of a category alone. `misc` categories
are not split artificially. Value/cost is deterministic: the base cost of
a primary is one send; further costs are conditional and subject to the shared limits.
We do not pretend to know future delays or the frequency of blocks.

## Boundaries and further decisions

- No request: ANALYST `NOT_TESTED`, technically for example BUDGET_EXHAUSTED,
  API_REQUIRED, DEGRADED. After an actual 429/403 response, exhaustion of the limit
  does not overwrite its semantics; the reason for stopping goes into reasons.
- The summary also covers groups rejected by the service budget / quality threshold;
  `not_tested_selected` makes it possible to tell them from those that were admitted but not executed.
- Extension is a suggestion of `deep/exhaustive`; there is no automatic raising
  of the cost, no stopping after the first profile and no hidden `max-results`.
- Resume and cache TTL were considered. Automatic reuse of results was not
  implemented: it requires a separate freshness policy, a key of username+canonical+revision and
  a shorter TTL for negatives. The current journal keeps committed observations,
  but does not pretend to be a complete queue checkpoint. Every control validation
  executes the indicated attempts again.
- The library API without `runtime` keeps the previous semantics. An adaptive
  call requires a `SelectionPlan`; the policy limits apply also when
  the caller passes a larger `SearchOptions.request_budget`.

Sources: `engine.py`, `scheduler.py`, `runtime_policy.py`, `cli.py`.
Evidence: `artifacts/adaptive-budget/`, results in `RUNTIME_BUDGET_RESULTS.md` (not published).

## Translator's status notes

These notes are not part of the original. They were checked against the code of this repository.

- **Mode limits have changed.** In the current `runtime_policy.MODES` only QUICK matches the table above (50 services, 50 requests, 0 retries, 90 s, min. score 30, no fallbacks). The current values are:

  | Mode | Services | Requests | Retry budget | Control-request budget | Enrichment follow-ups | Deadline | Min. score |
  |---|---:|---:|---:|---:|---:|---:|---:|
  | QUICK | 50 | 50 | 0 | 0 | 0 | 90 s | 30 |
  | NORMAL | 800 | 1100 | 60 | 150 | 0 | 300 s | 0 |
  | DEEP | 1000 | 1300 | 50 | 150 | 50 | 1200 s | -30 |
  | EXHAUSTIVE | 1 000 000 | 20 000 | 200 | 2500 | 200 | 3600 s | -100 |

  NORMAL, DEEP and EXHAUSTIVE additionally enable `transient_retries=2` and `rescan_errors` (one closing pass over services that ended in a network error; `--no-rescan` disables it); QUICK, NORMAL and DEEP set `health_skip` (definitions rated dead, blocked or false positive in `data/health.json` are skipped). Fallbacks per service remain 2 except in QUICK. The "NORMAL: 200 groups / 250 requests" figures also survive in `examples/runtime-policy.json` and in the Polish README; they describe the 2026-10-09 state.
- **Control budget.** The table above does not contain the control requests (`--control-budget`, `control.py`) that were added later; they are part of the request ceiling.
- **Per-job concurrency.** The default `--per-job` is now equal to `--concurrency` (20) instead of the fixed 10 (`cli.scheduler_config`).
- **Journal durability.** The journal uses SQLite WAL with `synchronous=NORMAL` (`storage.ResultJournal`); a process interruption loses nothing, an operating-system crash or power loss may lose the last commits.
- **Figures that depend on the catalogue** (7557 compatible groups, the 118 groups mentioned in the fallback document) refer to the catalogue that is not shipped with this repository.
- **Referenced files not published:** `RUNTIME_BUDGET_RESULTS.md`, `artifacts/adaptive-budget/`.
