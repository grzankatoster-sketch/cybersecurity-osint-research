# Benchmark: methodology, results and limitations

This document reports how the Ultimate Username Engine was measured against the earlier Username Engine v1 (called "OSINT" in the maintainer's internal reports; source in [`projects/osint-toolkit/username-engine`](../../osint-toolkit/username-engine)), what the numbers were, which development gates failed, and why the numbers should be read with caution. The harness is published in [`bench/`](../bench); the **labelled ground-truth data, the raw responses and the result files are not published**, so the figures below cannot be reproduced from this repository alone (section 9 explains how to reproduce the method with your own data).

All figures are quoted from the maintainer's internal reports of 2026-10-10 and 2026-10-11 (baseline, holdout, development, extraction and performance reports plus the progress and decision logs). They were not re-measured for this document. Commit hashes in this document identify states in the maintainer's development history and are given for traceability; they do not necessarily exist in the published history.

## 1. Summary

- The question measured is narrow: for a labelled set of (username, site) pairs, does the engine report that the account exists (`FOUND`/`PROBABLE`), does it report that it does not (`NOT_FOUND`), or does it abstain?
- At the baseline commit the engine had perfect precision on the holdout and very low recall (P 1.000, R 0.212, decision coverage 0.272): it almost never produced a false positive and almost never decided. Development work (control requests, retries and rescans, redirect handling, additional definitions, extractors) raised recall to 0.769 (final integrated run) and 0.779 (extraction stage) at P 1.000, at the price of 34.5% more requests in the exhaustive mode.
- **Two gates failed.** The detection-gap phase (F3) missed its recall gate (R 0.769 < 0.80). The identity phase (F4) failed: the identity score recognised 0 of 6 target accounts on the holdout and 1 of 7 on the development set.
- **v1 had higher recall than Ultimate on the same holdout** (R 0.962 against 0.779 at the last holdout measurement). v1 was less precise on the identity question (many hits were namesakes or deleted accounts) and, per the maintainer's analysis, its recall figure is inflated by how the sample was drawn (section 8.2). Ultimate prioritises precision and abstains when evidence is insufficient.
- The holdout is small: 159 labelled pairs, 151 evaluated (104 existing accounts, 47 absent). The target-identity view contains 6 positive accounts. Labels were assigned by LLM agents and reviewed by another LLM, not by a human.

## 2. Methodology

### 2.1 Unit of evaluation

The unit is a **pair (username, host)**, where `host` is the lower-case hostname of the profile URL without a leading `www.` (`bench/compare.py::hostkey`). A host can map to several catalogue definitions; the harness reduces them to one verdict per host by taking the strongest category in the order `FOUND > PROBABLE > NOT_FOUND > UNKNOWN > BLOCKED > ERROR > SKIPPED`. A host absent from the engine's catalogue is `MISSING` and counts as a miss.

### 2.2 Labels

Each pair carries two ground-truth labels (`bench/evaluate.py`):

- `label`: `ACCOUNT_EXISTS`, `ACCOUNT_ABSENT` or `UNVERIFIABLE`. Banned, suspended or locked accounts that still show a profile with history were labelled `ACCOUNT_ABSENT` (with an account-state note), following the rule that such a pair must never count as a found account. `UNVERIFIABLE` pairs (8 in the holdout) are excluded from all metrics.
- `identity` (meaningful for existing accounts): `TARGET` (the account belongs to the person behind the reference username, confirmed beyond a self-declaration, for example by platform verification, very large reach or a channel attached through OAuth), `HOMONYM` (a different person with the same handle), or `UNKNOWN`.

### 2.3 Labelling protocol (summary)

- Pairs were labelled on live pages by LLM agents working in disjoint, shuffled batches, without access to either engine's verdicts and without the sampling group of the pair. Evidence came from fetching the profile page (plain GET or a headless browser), the final URL, status, title and context around the username, a comparison with a control name where the result was ambiguous, and public platform APIs where they exist.
- A separate reviewer (also an LLM) re-checked a sample and every uncertain case. For the holdout, 5 labels were corrected and recorded in a `review` field and 6 independent re-checks agreed. For the development set, 19 pairs were re-verified live: 0 disagreements on account existence and 1 correction on identity.
- **No human labelled or adjudicated the pairs, and no inter-annotator agreement was computed.** The maintainer's report recommends human review of the 8 `UNVERIFIABLE` pairs and the 5 corrections.
- Labels date from 2026-10-10, hours after the baseline scan. Accounts may have appeared or disappeared in between.

### 2.4 Reference usernames

- Holdout: **three reference usernames** — one private reference account used throughout the project (pseudonym `Sampler51`) and two public figures with rare handles (pseudonyms `PublicRefA` and `publicrefb`: a chess player and a streamer). The two public handles were chosen as rare strings (fewer accidental namesakes than very common handles) belonging to people with official accounts on many platforms, from different domains (sport and gaming); the private account is the reference username used in all earlier measurements of the project.
- Development: 80 pairs drawn from the same baseline run, 65 pairs from two further public-figure handles, and 19 banned, suspended or closed accounts on 12 hosts in several languages.
- The private reference account contributed no pair to the divergence strata described below, because all of its hits were on services that had been tuned earlier (and were therefore excluded). It appears only in the control strata.

### 2.5 Development set versus holdout

| | Development set (`dev_v1`) | Holdout (`holdout_v1`) |
|---|---|---|
| Purpose | tuning and iteration | phase gates only; frozen |
| Pairs | 164 (EXISTS 101, ABSENT 56, UNVERIFIABLE 7); target identity: TARGET 7, HOMONYM 18, UNKNOWN 76 among existing accounts | 159 (EXISTS 104, ABSENT 47, UNVERIFIABLE 8); TARGET 6, HOMONYM 19, UNKNOWN 79 |
| Evaluated | 157 (UNVERIFIABLE excluded; computed from the counts above) | 151 |
| Sources | 80 pairs from the baseline run, 65 pairs from two further public-figure handles, 19 banned/closed accounts | stratified sample of the baseline run (section 2.6) |
| Hosts | holdout hosts and tuned hosts excluded | tuned hosts excluded at construction |

Rules in the development plan: tune only on the development set; use the holdout once per gate; at most three iterations per phase, after which a phase is stopped and its failure recorded; a precision regression below 0.97 on the holdout rejects a change.

### 2.6 Holdout sampling

The sample was drawn with a fixed seed (`20261010`) from the baseline run, after removing hosts of services that had been tuned during the project (31 services, 36 hosts, each cited to a file and line). The strata deliberately over-represent disagreements between the two engines:

| Stratum | Pool after exclusion (per username, in the order Sampler51 / PublicRefA / publicrefb) | Pairs drawn | EXISTS | ABSENT | UNVERIFIABLE |
|---|---|---:|---:|---:|---:|
| v1 reported a hit, Ultimate did not | 0 / 110 / 42 | 90 | 82 | 2 | 6 |
| Ultimate reported a hit, v1 did not | 0 / 4 / 0 | 4 (all) | 4 | 0 | 0 |
| both reported a hit | 0 / 15 / 10 | 20 | 18 | 0 | 2 |
| Ultimate `UNKNOWN`, v1 `NOT_FOUND` | 2726 / 2696 / 2702 | 30 | 0 | 30 | 0 |
| both `NOT_FOUND` | 889 / 811 / 868 | 15 | 0 | 15 | 0 |
| **Total** | | **159** | **104** | **47** | **8** |

A "hit" is `FOUND` or `PROBABLE`. Identity among existing accounts: TARGET 6, HOMONYM 19, UNKNOWN 79.

### 2.7 Engines and configurations

- Ultimate: `search <username> --mode exhaustive`, default `--enrich basic`, concurrency 20, per-origin 2 (journal and results written per run). Later measurements of the default mode used `--mode normal`.
- v1: `<username> --level full --no-variants --direct --strict-tls --ttl-hours 0`.
- Each engine runs in its own subprocess, sequentially (for each username, Ultimate first, then v1), with an observing wrapper that counts HTTP requests and statuses and hashes the engine sources before and after the run (`sources_unchanged` must be true).
- Verdicts are mapped to common, disjoint categories: for Ultimate the verdict if it is `FOUND`/`PROBABLE`/`NOT_FOUND`, otherwise by execution state (`OK` → `UNKNOWN`, `BLOCKED`/`RATE_LIMITED` → `BLOCKED`, no attempt or unsupported → `SKIPPED`, remainder `ERROR`); for v1 `FOUND` with confidence ≥ 0.6 is `FOUND`, below that `PROBABLE`, errors with an unrecognised-page reason are `UNKNOWN`, anti-bot/403/429/login reasons are `BLOCKED`.
- v1 verdicts for later phases were **not** re-run: the v1 verdicts of the baseline run were reused for every evaluation.

## 3. Metrics

Definitions as implemented in `bench/evaluate.py` (existence view):

- **hit** = engine category `FOUND` or `PROBABLE`; **decided** = `FOUND`, `PROBABLE` or `NOT_FOUND`.
- **TP**: label `ACCOUNT_EXISTS` and hit. **FP**: `ACCOUNT_ABSENT` and hit. **FN**: `ACCOUNT_EXISTS` and not a hit (this includes `UNKNOWN`, `BLOCKED`, `ERROR`, `MISSING` and an explicit `NOT_FOUND`). **TN**: `ACCOUNT_ABSENT` and not a hit.
- **Precision** P = TP / (TP + FP). **Recall** R = TP / (TP + FN).
- **Coverage** = decided pairs / evaluated pairs (positives and negatives together). It measures how often the engine commits to an answer, not how often the answer is right.
- **UNKNOWN among EXISTS** = share of existing accounts for which the engine answered `UNKNOWN`.
- **Target-identity view**: positive = `EXISTS` and `TARGET`; negative = `ABSENT` or (`EXISTS` and `HOMONYM`); `EXISTS` with identity `UNKNOWN` is skipped. For the identity score (`bench/evaluate_identity.py`) a positive prediction is a hit *and* a `TARGET_LIKELY` decision; confidence intervals are Wilson 95%.
- **Cost**: HTTP requests and wall-clock seconds, summed over the three reference usernames unless stated.

Because the sample is stratified (section 2.6), P and R describe the sample, not the catalogue.

## 4. Baseline (state before development, commit `389caf7`)

### 4.1 Full exhaustive scans, 2026-10-10

Hits are `FOUND` + `PROBABLE`. Overlap is computed on hosts without `www.`.

| Username | Engine | Services | Hits | NOT_FOUND | UNKNOWN | BLOCKED | Errors | Requests | Time [s] | Common hits | Only this engine |
|---|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| Sampler51 | Ultimate | 7553 | 8 | 1211 | 4455 | 477 | 1398 | 8054 | 679 | 7 | 1 |
| Sampler51 | v1 | 5142 | 9 | 4518 | 178 | 161 | 268 | 10212 | 388 | 7 | 2 |
| PublicRefA | Ultimate | 7553 | 27 | 1120 | 4525 | 468 | 1409 | 8066 | 653 | 21 | 5 |
| PublicRefA | v1 | 5142 | 143 | 4381 | 173 | 165 | 273 | 10388 | 391 | 21 | 113 |
| publicrefb | Ultimate | 7555 | 17 | 1190 | 4473 | 472 | 1399 | 8146 | 629 | 16 | 0 |
| publicrefb | v1 | 5142 | 63 | 4460 | 171 | 164 | 279 | 10417 | 413 | 16 | 44 |

("Services" are canonical groups for Ultimate and health-filtered definitions for v1, so the denominators differ.) The scan overlap table alone does not measure recall: on public handles v1 reported 5–7 times more hits, but there was no ground truth to decide how many were real accounts. For the hosts that only v1 flagged, Ultimate had sent a request and received `UNKNOWN` in 87 of 113 (PublicRefA) and 31 of 44 (publicrefb) cases; a missing catalogue entry explained only 5 and 3.

### 4.2 Holdout evaluation of the baseline

| View | Engine | n | TP | FP | FN | TN | P | R | Coverage | UNKNOWN among EXISTS |
|---|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| existence | Ultimate | 151 | 22 | 0 | 82 | 47 | 1.000 | 0.212 | 0.272 | 0.692 |
| existence | v1 | 151 | 100 | 2 | 4 | 45 | 0.980 | 0.962 | 0.980 | 0.019 |
| target identity | Ultimate | 72 | 3 | 4 | 3 | 62 | 0.429 | 0.500 | 0.333 | 0.500 |
| target identity | v1 | 72 | 5 | 21 | 1 | 45 | 0.192 | 0.833 | 1.000 | 0.000 |

Per the maintainer's analysis of this evaluation:

- Ultimate missed 82 of 104 existing accounts: 72 `UNKNOWN`, 6 `ERROR`, 3 explicit `NOT_FOUND` and 1 host missing from the catalogue. It produced no false positive.
- A root-cause analysis of the 72 `UNKNOWN` cases found that in 60 the imported catalogue rule already matched the account, but the evidence gate withheld a verdict because the rule was status-only or lacked profile-specific evidence; a request with a random control name distinguished the real account from the control in 41 of those 60 cases (and in 11 more by body length alone). This finding motivated phase F2.
- The suspicion that v1 produced mass false positives was **not** confirmed: 82 of the 84 resolvable v1-only hits were real accounts. v1's weakness was identity: 21 of its 26 hits in the target view were homonyms or deleted accounts.
- The control strata were clean: all 30 pairs "Ultimate `UNKNOWN`, v1 `NOT_FOUND`" and all 15 pairs "both `NOT_FOUND`" were truly absent (so no missed account was found by either engine in them).

### 4.3 Development set baseline

Ultimate P 1.000 / R 0.139 / coverage 0.166; v1 P 0.979 / R 0.921 / coverage 0.834.

## 5. Results by phase

### 5.1 Plan and gates

| Phase | Content | Gate |
|---|---|---|
| F0 | clean state, baseline metrics | baseline reproduced |
| F1 | labelled development set | ~150 pairs; Opus review of 10% of labels (more than 2 disagreements → relabel the batch) |
| F2 | control request with a random name | holdout P ≥ 0.97, R ≥ 0.60, coverage ≥ 0.70; no new explicit false negatives; a known deleted-account host must not become `FOUND`; exhaustive requests ≤ +25% |
| F3 | detection gaps: health ranking, extra definitions, normal-mode budget, retries and rescan, POST controls | holdout P ≥ 0.97, R ≥ 0.80, coverage ≥ 0.85 |
| F4 | identity score | P_TARGET ≥ 0.60 at R_TARGET ≥ 0.60, with n and confidence intervals |
| F5 | features ported from v1 (variants, dorks, Wayback, geo, HTML report) | holdout without regression; HTML reports for the three usernames open in a headless browser without console errors |
| E | extraction of account data | see 5.5 (gate redefined during the work) |

### 5.2 Holdout over time (existence view, n = 151)

| State | Commit | P | R | Coverage | UNKNOWN among EXISTS | Requests (3 usernames) | Time [s] |
|---|---|---:|---:|---:|---:|---:|---:|
| baseline | `389caf7` | 1.000 | 0.212 | 0.272 | 69.2% | 24,266 | 1,961 |
| after F2 | `afdd2f6` | 1.000 | 0.721 | 0.821 | 17.3% | 27,911 (+15.0%) | 2,425 |
| after F3, first integrated run | `d5b5c2a` | 1.000 | 0.712 | 0.808 | 20.2% | 29,068 (+19.8%) | 3,534 |
| final integrated run (F2–F5 + F3.8) | `5f35601` | 1.000 | 0.769 | 0.854 | 17.3% | 32,646 (+34.5%) | 3,349 |
| after extraction stage (E) | `03cffc6` + `9aae0d7` | 1.000 | 0.779 | 0.848 | n/a | 32,583 | 458–576 per username (see 5.6) |
| v1 (reference) | — | 0.980 | 0.962 | 0.980 | 1.9% | 31,017 | 1,192 |

The explicit false negatives on the holdout stayed the same three pairs as at baseline (explicit `NOT_FOUND` answers on two large platforms, Discord and PayPal); the known deleted-account host stayed `UNKNOWN`. The target-identity view on the holdout at the final run, using hits only (no identity filter): P 0.273, R 1.000 (v1: P 0.192, R 0.833).

### 5.3 Development set over time

| State | P | R | Coverage |
|---|---:|---:|---:|
| baseline | 1.000 | 0.139 | 0.166 |
| F2 iteration 1 | 0.882 | 0.663 | 0.694 |
| F2 iteration 2 | 0.964 | 0.525 | 0.561 |
| F2 iteration 3 | 0.955 | 0.624 | 0.631 |
| after F3 | 0.957 | 0.653 | 0.643 |
| final | 0.959 | 0.693 | 0.675 |

Development precision fell from 1.000 to 0.959 while recall rose. Three false positives remained at the end of F2: a deleted account whose API still returns a record, a search-engine-style definition, and a ban notice that lies outside the 2000-character signature window (v1 reports the first two as well). Iteration 2 of F2 shows the cost of an overly broad "JavaScript shell" rule: recall dropped from 0.663 to 0.525 and was recovered by restricting the rule to one class of cases.

### 5.4 Phase outcomes

| Phase | Result | Outcome |
|---|---|---|
| F0 | baseline reproduced | passed |
| F1 | 164 pairs; review of 19 pairs: 0 existence disagreements, 1 identity correction | passed |
| F2 | holdout P 1.000, R 0.721, coverage 0.821, requests +15.0%; reached at iteration 3 | passed |
| F3 | holdout P 1.000, **R 0.769 (< 0.80)**, coverage 0.854 (≥ 0.85; the first integrated run had 0.808) | **failed** (recall) |
| F4 | holdout TARGET **0 of 6** recognised; development TARGET **1 of 7** (P 1.00, R 0.14, 95% CI for R [0.03; 0.51]); holdout R 0.00, 95% CI [0.00; 0.39] | **failed** |
| F5 | features implemented, off by default; HTML reports for the three usernames: 0 console errors, 0 page errors, 0 external requests in a headless browser; holdout without regression | passed |

Contributions of the F3 sub-phases (measured in a single integrated exhaustive run and attributed from reason codes and counters, a deviation from the one-run-per-sub-phase plan that the maintainer recorded): health ranking changed no exhaustive verdicts; the additional definitions produced no hit on the labelled sets because their hosts were not in them; retries and rescan converted one holdout `ERROR` to `PROBABLE`; control requests for POST endpoints converted two holdout `UNKNOWN`/`BLOCKED` pairs to `FOUND`; redirect aliases (`www`/apex) and a re-run of the control request after a 429 added about +0.03 recall on the development set and converted four further holdout pairs. A defect found by the measurement itself: a `503` with `Retry-After: 259200` was retried until the job deadline, so one username took 3910 s; the fix caps backoff and gives up on long `Retry-After` values.

Why F3 and F4 failed according to the reports: the remaining false negatives are mostly pages that are JavaScript shells or identical for every name (they need rendering or a platform API), and only about 15% of hits carried any identity field, with almost no cross-links, so the identity score had no input. Only 3 of the 7 development TARGET accounts were detection hits at all.

The decision on merging the F3–F5 work was left to the maintainer; the published `main` branch includes the later merged work.

### 5.5 Extraction stage (E) and the redefined gate

The identity failure led to a stage that extracts account data (embedded state, JSON-LD, label/value text, public profile APIs, cross-links). While measuring the gap, the maintainer found that only 70 of the 101 existing development accounts were detection hits, so the original target "at least 50% of existing accounts with an identity field" was unreachable without better detection (ceiling 31–35%). **The gate was redefined during the work** to: at least 40% of detection hits on existing accounts have at least one genuine identity field, and field precision at least 0.9.

| | Before | After |
|---|---|---|
| hits on existing development accounts with a genuine identity field | 17/70 = 24% | 29/70 = 41.4% |
| field precision (random sample of 40 fields, verified live) | about 0.37 (52 of 82 fields were templates or echoes of the username); 0.51 after the first iteration | 0.95 (0.944 after deduplication) |
| holdout P / R / coverage | 1.000 / 0.769 / 0.854 | 1.000 / 0.779 / 0.848 (within ±0.01) |
| development P / R / coverage | 0.959 / 0.693 / 0.675 | unchanged |
| requests (3 usernames) | 32,646 | 32,583 |
| identity score, development / holdout | P 1.00 R 0.14 / 0 of 6 | unchanged |

The gate was met under the redefined criteria. The identity recognition gate (F4) remained failed: the holdout target accounts are on platforms the new extractors do not cover or whose pages are JavaScript shells. The second-iteration figures of this stage were measured on a run restricted to the labelled hosts (fewer requests, so fewer rate limits), which the report describes as slightly optimistic for detection; field metrics do not depend on that.

### 5.6 Cost and performance

Wall-clock time per username in exhaustive mode fell from about 1100–1200 s to 458–576 s, and CLI start-up from 24–35 s to about 3.5 s, with unchanged verdicts apart from network noise.

| Change | Effect (measured on a 300-definition random set and a 240-definition error-tail set, one username) |
|---|---|
| cached type hints and a compiled decoder in the codec; single JSON parse; lazy registry revision | start-up 24 s → about 3 s |
| `--per-job` default now equals `--concurrency` (it was 10 with concurrency 20, so one username used half the slots) | error-tail set 367 s → 183 s; 95% of attempts finished after 14.7 s → 8.3 s |
| SQLite journal in WAL mode with `synchronous=NORMAL` | commit 1.5–2.1 ms → 0.44 ms; risk: an OS crash or power loss can drop the last rows |

Profile of the old settings: effective concurrency was 10, not 20; timeouts were 3% of attempts but 27% of slot time; the closing rescan on half the slots took about 37% of the time on the error-tail set. A full-scan time of 600–650 s was an extrapolation in the performance report, and measured runs of 458–576 s per username followed in the extraction stage. Timing measurements were taken on a machine shared with other sessions (about ±10% variation).

Default mode measurement (`--mode normal`, 3 usernames): 769 services, 999 / 1003 / 991 requests, 145.5 / 125.4 / 112.0 s, 77% of exhaustive hits (129 of 167), below the 85% target; per-username overlap with the exhaustive hits was 100%, 73.5% and 82.6%. The reports note that health-based ordering was still weak at that point.

Synthetic scheduler benchmark (`ULTIMATE_USERNAME_ENGINE/benchmarks/run_synthetic.py`; fake transport, 277-byte bodies, 16 origins, concurrency 32, queue 128, Python 3.14.2, tracemalloc on; it measures the planner, scheduler and detection, not the network):

| Definitions | Registry build [s] | Pipeline [s] | Peak async tasks | Peak HTTP in flight | Peak queue |
|---:|---:|---:|---:|---:|---:|
| 100 | 0.048 | 0.045 | 34 | 32 | 100 |
| 1,000 | 0.365 | 0.466 | 34 | 32 | 128 |
| 10,000 | 4.283 | 6.721 | 34 | 32 | 128 |

The task count does not grow with the number of definitions. These figures are a property of the harness, not an SLA for the internet.

### 5.7 Earlier controlled validation (not an independent measure)

Before the holdout existed, a frozen set of 43 cases on 10 services (21 existing, 21 absent, 1 excluded) gave P 1.000, R 0.952, F1 0.976 and decision coverage 0.651 for the then-current version, against R 0.571 for the version before phase 2 and R 0.905 for v1. All 43 cases came from services that had been tuned, so the maintainer's report states that this set says nothing about recall on the remaining catalogue. It is mentioned only for completeness.

## 6. Failed and weak points (consolidated)

- **F3 recall gate failed:** R 0.769 against a gate of 0.80 (coverage met the 0.85 gate only in the final run).
- **F4 identity gate failed:** holdout TARGET 0 of 6, development 1 of 7; confidence intervals are very wide.
- **Recall below v1:** R 0.779 against 0.962 (holdout, existence view); the remaining misses are JavaScript shells and pages that do not differ between real and made-up names.
- **Cost increased:** +34.5% requests in exhaustive mode at the final run (24,266 → 32,646), and about 1.7 times the time before the performance work.
- **Development precision decreased** from 1.000 to 0.959.
- **Gate redefined** for the extraction stage.
- **Default mode** (`normal`) reaches 77% of exhaustive hits and sends roughly 4 times more requests than before the changes (a point recorded in the final review as needing documentation).

## 7. What the numbers do and do not show

They show that, on this sample and for these three reference usernames, the engine rarely reports an account that does not exist, that a control-request mechanism raised recall substantially, and that identity resolution did not work with the data available. They do not show the performance of the engine on arbitrary usernames, on unlabelled parts of the catalogue, or over time.

## 8. Limitations and threats to validity

1. **Small samples.** 151 evaluated holdout pairs (104 positives, 47 negatives), 157 on the development set; 6 target-identity positives on the holdout and 7 on the development set. A single pair moves recall on the holdout by about 0.01 and a single target account moves target recall by 0.17.
2. **The sampling design determines the baseline numbers.** The holdout positives come almost entirely from strata defined by the baseline hits of the two engines. In the baseline evaluation Ultimate's true positives (22) equal the "both hit" positives (18) plus the "Ultimate-only" positives (4), and its false negatives (82) equal the "v1-only" positives (82); v1's true positives (100) equal the "v1-only" (82) plus "both hit" (18) positives, and its false negatives (4) equal the "Ultimate-only" positives (4). These identities hold exactly in the reported counts (the matching of false negatives to the "Ultimate-only" stratum is inferred here from the equal counts, not stated in the reports). The baseline recall of both engines is therefore a consequence of how pairs were sampled, and **v1's recall of 0.962 is structurally high**: almost every positive was in the sample because v1 had flagged it. Later Ultimate measurements are meaningful as a comparison with its own baseline on the same pairs, but the recall figures of the two engines are not estimates of population recall. The maintainer's own estimate for the baseline, relative to the accounts that either engine found in the larger pool, was about 0.16 for Ultimate.
3. **Precision is measured on few negatives.** P = 1.000 is based on 47 labelled-absent pairs, of which 45 come from the control strata. With zero false positives among 47 negatives, the rule of three gives roughly 6% as an approximate 95% upper bound on the false-positive rate per absent pair (this bound is computed here, not taken from the reports). Development precision (0.959) shows that false positives do occur.
4. **Few reference usernames.** Three handles on the holdout, plus two on the development set. The private reference account contributed no divergence pairs. Nothing is known about other languages, naming styles or very common handles.
5. **Labelling quality.** Labels were assigned by LLM agents and reviewed by another LLM; there was no human adjudication and no agreement statistic. Identity labels rest on a conservative `TARGET` definition, which makes `TARGET` rare (6) and `UNKNOWN` common (79). Live pages change; labels are a snapshot of 2026-10-10.
6. **Repeated use of the holdout.** The holdout was used at several gates (baseline, F2, F3 first run, final, extraction stage). It was frozen and not used for tuning, but repeated looks and the knowledge of which hosts failed leak information into development decisions. Later work in an unpublished branch built platform adapters for the holdout's target-identity accounts and added their hosts to the tuned list, so the holdout identity view is no longer independent after that point; those results are not included here.
7. **Optimistic shortcuts.** Some iteration measurements used runs restricted to the labelled hosts (`bench/run_labeled.py`), which send fewer requests and meet fewer rate limits than a full scan; the final gates were taken on full runs except where stated in 5.5.
8. **Environment and time.** Live results depend on source IP, anti-bot behaviour, time of day and concurrent sessions on the same machine (other working copies were running at the same time). The two engines were run alternately for each username, so each may have affected the other's rate limits. The v1 verdicts were measured once and reused.
9. **Mapping choices.** The harness maps each engine's native output into common categories and aggregates definitions per host; different mapping rules (for example the v1 confidence threshold of 0.6, or the strongest-category rule) would change the figures.
10. **Moving gates.** The extraction-stage gate was changed after a measurement showed the first one unreachable. The change is documented but it shows that gates were adjusted to the data.
11. **Single-team evaluation.** The same team built the engine, the harness and the labels; there is no independent replication.
12. **Not measured:** wider catalogue precision and recall, stability over time, other usernames, identity at scale, behaviour under different networks, and comparison with other tools.

## 9. Reproducing the method with your own data

What the repository provides: the harness code in [`bench/`](../bench) (scan runners, normalisation, evaluators, root-cause and report tools) and its unit tests. What you must supply: a catalogue for Ultimate (rebuild it as described in the engine README), a built v1 catalogue if you want the comparison, your own reference usernames, and your own labelled ground truth. Run scans only where you have a lawful basis and authorisation: one exhaustive scan sends roughly 8,000 requests per username per engine to third-party sites.

### 9.1 Ground-truth format

A JSON Lines file, one object per pair (inferred from `bench/evaluate.py`; `host` is the lower-case hostname without `www.`, and `nick` must equal the username that was scanned):

```json
{"id": "h-001", "nick": "alice", "host": "example.com", "label": "ACCOUNT_EXISTS", "identity": "UNKNOWN", "group": "stratum-a"}
{"id": "h-002", "nick": "alice", "host": "example.org", "label": "ACCOUNT_ABSENT", "identity": "UNKNOWN", "group": "control"}
```

- `label`: `ACCOUNT_EXISTS` | `ACCOUNT_ABSENT` | `UNVERIFIABLE`.
- `identity`: `TARGET` | `HOMONYM` | `UNKNOWN` (required on every row; use `UNKNOWN` for absent accounts).
- `group`: free text; the evaluator reports metrics per group. Record how you sampled, and keep labellers blind to engine verdicts.

### 9.2 Steps

All commands run from the project directory `projects/ultimate-username-engine`, with the Ultimate package installed (`pip install -e ULTIMATE_USERNAME_ENGINE`) and, for the comparison, v1's catalogue built.

```bash
# 1. Scan (live network). Results go to bench/results/<date>/raw/<username>/<engine>/
python bench/compare.py alice --date 2026-01-01            # both engines, Ultimate in exhaustive mode
python bench/compare.py alice --date 2026-01-01 --only ultimate --mode normal

# 2. Evaluate against your labels (builds verdicts.json from raw/ on first use)
python bench/evaluate.py --run bench/results/2026-01-01 --holdout path/to/labels.jsonl

# Optional: measure usernames that were not in the run, only for specific hosts
python bench/run_pairs.py --pairs path/to/labels.jsonl --run bench/results/2026-01-01
# Optional: re-use v1 verdicts from an earlier run for an Ultimate-only run
python bench/assemble_run.py --run bench/results/<new> --osint-from bench/results/<old>
# Optional: why existing accounts ended in UNKNOWN; identity and field-coverage evaluation
python bench/rootcause_unknown.py --run bench/results/2026-01-01 --no-live
python bench/evaluate_identity.py --run bench/results/2026-01-01 --labels path/to/labels.jsonl
python bench/field_coverage.py --run bench/results/2026-01-01 --labels path/to/labels.jsonl
```

### 9.3 Caveats about the harness

- `bench/compare.py` expects the layout `projects/ultimate-username-engine/ULTIMATE_USERNAME_ENGINE` and `projects/osint-toolkit/username-engine`, and parses v1's result format as it was when the baseline was taken; check `osint_rows` against the current v1 output.
- Several scripts have Polish docstrings with Windows invocation examples; they are examples, not requirements.
- `bench/evaluate_identity.py` contains a `SEEDS` table that maps reference usernames to seed names for the identity evaluation; supply your own.
- Sampling and labelling helpers used by the maintainer (`make_sample`, `make_dev_sample` and the labelled batches) are not published; `bench/tests/test_dev_sample.py` imports one of them and therefore cannot run without it. `bench/recall_report.py` depends on frozen artifacts of an earlier validation that are not published.
- A comparable evaluation needs an explicit sampling design. Sample at random from *all* pairs, or stratify by something other than the engines' own output, and report the strata; otherwise section 8.2 applies to your results as well.
- Do not publish usernames, profile data or raw responses of real persons; use pseudonyms in reports, as this document does.
