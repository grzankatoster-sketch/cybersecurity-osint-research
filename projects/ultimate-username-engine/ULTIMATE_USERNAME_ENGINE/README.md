# Ultimate Username Engine

An evidence-based username research engine. Given a username, it checks a large catalogue of site definitions and reports, per service, a verdict about a **public profile under that username** together with the evidence behind it. It separates the verdict from the execution state, treats blocks and errors as `UNKNOWN` rather than "absent", and prefers abstaining to guessing.

- Python 3.11 or newer; runtime dependencies `aiohttp` and `regex`; package `ultimate_username`, version 0.1.0.
- Polish documentation of the earlier development stages is kept in [`README.pl.md`](README.pl.md) and the Polish design documents in this directory.
- Benchmark methodology, results and limitations: [`../docs/BENCHMARK.md`](../docs/BENCHMARK.md). Threat model and security controls: [`../docs/SECURITY_ARCHITECTURE.md`](../docs/SECURITY_ARCHITECTURE.md).

## Responsible use and what a result means

Scanning sends the username to every selected site, from your network address. Use the tool only where you have a lawful basis and authorisation (for example an investigation you are entitled to conduct, or a review of your own accounts), and follow the terms of the sites you query.

A match is a lead, not proof. The same handle is routinely held by different people. A result confirms at most that a public profile exists under that username; it does not establish who owns it or that accounts on different platforms belong to one person. The optional identity layer scores that question separately and never changes an existence verdict.

## Architecture

Pipeline: planning, scheduling, transport, detection, evidence, enrichment/extraction, identity, reporting.

```
input -> registry + validation -> normalisation + request plan -> canonical selection + runtime policy
      -> bounded scheduler -> guarded one-hop transport -> response gate + detection rules
      -> (control request) -> evidence + owner binding -> base result committed to the journal
      -> optional enrichment / extraction (isolated processes) -> optional identity score
      -> analyst JSON, console, HTML, JSON / NDJSON / CSV
```

| Stage | Modules (`src/ultimate_username/`) | Responsibility |
|---|---|---|
| Planning | `registry.py`, `domain/validation.py`, `domain/urls.py`, `planning.py`, `selection.py`, `runtime_policy.py` | Validated, immutable site definitions (invalid ones stay visible and are not executed); per-site username normalisation and URL rendering; grouping of definitions into canonical services with an explainable static quality score; mode profiles (`MODES`) with explicit request, retry, service and time ceilings. |
| Scheduling | `scheduler.py`, `engine.py`, `policies.py` | One fair dispatcher with global, per-origin and per-job limits and bounded queues; retries and redirects are new scheduled attempts, not sleeping workers; origin cooldown and circuit breaker; public fallback chain per canonical service; closing rescan of network errors. |
| Transport | `transport.py`, `http_transport.py`, `opsec/guard.py`, `opsec/transport_factory.py` | A transport port with an offline fake; the aiohttp implementation performs exactly one hop, verifies TLS, disables cookies and bounds the decoded body; every request, redirect hop, avatar and archive lookup passes the egress guard. |
| Detection | `response_quality.py`, `detection.py`, `profile_adapters.py`, `profile_binding.py`, `control.py` | Failure gate and response classification; rule strategies (status, message, regex, JSON path, redirect, header, all/any/not); narrowly scoped profile parsers and owner binding; the control-request mechanism that compares the real response with the response for a random name. |
| Evidence | `evidence.py`, `domain/models.py` (`DetectionResult`, `EvidenceSignal`), `request_economy.py` | Ordinal, explainable signals (never probabilities); evidence level and strength; per-run request accounting. |
| Enrichment / extraction | `enrichment.py`, `enrichment_filters.py`, `embedded_state.py`, `literal_data.py`, `api_adapters.py`, `field_model.py`, `extraction.py`, `profile_service.py` | Profile fields taken from the already fetched response (JSON, JSON-LD, Open Graph, embedded page state, label/value text) with provenance and an owner guard; optional follow-up requests to declared public profile APIs inside the request budget; parsers run in killable child processes and never execute JavaScript. |
| Identity | `identity.py`, `geo.py` | Optional score of whether a hit belongs to the target or a namesake (`TARGET_LIKELY`, `UNRELATED_LIKELY`), country clues from profile metadata. |
| Reporting | `presentation.py`, `html_report.py`, `storage.py`, `dorks.py`, `variants.py` | Analyst document and console view; self-contained HTML report; SQLite result journal and atomic JSON/NDJSON/CSV export; optional search-engine query text and archive lookups; optional username variants. |
| Catalogue tooling | `importers.py`, `metadata_import.py`, `tools/import_catalogs.py`, `health_probe.py`, `health.py` | Offline conversion of donor catalogues with a loss account; health ratings of definitions. |

Design decisions are recorded in [`docs/adr`](docs/adr) (typed immutable contracts, bounded runtime, conservative import, isolated enrichment, storage and scope) and the donor-to-component mapping in [`docs/COMPONENT_TRACEABILITY.md`](docs/COMPONENT_TRACEABILITY.md). English translations of four design documents are in [`docs/design`](docs/design): [evidence model](docs/design/EVIDENCE_MODEL.md), [budget architecture](docs/design/BUDGET_ARCHITECTURE.md), [fallback architecture](docs/design/FALLBACK_ARCHITECTURE.md) and [block classification](docs/design/BLOCK_CLASSIFICATION.md). The remaining design documents (`SEARCH_FUNNEL.md`, `REQUEST_ECONOMY.md`, `OSINT_FIELD_MODEL.md`, `OUTPUT_REDESIGN.md`, `IMPLEMENTATION_STATUS.md`, `PERFORMANCE.md`, `IMPORT_REPORT.md`) are in Polish.

## Evidence model and verdict classes

Every result carries two independent parts: a **verdict** about the account and an **execution state** of the check.

| Verdict | Meaning |
|---|---|
| `FOUND` | Positive profile-specific content or a reviewed profile object, plus an explicit owner binding. An HTTP 200 alone is never enough. |
| `PROBABLE` | A positive rule plus a profile signal (for example a matching root username/login together with a profile field), but no strong binding. A heuristic that needs verification. |
| `NOT_FOUND` | Negative content or a verified negative rule. Rejected candidates are not turned into non-existent accounts automatically. |
| `UNKNOWN` | Everything else: no evidence, conflicting evidence, an incomplete response, or any block. |

Execution states (`OK`, `BLOCKED`, `RATE_LIMITED`, `TIMEOUT`, `NETWORK_ERROR`, `SERVER_ERROR`, `PARSE_ERROR`, `UNSUPPORTED`, `SKIPPED`, `CANCELLED`, `BUDGET_EXHAUSTED`, `API_REQUIRED`, `DEGRADED`, ...) coexist with the verdict. The data model enforces the rule that an execution error cannot assert existence or absence (`DetectionResult.__post_init__`): transport errors, incomplete bodies, 401/403/429/5xx, challenges and login walls always yield `verdict=UNKNOWN` with the corresponding state, for example `BLOCKED`. No block is reported as "no account" and no attempt is made to solve or bypass a challenge.

Further fields on every result:

- `response_class`: `PROFILE`, `PROFILE_CANDIDATE`, `NOT_FOUND`, `WRONG_USER`, `GENERIC_PAGE`, `REDIRECT_ONLY`, `DISCOVERY_ONLY`, `LOGIN_REQUIRED`, `CHALLENGE`, `INSUFFICIENT_EVIDENCE` or `UNCLASSIFIED`. It is a separate classification, not a fifth verdict.
- `evidence_level` (0 to 4) and `confidence.strength` (`INSUFFICIENT`, `WEAK`, `MODERATE`, `STRONG`, `COMPOSITE`). They describe which criteria were met, not a probability. `confidence.value` is always `null`: no calibrated model exists.
- `signals`: the list of observed evidence (kind, source, locator, weight, independence group). Correlated reflections of the username (URL, title, Open Graph) are never summed into a `FOUND`.
- `source_kind` and the full attempt, redirect and fallback history.

Imported historical rules receive no invented owner binding, so most of the imported catalogue can produce at most `PROBABLE`. The **control request** adds evidence for `UNKNOWN` cases: for a limited class of results the engine requests the same URL for a random name that almost certainly does not exist, and compares the two responses (status, final URL, title, body similarity). A real difference together with substantive profile content can promote a result whose rule matched to `PROBABLE` or `FOUND`; where no rule matched, an identical response to the made-up name can establish `NOT_FOUND`; where a rule matched, an identical response keeps the result `UNKNOWN`. JavaScript shells, pages that do not differ and deleted-account patterns stay `UNKNOWN`. Details and a caveat about `evidence_level` on control-derived results are in the [evidence model notes](docs/design/EVIDENCE_MODEL.md).

## Runtime modes and budgets

`--mode` selects a profile from `runtime_policy.MODES`; the default is `normal`. Limits apply **per username**, and the request budget is a hard ceiling for all started requests, redirects, retries, fallbacks and control requests.

| Mode | Services | Requests | Retry budget | Control-request budget | Deadline |
|---|---:|---:|---:|---:|---:|
| `quick` | 50 | 50 | 0 | 0 | 90 s |
| `normal` (default) | 800 | 1100 | 60 | 150 | 300 s |
| `deep` | 1000 | 1300 | 50 | 150 | 1200 s |
| `exhaustive` | all | 20 000 | 200 | 2500 | 3600 s |

`quick`, `normal` and `deep` skip definitions that `data/health.json` rates as dead, blocked or false positive; `normal`, `deep` and `exhaustive` allow two extra attempts for transient failures and a closing rescan of network errors (`--no-rescan` disables it). `deep` and `exhaustive` also allow follow-up enrichment requests when `--enrich full` is used. Explicit flags (`--request-budget`, `--service-budget`, `--retry-budget`, `--control-budget`, `--enrichment-request-budget`, `--job-timeout`) override the profile, and `--runtime-config FILE` loads a strict JSON `RuntimePolicy`. Defaults: concurrency 20, per-origin 2, per-job equal to the concurrency.

A small budget examines a ranked fragment of the catalogue, not the whole internet. Services that were not tested are reported as `NOT_TESTED` with a reason (for example `SERVICE_BUDGET`, `BUDGET_EXHAUSTED`, `HEALTH_SKIPPED`). The cost model and its rationale are in the [budget architecture](docs/design/BUDGET_ARCHITECTURE.md); the public fallback and block handling in [fallback](docs/design/FALLBACK_ARCHITECTURE.md) and [block classification](docs/design/BLOCK_CLASSIFICATION.md).

## OPSEC and egress control

Only behaviour implemented in the code is listed. The full analysis, including gaps, is in [SECURITY_ARCHITECTURE.md](../docs/SECURITY_ARCHITECTURE.md).

- **Egress guard on all traffic.** The CLI wraps its transport in `opsec.transport_factory.public_egress_transport`: every request, redirect hop, avatar download and Wayback lookup is refused when the host is a numeric or local spelling of an internal address (`127.1`, `0x7f000001`, `localhost`, `*.internal`, ...) or when any resolved address is private, loopback, link-local (including the cloud metadata address), CGNAT, reserved or multicast (`opsec/policy.py`, `opsec/guard.py`).
- **One hop at a time.** The HTTP transport never follows redirects itself. Each hop is a new scheduled attempt that passes the guard and the per-origin limit; cross-origin redirects need an explicit allowed origin or the "safe cross-origin" exception (same site, or a public host whose path still names the profile), HTTPS-to-HTTP downgrades and loops are errors, and request bodies and non-public headers are not replayed across origins.
- **Bounded responses.** 1 MiB decoded body limit, incremental gzip/deflate decoding with a cap, TLS verification on, cookies off, environment proxy variables ignored.
- **Proxy.** `--proxy URL` (`http`, `https`, `socks4`, `socks5`; SOCKS needs `pip install -e ".[socks]"`). With a proxy the egress guard performs no local DNS lookup of target names (so internal-address checks then rely on literal and local spellings; see the security document for the `socks4` caveat). A failed proxied request is never retried directly.
- **Allowlist forward proxy (library component).** `opsec.ForwardProxy` is a local HTTPS `CONNECT` proxy that denies by default, requires an allowlist, validates every target before connecting, connects to the validated IP, requires a bearer token for non-loopback binds and fails closed when its upstream is unreachable; `opsec.build_transport` refuses to hand out a direct transport when a mandatory proxy is configured. These components have unit and adversarial tests but are **not started by the CLI** (see the security document).
- **Identification and defaults.** The default connection is direct, and the User-Agent is the constant `UltimateUsernameEngine/0.1`. The engine does not hide the operator's address unless you supply a proxy.

The adversarial tests and review rounds for these controls were run only against loopback and mock targets. They are internal adversarial testing, not an external penetration test.

## Sensitive-data handling and report safety

- **What is stored.** Each run writes a SQLite journal (`results/<run-id>.sqlite` unless `--journal` is given), a full results file, an analyst document (`*.analyst.json`), a selection document (`*.selection.json`) and optionally an HTML report. These files contain the searched username, URLs and any profile fields the extractors found (display name, bio, location, links, avatar URL). Treat them as personal data. There is no built-in retention period, purge or encryption; manage and delete them yourself. `results/` is git-ignored.
- **What is not stored.** Response bodies and request headers are not written to results; attempts keep the URL, status, timings, redirect history and a SHA-256 of the body. API credentials come from environment variables at request time and are never written out.
- **Redaction.** `opsec.redaction` provides helpers that mask e-mail addresses, JWTs, bearer-style tokens and long opaque strings and reduce URLs to scheme and host. They are available to library users; the CLI does not apply them, so keep secrets out of definitions and logs.
- **Report safety.** The HTML report is a single file without JavaScript or external resources, with a `default-src 'none'` Content-Security-Policy meta tag; all third-party text is escaped and control characters are removed; links are emitted only for `http`/`https` with `rel="noopener noreferrer"`. CSV cells that start with a formula character are prefixed with an apostrophe (the JSON keeps the exact value). Exports are atomic (temporary file, `fsync`, replace).
- **Passive features.** `--dorks` only lists search-engine query text (`"sent": false`); nothing is sent. `--wayback` queries the Wayback CDX API through the engine transport with its own budget. `--geo` is computed offline from already collected metadata.
- **Images.** `--identity-images` downloads avatars (5 MiB limit, public hosts only) and compares perceptual hashes; it needs Pillow, which is not installed by default.

## Installation

```bash
cd ULTIMATE_USERNAME_ENGINE
python -m venv .venv
# Linux/macOS: source .venv/bin/activate     Windows: .venv\Scripts\activate
python -m pip install -e ".[dev]"      # add ,socks for SOCKS proxy support
```

`requirements-tested.txt` pins the main package versions used in validation; it is not a full lock file of transitive dependencies. `requirements-lock-windows-py314.txt` records the complete environment of the maintainer's Windows / Python 3.14 setup. An editable install is recommended because the default catalogue path is resolved relative to the source tree.

## Rebuilding the catalogue

The site catalogue `data/catalog.json` (about 8,900 definitions) and the raw import records are **not published**: they are derived from third-party data (see "Data licensing"), and the raw import records also contained a third-party token. Without the catalogue, `search` has nothing to run; `demo` and the offline tests do not need it. Rebuild it locally from donor snapshots:

1. Obtain local clones or snapshots of the donor projects, laid out as the importer expects under one directory:

   ```
   <donors>/maigret/maigret/resources/data.json          (github.com/soxoj/maigret)
   <donors>/sherlock/sherlock_project/resources/data.json (github.com/sherlock-project/sherlock)
   <donors>/whatsmyname/wmn-data.json                     (github.com/WebBreacher/WhatsMyName)
   <donors>/blackbird/data/wmn-metadata.json              (github.com/p1ngul1n0/blackbird)
   ```

2. Optionally compare the SHA-256 of the three data files with `data/import-summary.json`, which records the digests of the snapshots used for the original import. Different donor versions are accepted but produce a different catalogue (counts and definition identifiers may differ), and the shipped `data/health.json`, which is keyed by definition identifier, then matches only partly.
3. Run the importer (offline; it reads files and makes no requests):

   ```bash
   python tools/import_catalogs.py --donors /path/to/donors        # writes to ./data by default
   python -m ultimate_username validate data/catalog.json
   ```

   It writes `catalog.json`, `import-records.json`, `conflicts.json`, `blackbird-metadata.json` and `import-summary.json` into `data/`, and **overwrites** `import-summary.json` and `IMPORT_REPORT.md` (the Polish import report); keep copies if you want to compare.

With the donor snapshots recorded in the shipped `import-summary.json`, the import yields 8,956 executable definitions (Maigret 7,814, Sherlock 455, WhatsMyName 687), 756 conflict groups and 17 Blackbird metadata rules. Definitions are not merged automatically: conflicting variants keep separate identifiers (`donor:hash-of-name`). The loader also reads `data/osint_custom.json` (16 definitions calibrated by the maintainer) when the catalogue file is named `catalog.json`.

## Usage

All examples use the synthetic username `alice`. Commands that contact real sites send requests to third-party systems; run them only when you are authorised to.

```bash
# Offline demonstration with fixtures (no network, no catalogue needed)
username-engine demo alice --site found --output -

# Quick, cheap pass: at most 50 requests, no retries or fallbacks
username-engine search alice --mode quick --output results/alice.json

# Default mode with an HTML report and only the matches in the analyst view
username-engine search alice --output results/alice.json --html results/alice.html --only-matches

# Deeper scan with follow-up enrichment requests to declared public APIs
username-engine search alice --mode deep --enrich full --output results/alice.json

# Through a SOCKS5 proxy (requires the socks extra)
username-engine search alice --proxy socks5://127.0.0.1:9050 --output results/alice.json

# Optional layers (all off by default): variants, dorks, archive lookups, country clues, identity
username-engine search alice --variants --dorks --wayback --geo --identity \
    --seed-name "Alice Example" --seed-url https://example.com/alice --output results/alice.json

# Render an HTML report from an existing analyst document (no requests)
username-engine report results/alice.analyst.json --html results/alice.html

# Validate a registry without HTTP
username-engine validate data/catalog.json
```

`python -m ultimate_username ...` is equivalent to `username-engine ...`. Outputs: `alice.json` (full results; `--format json|ndjson|csv`, `--output -` writes to stdout), `alice.analyst.json` (profiles, summary, `NOT_TESTED` accounting, request economy), `alice.selection.json` (the selection plan with scores) and the journal. `--view debug` prints the full observation chain. `--site ID` restricts the run to specific definitions and `--selection all` disables canonical deduplication and fallbacks (diagnostics only).

Exit codes: `0` completed without execution errors; `1` partial result or service errors (normal for broad scans); `2` configuration or output error; `3` health data refused (`health-probe` / `health-passive` when too many ratings are dead or blocked, unless `--force`); `130` interrupted (committed observations stay in the journal).

The library API (`UsernameEngine.search`, `search_stream`, `search_sites`, `search_many`) is shown in [`examples/offline.py`](examples/offline.py).

## Testing

```bash
cd ULTIMATE_USERNAME_ENGINE
python -m pytest
python -m pytest tests/opsec          # egress-control tests only; no catalogue needed
python tools/check.py                 # ruff, ruff format --check, mypy --strict, pytest (see note)
```

The suite is configured for offline operation: `tests/conftest.py` fails any test that opens a non-loopback socket or resolves a non-local name, and HTTP tests use local servers. The pytest session also writes `artifacts/test-results.json`. Some tests need the rebuilt catalogue, and the fixture suites `tests/golden_detection` and `tests/recall_detection` (captured real profile pages) are not published, so tests that depend on them may be skipped or fail in a fresh checkout. `tools/check.py` additionally expects artifacts that are not published and can fail for that reason. The benchmark harness has its own tests (`python -m pytest bench/tests` from the project directory); one of them imports a sampling helper that is not published.

## Data licensing

- **Site definitions.** The catalogue is derived from Maigret (MIT), Sherlock (MIT) and WhatsMyName (CC BY-SA 4.0), plus 17 metadata rules from Blackbird's `wmn-metadata.json` (check the licence of the snapshot you use). The importer converts them offline and records the SHA-256 of each source file. The converted catalogue and the import records are not redistributed here. If you redistribute a catalogue you built, the upstream terms apply to it: attribution for the MIT-licensed data and attribution plus share-alike for WhatsMyName-derived entries.
- **Code lineage.** Components were written or adapted with reference to the donors' designs; [`docs/COMPONENT_TRACEABILITY.md`](docs/COMPONENT_TRACEABILITY.md) states for each component which donor symbol it follows and whether it was rewritten or adapted. The importer does not import or run donor code.
- **Shipped data.** `data/health.json` holds the project's own passive health ratings of definitions (derived from earlier scan results; no extra requests), `data/osint_custom.json` holds 16 definitions maintained by the project, and `data/import-summary.json` holds import counts and source digests.
- **This project's code.** Its licence is given at the repository root; this directory contains no separate licence file.

## Limitations

- **Coverage is bounded by the catalogue and the budget.** Definitions age and sites change. A small budget tests a ranked fragment; results do not describe "the internet".
- **Many definitions can only abstain.** Imported rules without a profile-specific signal yield at most `PROBABLE`, and status-only rules often yield `UNKNOWN`. Pages that are JavaScript shells or identical for any name cannot be decided without rendering or a platform API; the engine has no browser and executes no JavaScript.
- **Blocks are reported, not bypassed.** There is no CAPTCHA solving, session transfer, browser impersonation or proxy rotation. A meaningful share of a full scan ends in `BLOCKED`, `RATE_LIMITED` or `ERROR`.
- **Identity is weak.** Only a minority of hits expose any identity field and cross-links are rare; the identity score failed its benchmark gate (see the benchmark document). Treat `TARGET_LIKELY` as a hint.
- **Measured quality is limited.** The benchmark set is small, labelled by LLM agents and drawn with a stratified design; recall of the engine was lower than that of the earlier engine on the same holdout. See [BENCHMARK.md](../docs/BENCHMARK.md) before relying on any number.
- **Outputs hold personal data and have no retention control.** See "Sensitive-data handling".
- **No** automatic catalogue updater, login handling, confidence calibration, GUI, PDF or XLSX output, or resume of an interrupted queue (the journal keeps committed observations only). `.onion` hosts need an explicit proxy; the SOCKS and `.onion` paths were not validated against a real gateway. Templates that change the hostname are rejected.
- **Cost.** In `exhaustive` mode one username costs thousands of requests (see the benchmark document). The journal commits with SQLite WAL and `synchronous=NORMAL`: an operating-system crash or power loss can drop the last rows.

## Roadmap

Planned (not implemented). These items are recorded in the project's own documents; none is a commitment.

- Controlled responses of real test accounts with selectors assigned to them, an owner-aware parser for Patreon campaign pages, and a supervised pool of parser processes that can terminate a hung parser (`IMPLEMENTATION_STATUS.md`, section NEXT).
- Automatic reuse of earlier results (resume and cache with a freshness policy, a username + canonical service + revision key and a shorter TTL for negatives), and enabling health-based ranking of definitions only after enough independent observations exist (`BUDGET_ARCHITECTURE.md`, `FALLBACK_ARCHITECTURE.md`).
- Platform adapters or JavaScript rendering for platforms whose pages are shells, a filter for default avatars, and additional ground-truth usernames for evaluating identity (the maintainer's internal reports; not published). Some adapter and extended-OPSEC work exists on branches that are not part of this release.
