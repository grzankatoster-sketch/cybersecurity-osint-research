# Architecture

This document describes how the repository is organised, the design principles shared by the
projects, and the data flow inside each of them. Package-level details live in each project's
README; the Ultimate Username Engine has dedicated
[design documents](projects/ultimate-username-engine/ULTIMATE_USERNAME_ENGINE/docs/design/).

## 1. Repository layout

```
security-engineering-projects/
├── .github/                      CI: tests, security (gitleaks, pip-audit, bandit), CodeQL, Dependabot
├── docs/SECURITY_REVIEW.md       pre-publication review results
├── projects/
│   ├── osint-toolkit/            defensive OSINT and attack-surface tools (one Python project per package)
│   │   ├── dns-audit/  site-audit/  net-intel/  hibp-monitor/
│   │   ├── phone-check/  exif-map/  org-intel/  entity-graph/
│   │   ├── osint-connectors/  meta-search/  osint-mcp/  panel/
│   │   ├── username-engine/      Username Engine v1 (independent project; nested here because
│   │   │                         panel and entity-graph launch it as a sibling directory)
│   │   ├── osint-env/            disposable Docker environment
│   │   ├── narzedzia/            launchers for separately installed third-party tools
│   │   ├── ci/                   offline pipeline checks + E2E tests
│   │   └── docs/                 cross-package security and provenance rules
│   └── ultimate-username-engine/
│       ├── ULTIMATE_USERNAME_ENGINE/   the engine package (src/, tests/, tools/, docs/)
│       ├── bench/                      benchmark harness (labelled data not published)
│       └── docs/                       benchmark and security architecture
└── README.md  PROJECTS.md  SECURITY.md  ARCHITECTURE.md  CONTRIBUTING.md  LICENSE  NOTICE.md
```

Each Python package keeps its own `pyproject.toml`, tests and virtual environment. There is no
shared library: where packages need the same helper (input validation, normalisation, redaction),
it is copied and hardened locally so that every stage validates its own input. The few runtime
couplings are explicit and documented (section 3).

The original directory names were kept (`ULTIMATE_USERNAME_ENGINE/`, `narzedzia/` = "tools") because
scripts and tests resolve sibling paths relative to them.

## 2. Shared design principles

1. **Four-way result status, never collapsed.** Tools distinguish *found*, *no result* (the source
   answered and found nothing), *error* (tool, proxy or source failed: result unknown) and *blocked*
   (rate limit, CAPTCHA, login wall, missing key). An error or block is never reported as absence.
   The Ultimate engine expresses the same idea as verdicts `FOUND / PROBABLE / NOT_FOUND / UNKNOWN`
   with every block mapped to `UNKNOWN`.
2. **Provenance for every fact.** Stored observations carry source, evidence location, timestamp,
   confidence and inference type (`org-intel`, `entity-graph`). Records without a source are
   rejected, not silently imported.
3. **Least intrusive default.** Offline by default where possible (`org-intel`, `phone-check`,
   `exif-map`, importers); passive public sources before touching a target; a small, bounded number
   of ordinary GET requests when a target must be contacted (`site-audit`).
4. **Fail closed on the network channel.** If the configured proxy/Tor channel is missing or fails,
   the tool refuses to send traffic instead of falling back to a direct connection.
5. **Evidence over coincidence.** A matching username is not an identity. Correlation is expressed
   as evidence levels, and identity attribution is never automatic.
6. **Bounded resource use.** Request budgets, time budgets with watchdogs, body-size caps and regex
   complexity limits protect both the operator and the targets.

## 3. OSINT Toolkit data flow

```
                         ┌────────────── passive public sources / target (bounded) ──────────────┐
 dns-audit  site-audit  net-intel  hibp-monitor  phone-check  exif-map  meta-search  username-engine
     │          │           │           │            │           │           │             │
     └──────────┴───────────┴─── JSON / CSV outputs ─┴───────────┴───────────┴─────────────┘
                                          │
                                          ▼
 org-intel (provenance registry) ──► entity-graph ──► graph.json · GraphML · Maltego CSV · HTML report
                                      (case store,         audit.jsonl (hash-chained)
                                       importers, decisions)

 osint-mcp ──► MCP client         exposes dns-audit, net-intel, phone-check, hibp-monitor only
 panel     ──► browser (loopback) orchestrates the CLIs as sub-processes with scrubbed environments
 ci/run_checks.py                 hygiene gates, per-package tests, lint, E2E with network blocked
```

- `entity-graph` auto-detects tool outputs by content and imports them offline. It launches
  `username-engine`, `dns-audit` and `phone-check` as sub-processes from their own environments, and
  imports `hibp-monitor` and `osint-connectors` as libraries.
- `osint-mcp` intentionally exposes nothing person-oriented.
- The original pipeline started with an `osint-poland` adapter for Polish company registries
  (KRS / CEIDG / REGON). That package is **not published**; the dependent CI stage skips itself.

## 4. Username Engine v1

```
CLI ─► variants (name → candidate usernames) ─► sources (catalogue: WhatsMyName + Maigret + custom rules)
    ─► engine (async scheduling, control request with a random username, retries on transport errors)
    ─► http (SOCKS5/Tor channel with remote DNS, preflight, circuit breaker, SafeResolver)
    ─► classify (FOUND / NOT_FOUND / ERROR / UNSUPPORTED, block detection)
    ─► extract · geo · correlate (evidence levels) · dorks · Wayback
    ─► report (HTML / CSV / JSON, escaping, CSV formula guard) ─► retention (12 h purge)
```

## 5. Ultimate Username Engine

```
planning ─► scheduling ─► transport ─► detection ─► evidence ─► enrichment / extraction ─► identity ─► reporting
(registry,   (budgets,     (aiohttp,    (rules +     (evidence    (bounded extra           (offline     (analyst JSON,
 health,      modes,        GuardedTrans- control     levels,      requests, field          scoring,     HTML report
 selection)   fallback)     port, opsec)  request)    response     filters)                 never        with CSP,
                                                      class)                                automatic)   storage)
```

- **Catalogue import** (`tools/import_catalogs.py`, `importers.py`) converts donor definitions
  offline, records every loss and conflict, and never executes donor code.
- **Runtime modes** `quick / normal / deep / exhaustive` set per-username request budgets; health
  data (`data/health.json`) ranks definitions; a controlled fallback is used when the primary
  definition is blocked or dead.
- **Egress control** (`opsec/`): allowlist and SSRF policy, guarded transport, optional local
  CONNECT forward proxy with fail-closed validation, log redaction. Known gaps are listed in
  [SECURITY.md](SECURITY.md#known-issues).

## 6. CI architecture

| Workflow | Purpose |
|---|---|
| `tests.yml` | Per-package pytest matrix (Ubuntu + Windows, Python 3.12/3.13) for the toolkit; connectors, panel and pipeline checks; Ultimate engine tests, lint and benchmark-harness tests |
| `security.yml` | gitleaks over full history, pip-audit for projects with runtime dependencies, bandit (fails on high-severity/high-confidence findings) |
| `codeql.yml` | CodeQL `security-extended` queries for Python |
| `dependabot.yml` | Weekly updates for GitHub Actions and pip manifests |

All tests are designed to run without network access; tests that would need excluded data
(third-party catalogue, captured profile pages, registry adapter) skip themselves with an explicit
reason.
