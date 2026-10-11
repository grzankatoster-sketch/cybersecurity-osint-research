# Projects

Three independently developed projects. Each section separates **implemented** capabilities
(verified against the code) from **planned** work. Test results are in [README.md](README.md#validation-status).

---

## 1. OSINT Toolkit

**Path:** [`projects/osint-toolkit/`](projects/osint-toolkit/) · **Language:** Python 3.12+ (mostly standard library) ·
**Status:** working tools with offline test suites; developed October 2026.

A set of small, single-purpose tools for defensive open-source intelligence and attack-surface
review, plus a case graph that correlates their outputs with provenance.

### Implemented

| Area | Package | Capabilities |
|---|---|---|
| Defensive DNS & mail security | `dns-audit` | A/AAAA, NS, SOA, MX (provider detection), CAA; SPF parsing with recursive lookup counting against the limit of 10; DMARC policy; DKIM selector probing and RSA key length; DNSSEC (DNSKEY/DS, AD flag, algorithms); MTA-STS, TLS-RPT, BIMI; recognition of service-verification TXT records; optional DoH over SOCKS5 with fail-closed preflight |
| Website configuration audit | `site-audit` | Redirect chain, TLS, security headers, cookies, `security.txt`, `robots.txt`, sitemap; at most a handful of GET requests; SSRF guard incl. IPv6-embedded IPv4, pinned IPs, per-hop redirect checks, hard time budget with watchdog; sitemap XML parsed with DTD/entities refused |
| Infrastructure intelligence | `net-intel` | IP context, domain RDAP, passive subdomain enumeration (certificate transparency and public datasets); never contacts the target; refuses non-public IPs; does not read RDAP contact data |
| Breach exposure monitoring | `hibp-monitor` | Have I Been Pwned: new breaches for own domains, breach catalogue, k-anonymity password check, optional paid domain search; API key bound to the HIBP host over HTTPS/443; redirects refused |
| Phone-number hygiene | `phone-check` | Offline validation and numbering-plan metadata (`phonenumbers`); no lookup of the subscriber |
| Image metadata / OPSEC | `exif-map` | EXIF/GPS inspection, HTML map, lossless JPEG metadata stripping with post-write verification, hardened `exiftool` arguments |
| Provenance registry | `org-intel` | Companies, domains, public persons and publicly described incidents; every entity needs a sourced observation; rejects leaked-data sources and raw secrets; offline by default |
| Entity correlation | `entity-graph` | Case store, evidence vault, importers for all toolkit outputs, correlation with evidence levels, operator decisions, hash-chained audit log, GraphML / Maltego CSV / HTML export, fail-closed proxy for profile search |
| Connector framework | `osint-connectors` | Clean-room plug-in contract (registry, uniform result record, async fan-out, per-module error isolation), HMAC subject references; frozen prototype |
| Official-API search | `meta-search` | Threads, Instagram Business Discovery and Facebook Pages via official Meta APIs only; token redaction; pinned fail-closed proxy; purge command |
| AI-assistant integration | `osint-mcp` | MCP server (FastMCP, stdio) exposing only infrastructure tools (DNS, IP, phone validation, own breach exposure); input validation, no shell |
| Operator UI | `panel` | Loopback web panel orchestrating the CLIs; session token, strict request typing, path-safe report handling, CSP |
| Reproducible environment | `osint-env` | Disposable Docker toolbox with a single writable mount |
| Pipeline assurance | `ci` | Repository-hygiene gates (no `.env`, no case data), per-package tests, lint, E2E with network blocked twice and environment scrubbed |

**OSINT methodology.** Passive sources first; a hit is a lead, not proof; at least two independent
correlations before treating records as related; every fact keeps its source; error and block are
never reported as absence.

### Not published / planned

- The `osint-poland` registry adapter (KRS / CEIDG / REGON → `org-intel`) exists privately and is not
  part of this repository.
- Planned (not implemented): background scans with resume in `panel`; per-case write locking in
  `entity-graph`; import of user-provided social-media data exports.

---

## 2. Username Engine v1

**Path:** [`projects/osint-toolkit/username-engine/`](projects/osint-toolkit/username-engine/) ·
**Language:** Python 3.12+, `aiohttp`, `aiohttp-socks` · **Status:** working; used by the toolkit integration.

An asynchronous username scanner over a locally built catalogue (WhatsMyName + Maigret + a small set
of manually calibrated rules).

### Implemented

- Username variant generation from a name or handle (opt-out with `--no-variants`).
- Control request with a random username per site: a rule that also "finds" a random name is turned
  into an error; a clean negative control raises confidence.
- Block / anti-bot detection reported as `ERROR`, never as absence; retries only on transport errors.
- SOCKS5/Tor channel with remote DNS, Tor preflight before any target traffic, random SOCKS
  credentials for circuit isolation, proxy circuit breaker, no unverified-TLS retry through a proxy,
  resolver that blocks private addresses.
- Profile field extraction, offline country inference (GeoNames), evidence-level correlation across
  variants, search-engine dork links, Wayback lookups.
- HTML / CSV / JSON reports with escaping and CSV formula neutralisation; 12-hour retention purge.

### Limitations

Coverage is bounded by the catalogue; upstream catalogues are fetched unpinned (see SECURITY.md
OPEN-09). No roadmap is documented for v1; development continued in the Ultimate engine.

---

## 3. Ultimate Username Engine

**Path:** [`projects/ultimate-username-engine/`](projects/ultimate-username-engine/) ·
**Language:** Python 3.11+, `aiohttp`, `regex` (optional `aiohttp-socks`) ·
**Status:** working research engine; published from `main` (includes the merged extraction stage).

A precision-first username research engine with an explicit evidence model, request budgets and an
egress-control module, evaluated against a labelled holdout set.

### Implemented

- Offline, loss-accounted import of ~9,000 donor definitions (Maigret, Sherlock, WhatsMyName,
  Blackbird metadata) with conflict tracking; donor code is never executed by the importer.
- Evidence model: verdicts `FOUND / PROBABLE / NOT_FOUND / UNKNOWN`, `response_class`,
  `evidence_level`; HTTP 200 alone never yields `PROBABLE`; every block is `UNKNOWN`.
- Control requests, health-ranked definition selection, adaptive budgets and controlled fallback;
  runtime modes `quick / normal / deep / exhaustive`.
- Bounded enrichment and field extraction with filters against templates and username echoes
  (field precision 0.95 on a 40-field live sample).
- Offline identity scoring (never automatic attribution).
- Egress control (`opsec/`): host allowlist, SSRF address classes and numeric-IP spellings, guarded
  transport, optional local CONNECT proxy, redaction.
- Benchmark harness (`bench/`) with dev / holdout separation.

### Benchmark headline (holdout, existence view; details and threats to validity in [BENCHMARK.md](projects/ultimate-username-engine/docs/BENCHMARK.md))

| Engine / stage | Precision | Recall | Coverage | Requests (3 usernames, exhaustive) |
|---|---:|---:|---:|---:|
| Ultimate, baseline | 1.000 | 0.212 | 0.272 | 24,266 |
| Ultimate, after extraction stage | 1.000 | 0.779 | 0.848 | 32,583 |
| v1 (reference) | 0.980 | 0.962 | 0.980 | 31,017 |

Two development gates failed: F3 recall (0.769 < 0.80) and F4 identity (0/6 target accounts on the
holdout). The holdout is small (151 evaluated pairs), and v1 still has higher recall.

### Not published / planned

- Unmerged branches not included: extended OPSEC hardening, platform-specific adapters (phase F8), an
  e-mail engine.
- Planned (not implemented): adapters and JavaScript rendering for platforms that serve empty shells.
