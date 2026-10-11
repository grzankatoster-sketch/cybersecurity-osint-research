# Security Engineering Projects

A collection of independently developed defensive-security and OSINT engineering projects:
infrastructure and website auditing, breach-exposure monitoring, provenance-tracked entity
correlation, and evidence-based username research with egress controls.

The projects share a few engineering rules: results distinguish *not found* from *could not check*,
every stored fact carries its source, network channels fail closed, and the default behaviour is the
least intrusive one. All test suites run offline.

> **Responsible use.** Use these tools only on assets you own or are authorised in writing to assess.
> A matching username or avatar is a lead, not proof of identity. See [SECURITY.md](SECURITY.md).

**Maintainer:** [@grzankatoster-sketch](https://github.com/grzankatoster-sketch) — see [MAINTAINERS.md](MAINTAINERS.md).
**Security policy:** [SECURITY.md](SECURITY.md) · **Review report:** [docs/SECURITY_REVIEW.md](docs/SECURITY_REVIEW.md)

## Security engineering highlights

Implemented and covered by tests in this repository:

| Area | What was built | Where |
|---|---|---|
| SSRF protection | Address-class checks incl. numeric/IPv6-embedded IPv4 spellings, pinned resolution, per-hop redirect validation | `site-audit/src/site_audit/target.py`, `ultimate_username/opsec/policy.py` |
| Fail-closed proxy | Missing, failing or **misconfigured** proxy blocks traffic instead of going direct; malformed settings refuse start-up | `ultimate_username/opsec/config.py`, `transport_factory.py`, `username-engine/.../http.py` |
| Credential isolation | Catalogue entries can only reference `UEE_CRED_*` variables; the operator binds each to exact HTTPS hosts | `ultimate_username/credentials.py` |
| Subprocess isolation | Per-tool environment allowlists so host secrets never reach child processes | `osint-mcp/src/osint_mcp/runner.py`, `entity-graph/.../siblings.py` |
| Supply-chain integrity | Upstream catalogues pinned to commits and verified by SHA-256 before parsing | `username-engine/scripts/build_db.py` |
| Evidence & provenance | Four-way result status, evidence levels, sourced facts, hash-chained audit log | `org-intel`, `entity-graph`, Ultimate evidence model |
| Vulnerability remediation | Pre-publication review → 10 findings → 4 fixed + 1 partly fixed, all with regression tests (36 + 28 + 16 + 3 + 3 new tests) | [SECURITY.md](SECURITY.md#known-issues) |
| Threat modeling | Threat model and control mapping for the username engine | [SECURITY_ARCHITECTURE.md](projects/ultimate-username-engine/docs/SECURITY_ARCHITECTURE.md) |
| Security CI | gitleaks (full history), pip-audit, bandit, CodeQL, Dependabot | `.github/` |

## Projects

| Project | What it is | Key techniques |
|---|---|---|
| [**OSINT Toolkit**](projects/osint-toolkit/) | 14 small Python tools for defensive OSINT and attack-surface review, plus a case graph | DNS/mail-auth audit (SPF lookup budget, DMARC, DKIM, DNSSEC, MTA-STS); website config audit with SSRF guard and time budget; passive IP/RDAP/subdomain intel; HIBP k-anonymity checks; EXIF stripping; provenance registry; hash-chained case audit log; MCP server exposing infrastructure-only tools |
| [**Username Engine v1**](projects/osint-toolkit/username-engine/) | Asynchronous username scanner over a locally built catalogue | Random-username control requests against false positives; block detection reported as error, not absence; Tor/SOCKS5 with remote DNS, preflight and circuit breaker; evidence-level correlation; report retention |
| [**Ultimate Username Engine**](projects/ultimate-username-engine/) | Precision-first username research engine evaluated on a labelled holdout | Explicit evidence model and verdict classes; offline loss-accounted catalogue import; request budgets and fallback; egress allowlist + SSRF policy + fail-closed proxy; benchmark harness with dev/holdout separation |

Detailed descriptions, implemented vs. planned features: [PROJECTS.md](PROJECTS.md).
How the pieces fit together: [ARCHITECTURE.md](ARCHITECTURE.md).

## Quick start

Each project is self-contained and has its own virtual environment. Example (DNS audit):

```bash
git clone <repository-url> && cd security-engineering-projects/projects/osint-toolkit/dns-audit
python -m venv .venv && .venv/bin/python -m pip install -e ".[dev]"   # Windows: .venv\Scripts\python.exe
.venv/bin/python -m dns_audit example.com
.venv/bin/python -m pytest -q
```

Ultimate Username Engine (the site catalogue must be rebuilt locally from upstream sources first; see
[NOTICE.md](NOTICE.md) and the [engine README](projects/ultimate-username-engine/ULTIMATE_USERNAME_ENGINE/README.md)):

```bash
cd projects/ultimate-username-engine/ULTIMATE_USERNAME_ENGINE
python -m pip install -r requirements-tested.txt -e ".[dev,socks]"
python -m pytest -q
```

## Validation status

Test suites executed locally on 2026-10-11 (Windows 11, Python 3.14.2), from the published tree.
After the Phase 3 security fixes, the changed projects (osint-mcp, v1, Ultimate, bench, ci) were re-run;
unchanged toolkit packages keep their earlier results.
GitHub Actions has not run yet; CI also targets Ubuntu and Python 3.12/3.13.

| Project / package | Passed | Failed | Skipped | Skip reason |
|---|---:|---:|---:|---|
| toolkit · dns-audit | 166 | 0 | 0 | |
| toolkit · site-audit | 107 | 0 | 0 | |
| toolkit · net-intel | 136 | 0 | 0 | |
| toolkit · hibp-monitor | 122 | 0 | 0 | |
| toolkit · phone-check | 83 | 0 | 0 | |
| toolkit · exif-map | 78 | 0 | 0 | |
| toolkit · org-intel | 233 | 0 | 0 | |
| toolkit · entity-graph | 1002 | 0 | 3 | opt-in network test (`EG_NETWORK_TESTS=1`), `osint-poland` not published, sibling `phone-check/.venv` absent |
| toolkit · osint-connectors | 111 | 0 | 0 | |
| toolkit · meta-search | 130 | 0 | 0 | |
| toolkit · osint-mcp | 81 | 0 | 0 | |
| toolkit · panel | 329 | 0 | 0 | |
| toolkit · ci (pipeline + E2E) | 38 | 0 | 25 | registry adapter (`osint-poland`) not published |
| Username Engine v1 | 415 | 0 | 15 | site catalogue not built (12), no symlink privilege on Windows (3) |
| Ultimate Username Engine | 1627 | 0 | 19 | third-party catalogue not shipped (18), self-signed test certificate not shipped (1) |
| Ultimate benchmark harness (`bench/tests`) | 31 | 0 | 0 | |

Known caveats (details in [docs/SECURITY_REVIEW.md](docs/SECURITY_REVIEW.md)): a few Ultimate tests
with timing assertions can fail under heavy CPU load and pass in isolation; image-related tests need
Pillow, which the engine's `pyproject.toml` does not declare; `ruff` reports 38 pre-existing style
findings in the Ultimate engine (lint is non-blocking in CI).

## Security

- Security policy, implemented controls and **known open issues**: [SECURITY.md](SECURITY.md)
- Pre-publication review (secret scanning, personal-data review, dependency audit, static analysis,
  exclusions): [docs/SECURITY_REVIEW.md](docs/SECURITY_REVIEW.md)
- Ultimate engine threat model and egress controls: [SECURITY_ARCHITECTURE.md](projects/ultimate-username-engine/docs/SECURITY_ARCHITECTURE.md)
- Toolkit security and provenance rules: [SECURITY_AND_PROVENANCE.md](projects/osint-toolkit/docs/SECURITY_AND_PROVENANCE.md)

Internal adversarial testing was limited to loopback and mock services. This repository makes no
claim of external penetration testing, CVEs or third-party adoption.

## Repository notes

- Original documentation and most CLI output are in Polish; every package has an English
  `README.md` and keeps the Polish original as `README.pl.md`.
- Site catalogues derived from Maigret, Sherlock, WhatsMyName and Blackbird are **not** redistributed;
  scripts rebuild them locally. Labelled benchmark data and captured profile pages are not published.
- The repository was created with a fresh Git history.

## Adoption

Not yet established. As of 2026-10-11 the repository is new, has no stars or forks, no known
dependent repositories, no packages published to PyPI or any distribution, and is not indexed by
ecosyste.ms. (A PyPI package named `osint-mcp` exists but is an unrelated third-party project.)

## Contributing & license

See [CONTRIBUTING.md](CONTRIBUTING.md) and [MAINTAINERS.md](MAINTAINERS.md). Original code is licensed under the
[Apache License 2.0](LICENSE); third-party data and tools are described in [NOTICE.md](NOTICE.md).
