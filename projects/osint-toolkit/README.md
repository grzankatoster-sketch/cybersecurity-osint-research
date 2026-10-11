# OSINT Toolkit

A set of small, mostly standard-library Python tools for defensive open-source intelligence and attack-surface review, built around three ideas: every result carries a status that distinguishes "not found" from "could not check", every stored fact carries provenance, and the default behaviour is the least intrusive one (offline, passive, minimal data).

> Each package has an English `README.md` and the original Polish `README.pl.md`. Command output and reports are mostly in Polish. Cross-package security rules: [docs/SECURITY_AND_PROVENANCE.md](docs/SECURITY_AND_PROVENANCE.md) (Polish original: [docs/BEZPIECZENSTWO_I_PROWENIENCJA.md](docs/BEZPIECZENSTWO_I_PROWENIENCJA.md)).

## Responsible use

Use these tools only on assets you own or are explicitly authorised in writing to assess, and for purposes you can document. A hit is a lead, not proof: an identical username, display name, avatar or domain does not establish that two records belong to the same person or organisation. Several tools were designed to refuse or to omit capabilities that enable harm (reverse phone lookup, circumventing blocks, scraping, processing leaked data, enumerating accounts on third-party services); see "Data handling and privacy boundaries" in each package README. None of this is legal advice; data-protection law (for example GDPR) can apply to "public" data as well.

## Packages

| Package | Purpose | Network behaviour | Runtime dependencies |
|---|---|---|---|
| [`dns-audit`](dns-audit/) | DNS and mail-authentication audit (SPF, DMARC, DKIM, DNSSEC, MTA-STS, CAA); optional DoH over SOCKS5 | Passive public sources: public DNS records of the audited domain via a resolver (or DoH through a proxy) | `dnspython` |
| [`site-audit`](site-audit/) | Web site configuration audit (redirects, TLS, security headers, cookies, `security.txt`, `robots.txt`, sitemap) | Touches the target: a handful of ordinary GET requests, with SSRF guard and time budget | none |
| [`net-intel`](net-intel/) | IP context, domain RDAP, passive subdomain enumeration | Passive public sources (ipinfo.io, RDAP, HackerTarget, Cert Spotter, crt.sh); does not contact the target | none |
| [`hibp-monitor`](hibp-monitor/) | Have I Been Pwned: new breaches for own domains, breach catalogue, k-anonymity password check, optional paid domain search | Passive public sources (official HIBP APIs) | none |
| [`phone-check`](phone-check/) | Phone-number validation and numbering-plan metadata | Offline | `phonenumbers` |
| [`exif-map`](exif-map/) | Photo metadata and geotag inspection, map, metadata stripping | Offline (a generated map loads tiles and libraries from third parties when opened in a browser) | `Pillow`, `folium` (optional `pillow-heif`, external `exiftool`) |
| [`org-intel`](org-intel/) | Provenance-enforcing registry of companies, domains, public persons and publicly described incidents | Offline by default; `--online` only for the public HIBP catalogue and a DoH TXT check | none |
| [`entity-graph`](entity-graph/) | Case graph with evidence, correlation, operator decisions, audit log; importers for the other tools | Importers offline; `run` transforms use passive public sources and, for `username_scan`, request public profile URLs on many sites; optional Brave Search API | none |
| [`osint-connectors`](osint-connectors/) | Clean-room connector contract and runner (frozen prototype) | None by itself; reference connectors are offline, Gravatar (public endpoint) or Brave Search (official API) | none (`httpx` optional) |
| [`meta-search`](meta-search/) | Threads, Instagram Business Discovery and Facebook Pages via official Meta APIs | Official APIs with the operator's own tokens (pinned proxy supported) | none |
| [`osint-mcp`](osint-mcp/) | MCP server exposing a defensive, infrastructure-only subset | Inherits from the tools it calls | `mcp` |
| [`panel`](panel/) | Local web panel that orchestrates the tools | Local server on loopback; network behaviour is that of the tools it launches | none |
| [`osint-env`](osint-env/) | Disposable Docker environment for the toolkit and a few third-party tools | Depends on what is run inside; image build needs network access | Docker Desktop |
| [`ci`](ci/) | Offline checks and an E2E test of the data pipeline | Offline (network blocked in tests) | `pytest`, `ruff` |
| [`narzedzia`](narzedzia/) | Launchers for locally installed third-party tools (theHarvester, BBOT, SpiderFoot, dig, ExifTool, Maigret); the tools are not in this repository | Depends on the tool; active modes touch the target | third-party tools (not included) |
| [`username-engine`](username-engine/) | Username scan across many sites (documented in its own README) | See its README | See its README |

## How the packages fit together

```
 phone-check ─┐
 dns-audit ───┤
 hibp-monitor ┤  JSON / CSV outputs ──►  entity-graph  ──►  graph.json, GraphML, Maltego CSV,
 exif-map ────┤  (importers/)              (case, audit      SVG, HTML report, audit.jsonl
 meta-search ─┤                              log, decisions)
 username-engine┤
 org-intel ───┘  (export JSON or store.json via `import-org-intel`)

 net-intel, dns-audit, phone-check, hibp-monitor ──►  osint-mcp  ──►  MCP client (e.g. an AI assistant)
 all CLI tools + entity-graph ──►  panel (browser UI; sub-processes from each tool's own .venv)
 pipeline packages ──►  ci/run_checks.py (hygiene, tests, lint, artefact scan; E2E with the network blocked)
```

- **Packages do not import each other** (with documented exceptions: `entity-graph` imports `hibp-monitor` and `osint-connectors` and launches `username-engine`, `dns-audit` and `phone-check` as sub-processes from their own environments). Validation and normalisation helpers are copied and hardened rather than shared, so each stage validates its input independently.
- **entity-graph** auto-detects tool outputs by content (not by file name). Importers are offline, never raise confidence above what the source states, and report unrecognised or oversized files as `SKIPPED` and damaged ones as `ERROR` without stopping.
- **org-intel -> entity-graph.** `org-intel` is the provenance gate for company and incident data; `entity-graph import-org-intel` re-validates, enforces per-source-type host rules, skips natural persons entirely and supports `--dry-run`, `--strict` and `--report`.
- **osint-mcp** runs `dns-audit`, `phone-check`, `hibp-monitor` and `net-intel` as sub-processes and deliberately exposes nothing person-oriented.
- **panel** adds a session token, a `Host` check, strict request typing and path-safe report and case handling in front of the same CLIs, and keeps the network channel explicit.
- **ci** runs the pipeline packages' test suites, repository-hygiene gates and an E2E test whose sub-processes run with network access blocked and environment variables that could enable network features removed.

### Not published: the `osint-poland` registry adapter

The original pipeline began with an `osint-poland` adapter that turned official Polish registry data (KRS / CEIDG / REGON) into the `org-intel` input format. **That package is intentionally not published.** Consequences in this repository: `org-intel` accepts its own JSON format and HIBP catalogue files directly; `entity-graph` still contains an importer for the file formats that adapter produced; and the CI E2E stage that depends on the adapter is **skipped automatically** (`ci/tests/conftest.py`, `ci/run_checks.py`). Some documents (notably `docs/SECURITY_AND_PROVENANCE.md`) describe the pipeline as it was with the adapter present.

## Installation

There is no single installer: each package is a self-contained project with its own `pyproject.toml` and its own virtual environment. The tools that call each other (`entity-graph`, `osint-mcp`, `panel`) look for `.venv` inside the sibling directories.

Python 3.12+ is expected (`osint-connectors` declares 3.11+).

Install every Python package that has a `pyproject.toml` (POSIX shell shown; on Windows use the `START_*.cmd` launchers, which create `.venv` on first run):

```bash
cd /path/to/security-engineering-projects/projects/osint-toolkit
for p in dns-audit site-audit net-intel hibp-monitor phone-check exif-map org-intel entity-graph \
         meta-search osint-mcp username-engine; do
  (cd "$p" && python -m venv .venv && ./.venv/bin/python -m pip install -e ".[dev]")
done
(cd osint-connectors && python -m venv .venv && ./.venv/bin/python -m pip install -e . pytest)
```

Notes:
- `.venv/bin/python` is `.venv\Scripts\python.exe` on Windows.
- `osint-connectors` has no `dev` extra, hence the separate line.
- `meta-search` and `username-engine` declare no `[build-system]`; `pip install -e ".[dev]"` still works through pip's setuptools fallback (verified with pip 26.2 on Python 3.14). `panel` has no `pyproject.toml`: run `python app.py` from its directory.
- `username-engine` needs its site catalogue built before a real scan; see its README.
- `narzedzia` contains launchers only; the third-party tools are installed separately. `osint-env` builds a Docker image instead.

## Running the checks

```bash
cd projects/osint-toolkit
python -m pip install -r ci/requirements.txt
python ci/run_checks.py            # hygiene, per-package tests, lint, (with --artifacts) artefact scan
```

Each package also documents its own pytest command.

## Configuration

Configuration is by environment variables and local files outside the repository; each package README lists the variable names it reads. No credential is read from a file inside the repository tree by the tools that handle API keys (`meta-search`, `entity-graph`), and the CI hygiene gate blocks `.env` files from being committed.

## Documentation

- [docs/SECURITY_AND_PROVENANCE.md](docs/SECURITY_AND_PROVENANCE.md): data sources, lawful-use limits, provenance model, offline/online behaviour, exit codes, fail-closed rules, audit log, HIBP limitations, secret handling.
- `README.md` in every package (English) and `README.pl.md` (Polish original).
