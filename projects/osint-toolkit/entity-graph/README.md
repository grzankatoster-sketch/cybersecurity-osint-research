# entity-graph

An evidence-first link-analysis tool for authorised OSINT work. It assembles the results of small, single-purpose "transforms" and of imported tool outputs into one case graph (JSON, GraphML, Maltego-style CSV, SVG, standalone HTML report), keeps the evidence behind every edge, and writes a hash-chained audit log. Operator decisions (confirm / reject a profile or a relation claim) are explicit, recorded and separate from automated confidence.

> A Polish version of this document (much longer, with the full command reference) is in [README.pl.md](README.pl.md). The tool-category catalogue [CATALOG.md](CATALOG.md) is Polish only. CLI output and reports are in Polish. Cross-package rules: [`../docs/SECURITY_AND_PROVENANCE.md`](../docs/SECURITY_AND_PROVENANCE.md).

**Purpose.** Your own domains, addresses and accounts, or research under a documented mandate. It is not a tool for establishing who a third party is: a hit is a lead, not proof.

## Security use cases

- Attack-surface mapping of an organisation you are authorised to assess: domain, DNS, RDAP, certificate-transparency subdomains, IP context, open-port intelligence from Shodan InternetDB.
- Due diligence on companies from register-derived data via the `org-intel` importer (legal entities only; natural persons are not imported there).
- Correlating the outputs of the sibling tools (username-engine, dns-audit, hibp-monitor, phone-check, exif-map, meta-search, org-intel) into one auditable graph.
- Case hygiene for person-related research: candidates stay hypotheses until an operator confirms them with a stated reason; all decisions land in the audit log.

## How it works

Seeds (IP, domain, e-mail, username, person name, phone, URL) are expanded by transforms to a bounded depth; edges carry confidence in [0, 1] and an evidence string. Every transform returns one of four statuses: `FOUND`, `NOT_FOUND`, `UNKNOWN`, `ERROR`; a network error is never converted into `NOT_FOUND`.

| Area | Modules |
|---|---|
| Model and normalisation | `model.py`, `normalize.py`, `identifiers.py` |
| Engine and transforms | `engine.py`, `transforms/` (`ip_rdap`, `ip_asn`, `ip_rdns`, `ip_internetdb`, `dns_audit`, `domain_rdap`, `domain_crtsh`, `email_domain`, `email_classify`, `email_idn`, `email_gravatar`, `email_hibp`, `username_scan`, `person_candidates`, `phone_metadata`, `url_host`) |
| HTTP and sibling tools | `http.py`, `siblings.py`, `vault.py` (evidence vault) |
| Guardrails and audit | `guardrails.py` (purpose requirement, hash-chained `AuditLog`, `verify_audit`) |
| Importers (offline) | `importers/` for dns-audit, exif-map, hibp-monitor, meta-search, org-intel, phone-check, username-engine, an `osint-poland`-format importer, and entity-graph's own `graph.json` |
| Correlation and evidence | `correlate.py`, `links.py`, `evidence.py`, `expand.py`, `kandydaci.py` |
| Case workflow | `sprawa.py`, `teczka.py`, `relacje.py`, `telefon.py`, `polacz.py`, `profile_discovery.py`, `profile_urls.py`, `profile_analyzer.py`, `asystent.py` |
| Output | `export.py` (GraphML, Maltego CSV, HTML), `kropki.py` (SVG) |

Main commands (`python -m entity_graph <command>`, alias `eg`): `run`, `polacz` (offline merge of existing outputs), `export`, `kropki`, `przeglad` / `potwierdz` (profile decisions), `relacja` / `relacja-potwierdz` (relation claims), `telefon`, `kandydaci`, `szukaj-profili` (Brave Search API, optional), `material-profilu`, `rozszerz` (evidence-driven record expansion), `sprawa`, `asystent`, `dziennik`, `import-org-intel`, `transforms`, `audit-verify`, `evidence-verify`.

Correlation is deliberately conservative (`correlate.py`, `evidence.py`): person nodes are never merged; a `same_person` edge arises only from explicit signals (mutual profile links, shared e-mail, shared own website, matching display name plus avatar hash), copyable fields count as one dependent group, and the result is capped by the weakest account's confidence.

## Implemented security mechanisms

- **Mandatory stated purpose.** Nothing runs without `--purpose` (at least 2 words and 12 characters; placeholders such as "test" are rejected) (`validate_purpose` in `guardrails.py`).
- **Hash-chained audit log.** `audit.jsonl` is append-only JSONL; each entry contains the SHA-256 of the previous line; the first entry is written before any request and the investigation does not start if it cannot be written; `audit-verify` detects an altered or removed middle entry (`AuditLog`, `verify_audit`). It does not protect against deletion of the whole file or silent change of the last entry.
- **Evidence vault.** In `run`, raw source responses (including 404/429/5xx and network errors) are stored with SHA-256 in `evidence/` by default (`--no-evidence` disables it); request headers are never stored, and `evidence-verify` cross-checks the files against both the index and the audit chain (`vault.py`).
- **Fail-closed proxy channel for profile search.** `eg szukaj-profili` goes only through one configured HTTP proxy; if the proxy is required but missing or unreachable it sends nothing; a mid-run proxy failure stops the run with no direct connection. A required proxy is the default whenever `OSINT_PROXY` is set; `BRAVE_REQUIRE_PROXY` turns the requirement off only for explicit false-like values. Proxy credentials never reach messages, audit log or report (`profile_discovery.py`; behaviour documented in the pipeline security document).
- **Secret scrubbing for sub-processes.** Sibling tools run with an environment stripped of variables whose names match KEY/TOKEN/SECRET/PASSWORD/PASSWD/CREDENTIAL, with `stdin` closed (`siblings.py`). The Brave key reaches only the request header of the search connector; a key file inside the repository tree is rejected (`profile_discovery.py`).
- **HTTP client limits.** Per-host rate limit, 5 MB response cap, redirects only to http/https, bounded `Retry-After`, honest User-Agent; blocks (401/403/429) are reported as `ERROR` and never circumvented (`http.py`).
- **Importers are offline and non-escalating.** They never raise confidence above what the source stated and never convert `ERROR` into "no data"; files over 50 MB are skipped; at most 2000 files per run (`importers/base.py`, `importers/__init__.py`).
- **Hardened `import-org-intel`.** Per-source-type host allowlists, HTTPS-only/port-443, rejection of IP-literal and internal hosts, leak-forum/paste hosts and URLs with credentials; secret-pattern and hash-like value rejection; persons skipped entirely; e-mail masking in text fields; `--dry-run`, `--strict` and `--report` with strict output-path rules; idempotent re-import (`importers/org_intel.py`, `cli.py`).
- **Output safety.** The HTML report has no JavaScript or external resources, a `default-src 'none'` CSP, escaped third-party text and `rel="noopener noreferrer nofollow"` links (`export.py`); the SVG is script-free and escaped (`kropki.py`). The Maltego CSV never exports Email nodes, replaces e-mail addresses with a marker, replaces cells containing secrets, neutralises spreadsheet formulas, does not overwrite existing files without `--force`, and refuses case-file names (`export.py`).
- **Local-only assistant.** The optional AI helper talks to Ollama only on a loopback address, receives counts and step numbers rather than case content, has its reply filtered, and writes only a hash of the answer to the audit log (`asystent.py`).
- **Safe case sources.** A claim source is an http(s) URL without credentials or a `dokument:` path to a file already inside the case directory; only its path, SHA-256 and size are recorded (`sprawa.py`).
- **Bounded expansion.** Hard limits on nodes and runs; budgets for queries, time and cost in `rozszerz`, `kandydaci` and `szukaj-profili`; a `STOP` file halts expansion.
- **Out by design.** No reverse phone lookup (caller-ID style services), no CAPTCHA or login circumvention, no IP rotation, no fingerprint spoofing, no search-engine scraping, no IP-based geolocation of people (`EXCLUDED_CAPABILITIES` in `guardrails.py`; a test guards the phone rule).

## Data handling and privacy boundaries

- Case directories (`graph.json`, `audit.jsonl`, reports, documents) hold whatever the operator entered; if a person is the subject, that is personal data. Retention is manual: delete the case directory when the purpose ends.
- Profiles are reduced to minimal fields (URL, display name, avatar hash, website, links, entity type, bio fingerprint of hashed word tokens); bio text and location are not carried. Operator-supplied profile material is analysed in memory and only findings with literal evidence plus a hash are stored.
- RDAP person/contact data is not collected; only organisations are read.
- `username_scan` sends requests to public profile URLs on many services via `username-engine`; `ip_internetdb`, `domain_crtsh`, `ip_rdap`/`ip_asn` query third-party databases rather than the target.
- Queries expose the investigated identifiers to the third parties named above; use the proxy channel where that matters.

## Installation

Python 3.12+; no runtime dependencies. Sibling tools are launched from their own `.venv` when present (otherwise the current interpreter); `ENTITY_GRAPH_TOOLS_DIR` overrides where they are looked up.

```bash
cd projects/osint-toolkit/entity-graph
python -m venv .venv
python -m pip install -e ".[dev]"
```

On Windows, `START_ENTITY_GRAPH.cmd` bootstraps `.venv` and provides the alias `eg`. Without installing the package: `PYTHONPATH=src python -m entity_graph <command>`.

## Usage

```bash
# Infrastructure case (network transforms run unless --offline)
python -m entity_graph run --purpose "audit of own infrastructure, engagement 2026/14" \
    --domain example.com --ip 192.0.2.10 --depth 1 --out case-example

# Offline merge of previously produced outputs into one graph
python -m entity_graph polacz --purpose "merge of existing tool outputs, case 2026/14" results/ --out case-merged

# Import an org-intel export (dry run first; report must be a new file)
python -m entity_graph import-org-intel org-intel-export.json --dry-run

# Exports and verification
python -m entity_graph export case-example/graph.json --graphml g.graphml --html report.html --maltego edges.csv
python -m entity_graph audit-verify case-example/audit.jsonl
python -m entity_graph evidence-verify case-example

# Person-related case work (every decision needs a stated reason)
python -m entity_graph przeglad case-example --person "Alice Example"
python -m entity_graph potwierdz case-example --person "Alice Example" --profil https://example.com/alice --dowod "same photo and employer"
```

Exit codes (`run`): `0` finished, `1` at least one transform ended in `ERROR`, `2` usage error or guardrail violation. `import-org-intel`: `0` all records accepted, `2` usage/file error, `4` some records rejected, `5` `--strict` refusal (nothing written). `szukaj-profili`: `3` for missing/invalid configuration or a required but unavailable proxy (zero traffic).

## Configuration

Names only; see the pipeline security document for the proxy rules.

| Variable | Purpose |
|---|---|
| `ENTITY_GRAPH_TOOLS_DIR` | Directory containing the sibling tool folders |
| `HIBP_API_KEY` | Enables `email_hibp` (otherwise `UNKNOWN`); never written to graph, log or sub-processes |
| `BRAVE_SEARCH_API_KEY`, `BRAVE_SEARCH_ENV_FILE` | Brave Search API key / alternative env-file location outside the repository |
| `BRAVE_PROXY`, `BRAVE_REQUIRE_PROXY`, `OSINT_PROXY` | Pinned HTTP proxy and proxy-required policy for `szukaj-profili` |
| `EG_AI_URL`, `EG_AI_MODEL` | Optional local-model endpoint (loopback only) and model name for `asystent --ai` |

## Testing

```bash
cd projects/osint-toolkit/entity-graph
python -m pytest -q
```

Tests use fixtures in `tests/fixtures/` and fake fetchers/runners; they require no network access.

## Limitations

- Findings are leads: identical usernames, display names or avatars do not identify a person. Avatar hashes are computed from the image address, not the image content.
- Facebook, Instagram, Threads and LinkedIn are not checked automatically (manual links only, apart from the official-API `meta-search` importer).
- A format change in a sibling tool can lead to `SKIPPED`/`ERROR` on import; importers are tested on fixtures of the known formats.
- `ip_internetdb` reports other parties' scan data; a 404 does not prove ports are closed. `domain_crtsh` presence does not prove a host is live.
- Company-name matching is heuristic; domain-to-company relations by name are always `inferred`.
- Maltego CSV and GraphML-in-Maltego import have not been tested with a Maltego licence; column mapping is done at import time.
- The profile-address filter is a structural heuristic, not a complete secret filter.
- The HTTP layer is a thin `urllib` client without TLS pinning or SSRF filtering of seed hosts; it is meant for public lookups, not for fetching arbitrary attacker-supplied URLs.
- The `osint-poland` importer parses files in the formats that package produced; that package is not published here.

## Planned (not implemented)

- Background scans with resume for long runs (listed as open in the panel's status block).
- Per-case locking against concurrent writes to one case (listed as open in the same block).
- Import of a user-supplied social-media data export (listed as not yet built in the same block).
