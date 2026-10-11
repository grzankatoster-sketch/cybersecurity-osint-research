# org-intel

Local registry of information about **companies, domains, public persons and publicly described security incidents**, with **mandatory provenance**: every entity carries at least one observation (source, evidence address, date, confidence, direct or inferred derivation). HIBP is used here only as a **public catalogue of incident metadata** (CC BY 4.0, attribution carried into exports), never as a source of account data.

> A Polish version of this document is in [README.pl.md](README.pl.md). Pipeline-wide rules are in [`../docs/SECURITY_AND_PROVENANCE.md`](../docs/SECURITY_AND_PROVENANCE.md).

## Security use cases

- Counterparty and supplier due diligence from public, attributable sources.
- Tracking which of your own or a vendor's domains have publicly described incidents, without handling any leaked data.
- A provenance-enforcing staging store in front of `entity-graph` (`import-org-intel`): records without a source, or carrying secrets, never get that far.
- Proving ownership of your own domain (TXT-token verification) before attributing it to an organisation.

## How it works

Input (own JSON format or an HIBP catalogue) -> `parsers.py` + `guards.py` (validation, rejection with reasons) -> `store.py` (deduplicating JSON store) -> `correlate.py` (organisation-domain-incident-person relations) -> `export.py` (JSON / CSV).

| Module | Role |
|---|---|
| `src/org_intel/models.py` | `Source`, `Observation`, `Organization`, `Domain`, `Incident`, `Person`; enums (`SourceType`, `Confidence`, verification status) |
| `src/org_intel/guards.py` | Provenance requirement, leak-source signals, recursive secret detection, forbidden relations, person/e-mail rules |
| `src/org_intel/parsers.py` | Own-format and HIBP-catalogue parsers; source-key resolution; per-record rejection |
| `src/org_intel/normalize.py` | Company names, URLs, identifiers (NIP/REGON checksums, KRS format) |
| `src/org_intel/quality.py` | Source quality = min(type base, declared reliability) |
| `src/org_intel/store.py` | Atomic JSON store, deterministic ids, merge rules |
| `src/org_intel/correlate.py` | Relations with `direct`/`inferred` derivation |
| `src/org_intel/hibp_catalog.py` | Public HIBP catalogue connector (disk cache, rate limit, minimisation) |
| `src/org_intel/verify.py` | Domain-ownership token and DNS-over-HTTPS TXT check |
| `src/org_intel/export.py`, `logging_redact.py`, `http.py`, `cli.py` | Export, log redaction, stdlib HTTP client, CLI |

## Implemented security mechanisms

- **Offline by default.** Network commands without `--online` exit with code 2 and make no request (`_require_online` in `cli.py`).
- **Mandatory provenance.** A record without an existing source key is rejected ("no source"); a typo in a key cannot silently drop provenance (`require_sources` in `guards.py`). Sources need an http(s) URL, an ISO 8601 `retrieved_at` and a type from the enum (`validate_source`).
- **No leak sources.** Sources whose name, type, URL or host signal dumps, combolists, stealer logs, pastes, Telegram or leak forums are rejected (`check_source_signals`, `_LEAK_WORDS`, `_LEAK_HOSTS`). CERT advisories, official documents and the HIBP catalogue, which legitimately describe leaks, are checked on host only.
- **No raw secrets.** Every record is searched recursively for secret-named fields and secret-looking values: JWTs, PEM private keys, bcrypt hashes, bearer tokens, `email:password` pairs and 32/40/64-character hex strings (`check_secrets`). The HIBP data class label "Passwords" is not rejected.
- **No incident-to-person linkage.** An incident with person/e-mail/account fields, or a person with incident fields, is rejected (`reject_forbidden_relations`). HIBP catalogue records containing account, address or secret fields are rejected entirely (`catalog_forbidden_key`).
- **Careful handling of public persons.** Only `official_registry`, `company_website` or `official_document` sources qualify; an e-mail is stored only if its source is first-party/official **and** its domain is the organisation's official domain (or subdomain) or it appears verbatim in the evidence quote (`decide_person_email`). E-mails are masked in exports unless `--include-emails`.
- **Address data limited to legal entities.** A registered address requires a KRS number or an explicit legal-entity marker plus an `official_registry` source; otherwise the record is rejected (documented in the input-format notes; enforced in `parsers.py`).
- **Evidence minimisation.** Evidence quotes are stored only as sha256 unless the explicit `--audit-mode` is used; rejected records never reach the audit raw files.
- **CSV formula neutralisation.** Values starting with `=`, `+`, `-`, `@`, TAB or CR receive a leading apostrophe (`export.py`).
- **Atomic writes** for the store and the HIBP cache (`mkstemp` in the same directory + `os.replace`; `store.py`, `hibp_catalog.py`).
- **HTTP client limits.** 20 MB response cap, redirects refused, 30 s default timeout (`http.py`). The HIBP connector keeps at least 1.6 s between requests, honours `Retry-After` (at most 3 attempts, wait up to 120 s) and caches the *minimised* response for 24 h.
- **No API key path for HIBP.** The catalogue command sends only `User-Agent` and `Accept`; it has no key option and does not read `HIBP_API_KEY`.
- **Log redaction.** `RedactingFilter` masks e-mails, JWTs, authorisation and bearer values, `hibp-api-key`, password/token assignments, the verification token and long hex strings (`logging_redact.py`).
- **Domain verification token handling.** A random token (`secrets.token_urlsafe`) is shown once; only its sha256 is stored, compared with `hmac.compare_digest`, and never exported (`verify.py`).

## Data handling and privacy boundaries

- No dumps, combolists, stealer logs, paste or messenger sources; no e-mail-in-leak searches; no e-mail-to-person or person-to-incident relations. Incidents attach to a domain or organisation only.
- HIBP data accepted: name, title, domain, dates, account **count**, data-class labels, description (HTML stripped, e-mails masked, at most 2000 characters) and quality flags. Other fields are ignored.
- The store is a local JSON file (default `./org-intel-data/store.json`); a HIBP cache lives beside it. Audit-mode raw records go to `raw/`.
- `verify-domain --check --online` sends the domain name to the DNS-over-HTTPS provider configured in `verify.py` (Cloudflare).
- This is not legal advice; see the pipeline document for the lawful-use boundaries.

## Installation

Python 3.12+; no runtime dependencies (stdlib only).

```bash
cd projects/osint-toolkit/org-intel
python -m venv .venv
python -m pip install -e ".[dev]"
```

## Usage

```bash
python -m org_intel ingest input.json [--store ./org-intel-data/store.json] [--audit-mode]
python -m org_intel search-company "Example Sp. z o.o." --json
python -m org_intel incidents --domain example.com
python -m org_intel export --format json --out export.json
python -m org_intel export --format csv --out ./export-csv        # directory; one file per entity type
python -m org_intel verify-domain example.com                     # offline: issues token + TXT instructions
python -m org_intel verify-domain example.com --check --online
python -m org_intel fetch-hibp-catalog --online --user-agent "my-tool/1.0 (contact)" [--refresh]
```

Minimal input document (own format):

```json
{"sources": [{"key": "s1", "name": "Registry extract", "url": "https://registry.example.com/entry/1",
              "source_type": "official_registry", "retrieved_at": "2026-01-01T10:00:00Z", "reliability": "high"}],
 "organizations": [{"legal_name": "Example Sp. z o.o.", "official_domain": "example.com",
                    "sources": ["s1"], "confidence": "high", "derivation": "direct"}]}
```

Input is JSON only, with a 50 MB file limit; one rejected record does not stop the import. HIBP catalogue files are recognised by content (a list from `/api/v3/breaches`, or `{"breaches": [...]}` from `hibp-monitor breaches --catalog --json`).

Exit codes: `0` OK; `2` usage/configuration error (syntax, unreadable file, missing User-Agent, unknown domain, network command without `--online`); `3` network/API error; `4` `ingest` stored valid records but some were rejected.

## Configuration

No environment variables are read. The store location is set with `--store`.

## Testing

```bash
cd projects/osint-toolkit/org-intel
python -m pytest -q
```

Tests use a fake HTTP client and resolver and only synthetic fixtures (`tests/fixtures/`).

## Limitations

- No automatic retrieval of company registers: records are supplied in the JSON format with their source. (The original pipeline fed this format from a separate registry adapter, `osint-poland`, which is intentionally not published.) KRS has a format check only, no checksum.
- Company-name matching is heuristic (legal forms recognised only at the end of a name); a domain-to-company relation derived by name is always `inferred`.
- Domain verification checks TXT on the apex domain at a single DoH provider.
- The HIBP connector and the DoH resolver have not been exercised against the live services in this repository; tests use fake clients and block sockets.
- Re-importing a changed incident description or flags keeps the first values (statuses are unioned); `ModifiedDate` is only recorded in an observation note.
- Source-host strictness (HTTPS/443-only, IP and internal-host blocking, per-type host allowlists) is applied by the `entity-graph` importer, not by this package.
