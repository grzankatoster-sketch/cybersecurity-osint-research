# Security and Provenance in the OSINT Pipeline

> English translation of [`BEZPIECZENSTWO_I_PROWENIENCJA.md`](BEZPIECZENSTWO_I_PROWENIENCJA.md) (Polish original, kept alongside). The text below is a faithful translation; it makes no claims beyond the original.
>
> Translation notes: the document describes the toolkit as it was in the author's original (private) working repository. The `osint-poland` registry adapter and the `username-engine` package referred to below are discussed from that perspective; `osint-poland` is **not** part of this published repository. Command names, flags, file names and a few literal output strings (shown in code font with an English gloss) are kept in their original form. Section 13 (code-versus-documentation discrepancies) is preserved as written. Commit hashes and branch names refer to the original repository history and are retained for fidelity.

State as of 2026-10-05, branch `lab/wdrozenie-2026-10-03`, HEAD `4ef32db`. This document is for the analyst/auditor (what the tool does, what it does not do, how one knows a result is trustworthy) and for the developer (where in the code a given rule lives). It describes the state of the **committed code**; uncommitted items (for example the case assistant in `entity-graph`) are out of scope. **This is not legal advice** (see section 3).

All data in the examples is synthetic (`example.test`, `Example Sp. z o.o.`, `Jan Kowalski`, `DemoBreach`). The document contains no password, token or key values.

## Table of contents

1. [Pipeline](#1-pipeline)
2. [Data sources](#2-data-sources)
3. [Limits of lawful use](#3-limits-of-lawful-use)
4. [Incident metadata versus raw breach data](#4-incident-metadata-versus-raw-breach-data)
5. [Provenance](#5-provenance)
6. [Offline and online mode](#6-offline-and-online-mode)
7. [Exit codes](#7-exit-codes)
8. [Fail-closed behaviour](#8-fail-closed-behaviour)
9. [Reporting and the audit log](#9-reporting-and-the-audit-log)
10. [HIBP limitations](#10-hibp-limitations)
11. [Not storing passwords and tokens](#11-not-storing-passwords-and-tokens)
12. [Deferred topics and known limitations](#12-deferred-topics-and-known-limitations)
13. [Code-versus-documentation discrepancies noticed while writing](#13-code-versus-documentation-discrepancies-noticed-while-writing)

---

## 1. Pipeline

```
 official registers                      public HIBP catalogue
 (KRS, CEIDG, REGON/GUS)                 (GET /api/v3/breaches, no key)
        |                                        |
        v                                        v
 osint-poland adapter                     org-intel fetch-hibp-catalog
 (org_intel_feed.py;                      or hibp-monitor breaches --catalog --json
  KRS/CEIDG connectors,                   (incident metadata; the only contact with HIBP)
  REGON result from a file)                      |
        |  org-intel input file                  |
        +------------------+---------------------+
                           v
                    org-intel  (ingest -> store.json; export --format json)
                    companies, domains, incidents, sources, observations
                    guards: provenance, zero leaks, zero secrets
                           |  JSON export or store.json
                           v
                    entity-graph import-org-intel  (--dry-run / --strict / --report)
                    case folder: graph.json + audit.jsonl (hash chain)
                           |
                           v
                    export: graph.graphml, report.html,
                            maltego.csv  (or eg export --maltego FILE)
                           |
                           v
                    CI: ci/run_checks.py + .github/workflows/osint-pipeline.yml
                    (zero network, zero secrets, synthetic data, E2E of the whole chain)
```

Cross-cutting rules:

* The packages **do not import each other**. The guards and normalisation are copied (`entity-graph/.../importers/org_intel.py` copies `org-intel/guards.py`, `quality.py` and the register list from the adapter) and **hardened** in the importer. Consequence: every stage validates its input independently of the previous one (it does not trust it).
* The direction is one-way: data flows downstream. `entity-graph` makes no network calls in the org-intel import; `org-intel` does not know `entity-graph`.
* Natural persons **do not enter the graph** through this import (section 3).

## 2. Data sources

The source type in org-intel (`source_type`) is constrained by an enum. The `entity-graph` importer additionally requires that the **host of the address matches the type** (allowlists in `HostRules`; a type without a rule is rejected). Hosts match exactly or as subdomains of an entry.

| Source type | Example host | What is stored | Base quality (importer) |
|---|---|---|---|
| `official_registry`: KRS | `api-krs.ms.gov.pl` (also `ekrs.ms.gov.pl`, `prs.ms.gov.pl`) | legal name, KRS, NIP, REGON, status, registered-office address of the legal entity, former names (full extract), `retrieved_at`, sha256 of the response | high |
| `official_registry`: CEIDG | `dane.biznes.gov.pl` (also `biznes.gov.pl/ceidg`) | only with the `--include-sole-proprietors` flag: business name, NIP, REGON, status; **no address**; access via an operator token (environment variable, not a file, not an argument) | high |
| `official_registry`: REGON/GUS | `wyszukiwarkaregon.stat.gov.pl`, `api.stat.gov.pl` | same as KRS; address only for type P (legal entity). In this repository the GUS result enters **from a file** (`--input`), not from the network | high |
| `official_registry`: other | `wl-api.mf.gov.pl` | permitted host in the allowlist (VAT whitelist); no connector in the adapter at HEAD | high |
| `company_website` | the organisation's official domain from the same import | evidence that a fact is present on the company site (address, hash), not the page content | low in the import (domain taken from an untrusted file), high in org-intel |
| `cert_advisory` | `cert.pl`, `cert.europa.eu`, `enisa.europa.eu` (category `cert`); `nask.pl` (`nask`); `csirt.gov.pl`, `gov.pl` (`csirt`); the organisation's domain (`vendor_advisory`) | address of the advisory as evidence of an incident; incident description without HTML | high (`vendor_advisory`: low) |
| `official_document` | `*.gov.pl`, `*.europa.eu` or the organisation's domain | document address and its hash | medium (high for official hosts; low when recognised only through a domain from the file) |
| `hibp_catalog` | `haveibeenpwned.com`, `api.haveibeenpwned.com` | **metadata only** about the incident (section 4) | medium; an incident without the `verified` flag gets a low observation |
| `ct_log` | `crt.sh`, `ct.googleapis.com` and other known CT logs | evidence that a certificate/domain exists | medium |
| `passive_dns` | any public host | evidence of a domain-to-resource association | low |
| `manual` | any public host | a manual operator entry | low |

Host blocks common to all types (apply to the source `url` and to `evidence_url`): IP addresses in any form (including decimal and hexadecimal), `localhost`, `*.local`, `*.internal`, hidden networks (`.onion`, `.i2p`), hosts without a dot, known leak forums and marketplaces, as well as paste sites and messengers (host, subdomains, words in the host name). Only HTTPS on port 443 is accepted; an address containing credentials or an `@` character (also encoded once or twice) causes the record to be rejected rather than silently "cleaned".

Source quality = the minimum of the type's base and the declared `reliability`. A source recognised **only** because its host is the `official_domain` from the same untrusted file has a quality of at most low (the file could have pointed to any domain, for example shared hosting).

The pipeline **does not have**, and will not have, these sources: dumps, combolists, stealer logs, messenger channels and pastes, leak forums, services selling leak content.

## 3. Limits of lawful use

**Permitted purpose:** counterparty verification and due diligence based on public data; security of the operator's **own** organisation (own domains, the company's history of publicly described incidents); authorised research commissioned for a clear purpose and on a clear legal basis. The tool requires an explicit purpose (`--purpose`, at least 2 words and 12 characters) and records it in the audit log.

**What the pipeline does NOT do** (and for the most part has neither data types nor code for it):

* it does not search for people in leaks and does not link an e-mail address, login or phone number to a person (there is no e-mail-to-person or person-to-incident relation; an incident is linked only to a domain/organisation);
* it does not enumerate accounts on services (probing sign-up/password-reset), does not perform credential stuffing or any testing of passwords at login;
* it does not download, buy or index dumps (forums, messengers, pastes, combolists), not even "for verification only";
* it does not scrape search engines or private or unofficial APIs; the only automated search engine is the official Brave Search API with the operator's key (`eg szukaj-profili`);
* it does not circumvent protections: no logging into services, no CAPTCHA solving, no **IP rotation** after a block, no **browser fingerprint spoofing** (a fixed, honest User-Agent; the only permitted exception is a single fixed proxy protecting the operator, in fail-closed mode, section 8);
* it does not establish identity: a hit is a lead, not proof (profile search results are hypotheses for the operator to decide on).

**Natural persons outside the import graph:** `import-org-intel` skips persons entirely (no Person/Email/Username/Phone nodes, a hard assertion and tests; this includes public persons from the register). The register adapter skips claims about persons (management board, partners, proxies, beneficial owners), and sole proprietorships (CEIDG, REGON type F) only on an explicit flag and without an address. A registered-office address is accepted only for legal entities / KRS entities from a register source. In `org-intel` itself a public person is permitted only from a first-party/official source, and their e-mail only with double confirmation (section 5); the export masks e-mails by default.

**Minimisation:** only fields from the allowlist are stored; an evidence quote is stored as a sha256 (text only in the explicit `--audit-mode`); source and observation `notes` do not reach the graph; e-mails in text fields are replaced with a marker (section 9).

**This is not legal advice.** Consult a lawyer before production deployment or before changing the boundaries. Risks to discuss:

* GDPR Art. 6 (legal basis for processing) and Art. 14 (information duty when data was not obtained from the data subject), also for "public" register data: being public does not replace a legal basis or a purpose;
* personal data from leaks and any linking of it with persons (GDPR Art. 9 for special categories; criminal liability for processing without authorisation and for disclosing unlawfully obtained information): this is why the pipeline does not process such data at all;
* terms of service and API terms of the sources (CEIDG, Brave, HIBP: among others CC BY 4.0 attribution and the prohibition on queries intended to harm breach victims);
* retention: the graph and the log contain what the operator entered as the purpose and inputs; delete the case after the investigation ends (deleting the case folder also deletes the log);
* offering results to SaaS customers (a different regime from own use).

## 4. Incident metadata versus raw breach data

From the public HIBP catalogue (`/api/v3/breaches`, no key) the pipeline accepts only a **description of the event**:

| In the catalogue (permitted fields) | Notes |
|---|---|
| name (`Name`), title (`Title`), service domain (`Domain`) | the domain of the service that was the source of the incident |
| dates: `BreachDate`, `AddedDate`, `ModifiedDate` | `ModifiedDate` only in the observation note |
| account count (`PwnCount`) | a number, not a list |
| data classes (`DataClasses`) | labels, for example "Email addresses"; the label "Passwords" does **not** mean passwords are present in the repository |
| description (`Description`) | HTML removed, e-mail addresses masked, at most 2000 characters |
| flags: verified, fabricated, sensitive, retired, spam list, malware, stealer log | a flag is only an explicit truth (`true`/`1`); the text "false" is not one |

Fields outside the list (for example logo, attribution) are ignored. **A record containing an account, address, password or secret field is rejected as a whole**; the rest of the import continues.

**What is NEVER present in the repository nor in the store/graph/exports:** e-mail addresses of accounts from leaks, passwords, password hashes, tokens and keys, account records, stealer logs (domain-account pairs), "who is in the breach" lists. This also applies to the HIBP catalogue cache (the already-minimised response is stored, not the raw one) and to audit mode (only permitted fields).

Why (the HIBP model, see `AUDYT_HIBP_POZYSKIWANIE_WYCIEKOW_2026-10-05.md`, an audit note that is not included in this published repository): HIBP operates lawfully and ethically thanks to minimisation (it keeps only breach names against an address), source verification, disclosure to companies, the address owner's opt-out, domain-ownership gates for bulk search, and institutional partners (CERTs, law enforcement). A self-built dump database has none of these properties, and its only use would be looking up other people. The metadata catalogue provides what is useful for company analysis (whether a domain/organisation had a publicly described incident, when, how large, which data classes) without personal data.

The remaining HIBP functions are **outside** the pipeline: search by e-mail address, bulk search by domain, pastes and stealer logs. In the code they appear only in `hibp-monitor` (optional, paid: a key and verified domain ownership; section 6); static tests ensure the endpoints of these functions are absent from `org-intel`.

## 5. Provenance

Every stored piece of information has at least one source and one observation. Fields (in the graph, `provenance` in the node attributes; in org-intel as `Source` + `Observation`):

| Field | Meaning |
|---|---|
| `source_url_original` | the address as stored by org-intel (org-intel already normalises on write: no fragment, no `utm_*`, no trailing `/`), so this is not the input from before `org-intel ingest` |
| `source_url_normalized` | the entity-graph key (without scheme and `www.`); used solely for deduplication and identification of the source node |
| `source_type`, `source_category` | the type from org-intel and the importer's category (`SOURCE_TYPE_TABLE`: for example `official_registry`, `official_company`, `cert`, `nask`, `csirt`, `vendor_advisory`, `public_report`, `hibp_catalog`) |
| `retrieved_at` | time the source was retrieved (ISO 8601; must be a real date, from 1990, no later than a day after the import time) |
| `confidence` | high/medium/low; in graph edges numerically 0.9 / 0.6 / 0.3, for `inferred` at most 0.6 |
| `derivation` | `direct` (a fact stated directly by the source) or `inferred` (a conclusion, for example an incident on a subdomain attributed to the parent domain, a domain matched by company name) |
| `evidence_hash` | sha256 of the evidence (in org-intel also the source's `content_hash` = sha256 of the server response; a quote is stored only as a hash) |
| `quality` | source quality = min(type base, `reliability`) |
| `import_id` | `imp_` + 12 characters of sha256 (file hash + import time); in the report, in both audit entries and in every newly contributed provenance entry |

Rules:

* **No source means rejection.** A record without `source_ids`, referring to a non-existent source, without an observation, or without `derivation`/`confidence`/`reliability`/`verification_status` (the entity-graph importer **has no default values**; letter case matters), as well as a source without a name, type, http(s) address or `retrieved_at`, is rejected with a reason. A typo in a source key cannot silently drop provenance.
* **Weaker does not overwrite better.** The first non-empty value wins; `verification_status`: verified > pending > unverified > failed (`failed` does not revert `verified`); `affected_accounts_count` = maximum; `is_*` flags are combined with OR; edge confidence = maximum; a provenance entry with higher confidence replaces the older one together with its `import_id`. Contradictory identifiers (the same KRS, a different NIP) reject the later record. Registered-office address: the first value wins, a difference is a warning.
* **Idempotence.** Re-importing the same file (also under a different name) changes no nodes, edges or attributes; the provenance entry keeps the `import_id` of the first import. The report shows "no changes" and the case files are not rewritten (the E2E test checks byte-identity of `graph.json`, GraphML, CSV and HTML). In org-intel sources are merged by normalised URL: the first source stays, every subsequent retrieval is a new observation with a newer `observed_at`.
* **Public persons in org-intel:** only from an `official_registry`, `company_website` or `official_document` source; a **person's e-mail** is stored only when the e-mail's source is first-party/official **and** the address domain is the organisation's official domain (or its subdomain) or the address appears verbatim in the evidence quote. Otherwise the person stays without an e-mail, with a rejection annotation.
* **Source URL collision (fail-closed).** If the case graph already holds a node with the same id and a `kind` other than `source` (a profile, a gravatar), the source is rejected; `has_source` never points to a node of another `kind`. Similarly, an Organization key collision (an incident title equal to a company name) rejects the record instead of merging attributes.
* **No evidence text in the graph:** source and observation `notes` are not stored; quotes only as sha256.

## 6. Offline and online mode

**Offline is the default** in every pipeline step. An `org-intel` network command without `--online` ends with exit code 2 and no traffic at all; the register adapter by default reads the connector result from a file (`--input`); `entity-graph import-org-intel` has no network mode at all; CI blocks the network twice (replacing the socket functions in the test process and a `sitecustomize` in every subprocess; after each test the log of connection attempts must be empty).

`--online` mode (explicit, per command):

| Tool | What it does online | User-Agent | Timeout | Rate limit | Cache |
|---|---|---|---|---|---|
| `org-intel fetch-hibp-catalog --online` | public `GET /api/v3/breaches`, **no key** (the command has no key option, the key variable is not read) | `--user-agent` required (absent = code 2) | 30 s | at least 1.6 s between requests; 429 with `Retry-After` (at most 3 attempts, waiting up to 120 s) | on disk next to the store, TTL 24 h, `--refresh` bypasses it; response limit 20 MB; the stored response is minimised |
| `org-intel verify-domain --check --online` | checking a TXT record through DNS-over-HTTPS (one provider) | per the `http.py` client | per the client | none of its own | none; a network error does not change the domain status |
| `osint_poland.org_intel_feed --online --krs ...` adapter | the existing KRS connectors (current and full extract) and CEIDG (by NIP, only with `--include-sole-proprietors`, token in an environment variable) | the KRS/CEIDG connectors do not set their own header (the HTTP client default); see section 13 | 20 s per request | at least 1 s pause between requests | none |
| `entity-graph szukaj-profili` | the official Brave Search API (operator's key), exclusively through the fail-closed channel (section 8) | fixed, honest | hard run time of 60 s by default (max 120 s) | 6 calls by default (max 12); the HTTP client has a per-host rate limit | none; full responses are not stored |
| `hibp-monitor breaches` | `/breaches?domain=` or the full catalogue (`--catalog`) | required (`config.toml` or `--user-agent`) | per the client | 1.6 s between domains; 429 as above | state in `state.json` (known breaches), not a response cache |

**Paid HIBP endpoints** (bulk domain search, `domain-search`) exist solely in `hibp-monitor`, behind a key in the `HIBP_API_KEY` variable (never from a file or a CLI argument) and **only for a domain verified on the owner's HIBP account**. Without a key: a readable message and zero traffic. The key is sent only to `https://haveibeenpwned.com` (port 443, redirects rejected) and does not reach messages or output. Addresses in the result only with an explicit `--show-addresses`. This was not tested live (section 10).

## 7. Exit codes

| Tool | 0 | 1 | 2 | 3 | 4 | 5 |
|---|---|---|---|---|---|---|
| `org-intel` (`ingest`, `search-company`, `export`, `verify-domain`, `fetch-hibp-catalog`) | OK | not used | usage/configuration error: syntax, unreadable file, missing User-Agent, unknown domain, network command without `--online` | network/API error | `ingest` stored valid records, some were rejected | not used |
| `osint_poland.org_intel_feed` adapter | OK | not used | usage/file error (also an existing output file; the result is written only to a new file) | network/connector, nothing written | some records rejected, the rest written | `--strict` and any rejection: the output file is not created (a report only with an explicit `--report`) |
| `entity-graph import-org-intel` | all records accepted (also when nothing changed) | not used | usage/file error: bad file, CSV, unrecognised format or schema version, conflicting `--json`/`--format`, bad `--report` path, damaged audit log; nothing written | not used | some records rejected, the rest imported (also in `--dry-run`) | `--strict`: refusal, nothing written, no log entry |
| `entity-graph export --maltego` (and `--graphml`, `--html`) | OK | not used | write-rule violation: an existing file without `--force`, a case file name, the input file, someone else's temporary file, missing directory | not used | not used | not used |
| `entity-graph szukaj-profili` | OK | at least one query ended with ERROR (no authorisation, provider limit, timeout, `proxy_down` mid-run, damaged response); partial results stay in the case | rule violation: unknown person without `--dodaj`, bad name, limits out of range | missing/bad configuration, **proxy required and unavailable**, SOCKS without an HTTP proxy, missing key: **zero traffic, case unchanged** | not used | not used |
| `ci/run_checks.py` | all steps OK | tests or checks failed, including a hit from the artefact scanner | usage/environment error: unknown step, missing pytest/ruff/dependencies, Python < 3.12 | not used | not used | not used |
| `hibp-monitor` | OK | not used | usage/configuration error/missing key | network or API error | not used | not used |

`entity-graph audit-verify` and `evidence-verify`: 0 for a consistent chain/vault, 1 on error.

## 8. Fail-closed behaviour

Principle: when a security condition is not met, or cannot be checked, the tool **refuses and does nothing** (instead of "trying anyway").

**Proxy channel in `szukaj-profili`** (`profile_discovery.py`):

* `BRAVE_PROXY=http://host:port`: traffic only through this proxy; proxy unavailable = error, **never a direct connection**. The transport supports only an HTTP proxy (CONNECT); HTTPS and SOCKS as a `BRAVE_PROXY` value are a configuration error.
* `BRAVE_REQUIRE_PROXY`: the proxy requirement is turned off only by an explicit `0`/`false`/`no`/`nie`/`off`; **any other value, including a typo, turns it on**.
* `OSINT_PROXY` (the channel of the whole toolkit, for example Tor; the panel sets it by default) **forces a proxy**. When it has the form `http://host:port` and `BRAVE_PROXY` is absent, it is used as the channel; in SOCKS form (for example Tor) without `BRAVE_PROXY` = refusal (for Tor: `HTTPTunnelPort` and `BRAVE_PROXY` on that port).
* **Probe:** before the first query the TCP connection to the proxy itself is checked (3 s); unreachable = zero queries, code 3, case unchanged.
* **`proxy_down`:** a connection error through the proxy during a run stops the run with no retries and without any direct connection; partial results collected stay (code 1).
* When a proxy is required, the system variables `HTTP(S)_PROXY`/`NO_PROXY` have no effect (the route is pinned). One fixed proxy for the whole run, a fixed User-Agent, **no IP rotation, no browser fingerprint spoofing, no automatic fall-back to Tor or a local connection**. The login and password from the proxy address do not reach messages, the audit log or the report. The rule is recorded in `guardrails.EXCLUDED_CAPABILITIES` and covered by an E2E test in CI (proxy required without configuration: code 3, zero connection attempts).
* The `BRAVE_SEARCH_API_KEY` key from a file: a file inside the repository directory is rejected; the key goes only into the request header.

**`--report` in `import-org-intel`** (checked **before anything else**, also with `--dry-run`; refusal = code 2):

* file names reserved for case files (`graph.json`, `audit.jsonl`, `graph.graphml`, `maltego.csv`, `report.html`, `kropki.svg`) in any directory, regardless of letter case, trailing dots and spaces, and alternate data streams;
* a path inside the current case directory and inside the directory of **any** case or its subdirectory (a directory containing `graph.json` or `audit.jsonl`);
* the `--input` file; any existing file (also a symlink or hard link); paths are resolved through `..`, relative paths, symlinks and junctions;
* writing only to a **new** file (temporary file + `os.link`, which does not overwrite the target); **someone else's temporary file** with the report's working name = refusal detected **before the import** (a fix from `622856b`: previously the import was already stored and code 2 came back only when writing the report); someone else's temporary file is not deleted.

**`--strict`:** the first rejection of a record (also an unknown record field; an unknown top-level key rejects the whole file) = code 5, nothing written, **no log entry** (the log records changes to the case, and a refusal does not change it). The trace of the refusal is code 5 and the report on screen/`--report` with the `import_id`. In the adapter `--strict` means the output file is not created.

**`--dry-run`:** computes the same on an in-memory copy of the graph; **writes nothing** (neither case files nor the log; E2E test: byte-identical and no new file). With `--report` only the report is produced, with the header "DRY-RUN: nic nie zapisano" ("DRY-RUN: nothing written").

**`--maltego` export:** does not overwrite an existing file (exception: explicit `--force`), refuses case file names and the input file, `maltego.csv` in the case directory is written only by the case itself, the temporary file is created in "new only" mode, so someone else's file is not touched.

**Other fail-closed rules:** a record with a URL or key collision is rejected instead of merged; a source type without a host rule is rejected; `verified` without a valid `verified_at` rejects the domain; a 32/40/64-character hex string in a text field is treated as a suspected hash; `emails_masked` other than `true` in the export (and also `store.json`) = the importer masks by itself and adds a warning; host allowlists are deliberately narrow (a real but unlisted host, for example another national CERT, is rejected until the list is consciously extended in code); repo hygiene in CI fails when the repository contains case data or `.env` files.

## 9. Reporting and the audit log

**Import report** (`import-org-intel`, screen and `--report`; `text` or `json` format): `import_id`, file name (without path), format, case path, counts (nodes and edges created/updated/unchanged/rejected), number of skipped persons, number of masked fields (`masked_fields`), number of unknown fields, list of rejections (kind + org-intel identifier + name **only when it does not look like a secret or e-mail** + reason), warnings, record counts in the file. No personal data in the content; **note:** the report contains the local path of the case directory, so check it for the system user name before sharing the report externally.

**E-mail masking:** in every text field written to the graph (legal name, former names, incident name and title, description, data classes, source name and licence, registered-office address) an e-mail address is replaced entirely with the marker `[e-mail ukryty]` ("e-mail hidden"; without the first letter and without the domain). This also covers addresses **partially** masked already by org-intel (for example `j***@example.test`): after the fix `622856b` no address domain remains in the case files. Email-type nodes are not exported to `maltego.csv`; in the other cells an address is replaced with the marker, and a cell containing a secret becomes `[usunięto: sekret]` ("removed: secret"). E2E test: `maltego.csv` with no `@` character at all; in the case files only addresses masked by org-intel in the incident description are allowed (in the tests in the `example.test` domain).

**Audit log** `audit.jsonl`: who (operator), when, why (purpose, case signature), inputs and options, an entry for each operation. The first entry is created **before** the first action; when it cannot be written, the operation does not start. Entries form a SHA-256 hash chain (`eg audit-verify` detects a changed or removed entry in the middle; it does **not** protect against deletion of the whole file or against a change of the last entry without a trace). The org-intel import writes `org_intel_import` entries before/after: file name, sha256, `import_id`, counts; **never the record content nor e-mail addresses**. Profile search writes `profile_search`/`profile_material` (before/after), without the material's content.

**HTML report:** a single file, no JavaScript and no external resources, a `default-src 'none'` CSP, content from third-party sources escaped, links only http/https with `rel="noopener noreferrer nofollow"`, a section "what the tool does not do". **Tabular exports** (org-intel CSV, `maltego.csv`) protect against spreadsheet formulas (an apostrophe before a value starting with `=`, `@`, and for `+`/`-` when it is not a number).

**Attribution:** the org-intel JSON export contains an `attribution` block (Have I Been Pwned, CC BY 4.0), the CSV export an `ATTRIBUTION.txt` file, when `hibp_catalog` sources are in the store. The source licence is carried into the graph.

## 10. HIBP limitations

* **Coverage:** the catalogue covers only breaches that HIBP has loaded; the absence of an entry for a domain **does not prove** there was no incident. `breaches?domain=` (hibp-monitor) shows breaches in which a service on that domain was the **source**, not breaches containing addresses from that domain (that requires paid, verified bulk search).
* **Disclosure delay:** HIBP loads a breach after verification and a disclosure procedure towards the company (on the order of working days), often long after the incident itself; `BreachDate` and `AddedDate` are different dates. Modifications to an existing entry (`ModifiedDate`) are not reported by `hibp-monitor`, and on re-import of a changed description or flags org-intel keeps the first values (statuses are summed).
* **Sensitive breaches:** sensitive breaches are protected in HIBP (among other things, search by address only for the verified address owner); the pipeline carries the `sensitive` flag but **it was not verified live in this repo** to what extent the public catalogue returns them. Do not draw conclusions about the "absence" of such incidents.
* **Entry quality:** a catalogue incident without the `verified` flag has a low observation; `fabricated` and `spam_list` are also low. The `retired` flag means the data stopped circulating, not that the incident did not happen.
* **No live verification in this repo:** the HIBP catalogue connector and the DoH resolver were not tested live (the tests use fake clients and block sockets); neither was the paid `domain-search` endpoint (no key).
* **Terms of use:** attribution (CC BY 4.0), an honest User-Agent and request limits are required; the API forbids queries intended to harm breach victims. The Polish counterpart for a person checking **themselves** (without automation): bezpiecznedane.gov.pl (Ministry of Digital Affairs and CERT Polska).

## 11. Not storing passwords and tokens

**Guards** (`org-intel/guards.py`; a hardened copy in `entity-graph/.../importers/org_intel.py`; separate, analogous patterns in the Maltego export and in the CI artefact scanner). A record is rejected as a whole when:

* a **field name** indicates a secret: password (variants), hash or a field ending in "hash" (except the evidence-hash fields `content_hash` and `evidence_hash`), token (also access and refresh), API key, secret, cookie, session, authorisation header, private key;
* a **value** contains a JWT (three segments starting with an encoded header and payload), an authorisation header with a bearer token of significant length, a private key in PEM format, a bcrypt hash, an "e-mail address + separator + character string" pair that looks like a login and password, or a standalone hexadecimal string of length 32, 40 or 64 (suspected hash; exception: evidence-hash fields and URLs);
* the data class "Passwords" in the HIBP catalogue does **not** cause rejection (it is a label; value patterns are checked).

Additional safeguards: a `RedactingFilter` in the org-intel logger (redacts e-mails, JWTs, authorisation headers, the HIBP key, password and token assignments, the domain verification token, long hex strings); the domain verification token is shown once and stored only as a sha256 and is not exported; subprocesses of sibling tools receive an environment without variables containing `KEY`, `TOKEN`, `SECRET`, `PASSWORD`; the summary and output of failed CI steps are masked, and the CI artefact directory is scanned before upload (a hit = code 1 and the file is removed; every unmasked e-mail is a hit); repo hygiene in CI blocks `.env*` files (except the example) and case data.

**User passwords (`hibp-monitor password`):** the k-anonymity model. The password is entered without echo; SHA-1 is computed, and **only the 5-character hash prefix** is sent to the Pwned Passwords service with a padding header, while the suffix is matched locally; padding rows (count 0) are ignored. The password is not logged, stored or printed; the package does not use the `logging` module. No hit does not prove the password is strong; a hit means: change it everywhere.

## 12. Deferred topics and known limitations

* **REGON online:** the committed code has no REGON/GUS connector called by the adapter (`--online` supports only KRS and CEIDG); the REGON result is supplied from a file (`--input`).
* **Registers in org-intel:** no automatic register retrieval in `org-intel` itself (the `osint-poland` adapter does that); KRS has no checksum (only the format is checked, unlike NIP and REGON).
* **HIBP live:** the catalogue connector, the DoH resolver and the paid `domain-search` have not been tested live (section 10); if HIBP changes its response format the parser may reject records.
* **Maltego:** `maltego.csv` and the type mapping (`maltego.Person` and so on) have not been tested in the Maltego application (no licence); columns are mapped on import (*Import Graph from Table*). GraphML was checked for XML validity (Gephi/yEd), not for Maltego.
* **Line-ending hygiene:** two test files in `entity-graph` have **mixed** line endings committed (CRLF + LF): `entity-graph/tests/test_transforms_ip.py` and `entity-graph/tests/test_transforms_person_phone_username.py`. Known debt in `ci/known_mixed_eol.txt`; the `hygiene:eol` check fails on every **new** file with mixed line endings.
* **`username-engine`:** outside the original repository (a separate repository, in `.gitignore`), so it is absent from the CI checkout and has no test step; `entity-graph` uses it only as a sibling tool.
* **Case assistant (`eg asystent`, `eg dziennik`):** outside the scope of this document and outside the committed state at the time of writing.
* **Typing:** the repo does not use mypy/pyright (no configuration); lint (ruff) covers only ruff-clean files (`LINT_TARGETS`).
* **CI:** the adapter-to-org-intel-to-entity-graph test in `osint-poland/tests/test_org_intel_feed.py` is skipped in CI (it looks for `org-intel/.venv`); the same chain is covered by `ci/tests/test_pipeline_e2e.py`. The `ci-artifacts/` directory is created locally with `--artifacts` (consider deleting it or adding it to `.gitignore`).
* **Heuristic limits:** company-name matching is heuristic (legal forms only at the end of the name), the domain-to-company relation by name is always `inferred`; domain verification checks TXT only on the apex domain at one DoH provider; the profile-address filter is a heuristic on address structure, not a complete filter (a secret as an ordinary path segment will pass); `polacz` uses the same parser but without ranking, deduplication and URL-collision detection against the case.
* **Cases from before the profile-search fixes** may contain search-result fragments and addresses with contact data; the fix rewrites nothing (the log is a hash chain); the clean-up procedure is in `entity-graph/README.md`.

## 13. Code-versus-documentation discrepancies noticed while writing

Collected for the owner's decision; the document describes the state of the **code**.

1. **User-Agent in the KRS and CEIDG connectors.** `osint-poland/src/osint_poland/connectors/base.py` defines a fixed `USER_AGENT`, but the GET requests in `krs.py` and `ceidg.py` do not pass it (the other connectors, BZP, GUS, SAOS and TED, do). The `--online` adapter uses the default HTTP client. The pipeline documentation speaks of an "honest User-Agent" in general; for the registers this is not true literally.
2. **Quality base of `company_website`.** The `org-intel/README.md` gives high, the entity-graph importer low when the host is recognised only through the official domain from the same file. This is a deliberate hardening in the importer, but the org-intel README does not mention it.
3. **High quality of an official document.** The org-intel README lists the hosts gov.pl, nask.pl, cert.pl, europa.eu; the importer allowlist: `*.gov.pl` and `*.europa.eu` (nask.pl and cert.pl are covered by the `nask`/`cert` categories for `cert_advisory`, not for `official_document`).
4. **The import report contains the local case path** (the `case` field); it is not personal data from the registers, but it may reveal the system user name.
5. **`entity-graph/README.md`, the "No circumvention of protections" point** said "no ... proxy and identity rotation (the HTTP client has no such options)"; after `cdeffbf` this is outdated (`UrllibClient` has a fixed, fail-closed proxy). Corrected together with this document.
6. **Two test files with mixed line endings** (section 12) are still in the repository.
