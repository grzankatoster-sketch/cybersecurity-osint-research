# Security Policy

## Supported versions

This repository is a research and engineering portfolio. Only the `main` branch is maintained.
There are no tagged releases and no backports.

## Reporting a vulnerability

Please do **not** open a public issue for a security problem.

Use GitHub's private vulnerability reporting ("Security" tab → "Report a vulnerability") on this
repository. Include the affected project and file, a description of the impact, and reproduction
steps that use only local or mock targets. Expect an acknowledgement within 14 days. There is no
bug bounty.

## Responsible use

The tools in this repository collect information from public sources. Use them only on:

- assets you own (domains, IP ranges, accounts, photos, phone numbers), or
- assets you are explicitly authorised **in writing** to assess, for a documented purpose.

Data-protection law (for example the GDPR) can apply to publicly available personal data. A
matching username, display name, avatar or domain is a **lead, not proof** that two records belong
to the same person. The tools deliberately do not bypass CAPTCHAs, logins, paywalls or rate limits,
do not process leaked datasets, and do not attribute accounts to real identities automatically.

## Security architecture (summary)

Detailed per-project documentation:
[OSINT Toolkit security & provenance](projects/osint-toolkit/docs/SECURITY_AND_PROVENANCE.md),
[Ultimate Username Engine security architecture](projects/ultimate-username-engine/docs/SECURITY_ARCHITECTURE.md),
and the package READMEs. Implemented controls include:

| Concern | Control (where) |
|---|---|
| Operator IP exposure | Fail-closed proxy/Tor channel: a missing or failing proxy blocks traffic instead of falling back to a direct connection (`username-engine/src/username_engine/http.py`, `cli.py`; `entity-graph` profile search; `meta-search`; `dns-audit` DoH over SOCKS5) |
| SSRF via user input, catalogues or redirects | Address-class checks, numeric-IP spellings, pinned resolution and per-hop redirect validation (`site-audit/src/site_audit/target.py`, `fetch.py`; `ULTIMATE_USERNAME_ENGINE/src/ultimate_username/opsec/policy.py`, `policies.py`; `net-intel` refuses non-public IPs) |
| Secret leakage | Keys read from environment only; host-bound API keys (`hibp-monitor/src/hibp_monitor/http.py`); redaction of tokens and proxy credentials in logs and errors (`meta-search`, `dns-audit`, `org-intel`, `ultimate_username/opsec/redaction.py`); scrubbed environments for sub-processes (`panel`, `entity-graph`) |
| Hostile response content | Body-size caps, regex length / nested-quantifier heuristics, XML parsed without DTD/entities (`site-audit` sitemaps), HTML escaping and CSP `default-src 'none'` in reports, CSV formula neutralisation |
| Data minimisation & integrity | Provenance required for every stored fact (`org-intel`), hash-chained audit log (`entity-graph`), report retention and purge (`username-engine/retention.py`), atomic writes |
| Supply chain & repository hygiene | gitleaks (full history), pip-audit, bandit, CodeQL and Dependabot in CI (`.github/`); `ci/run_checks.py` blocks committed `.env` files and case data |

Internal adversarial testing of the Ultimate Username Engine's egress module was performed by the
maintainers against **loopback and mock services only**. It is an internal hardening exercise, not
an external penetration test, and no third-party system was tested.

## Pre-publication review (2026-10-11)

Summary of the review performed before this repository was assembled. Full results:
[`docs/SECURITY_REVIEW.md`](docs/SECURITY_REVIEW.md).

- **Secrets:** gitleaks 8.21.2 reports no findings on the published tree. The only matches before
  the allowlist were synthetic test canaries (`SYNTH-…`, `tok_SEKRET_…`, the public jwt.io sample
  token). The repository was created with a fresh history; no history from the private working
  repositories was imported.
- **Credentials requiring rotation:** none were found in the published tree or in the commit
  histories of the source repositories. A third-party JWT (a Vimeo token embedded in Maigret's
  public `data.json`) was present in a generated import file; that file is excluded and the token
  is not a credential of this project. Local `.env` files of the excluded `osint-poland` project
  were never committed and were not copied.
- **Personal data:** captured profile pages, labelled ground-truth sets, benchmark outputs and
  research results were excluded. Usernames and names of real people in tests were replaced with
  synthetic pseudonyms (for example `Sampler51`, `PublicRefA`, `vexalune`).

## Known issues

Found during the pre-publication review. **Fixed** items were remediated in Phase 3 (2026-10-11) with
regression tests; the rest remain open.

Credential use in the Ultimate engine is now deny-by-default: a site definition may only name a
`UEE_CRED_*` variable, and the operator must bind it to exact hosts, e.g.
`UEE_CREDENTIAL_SCOPES="UEE_CRED_EXAMPLE=api.example.com"`. Credentials are sent over HTTPS to
port 443 of those hosts only (`ultimate_username/credentials.py`).

| ID | Severity | Project / file | Issue | Status / fix |
|---|---|---|---|---|
| OPEN-01 | Medium | Ultimate · `opsec/config.py` | Invalid values fail open: `OSINT_PROXY_ALLOWED_PORTS=abc` yields an empty set, which `policy.py` treats as "all ports allowed"; a misspelled `OSINT_PROXY_FAIL_CLOSED` (e.g. `flase`) yields `False`. The forward proxy is a library component that the CLI does not start, which limits exposure. | **Fixed.** Strict parsing; malformed values are recorded and make `validate()` refuse start-up; unparseable `FAIL_CLOSED`/`REQUIRE_ALLOWLIST` stay `True`, unparseable `ENABLED` forces validation. Tests: `tests/opsec/test_config_strict.py` (36). |
| OPEN-02 | Medium | Ultimate · `engine.py` (`credential_env`) | A site definition can name any environment variable; its value is sent to that definition's host. A tampered catalogue could exfiltrate environment variables. | **Fixed.** `credentials.py`: `UEE_CRED_*` names only, operator host scopes, HTTPS/443, exact host, no userinfo; catalogue validation rejects other names. Tests: `tests/unit/test_credentials.py` (28). |
| OPEN-03 | Low | Ultimate · `opsec/guard.py` | DNS check-then-connect gap (TOCTOU) in direct mode; `socks4://` resolves names locally. | Connect to the validated address; prefer `socks5h`. |
| OPEN-04 | Low | Ultimate · `opsec/server.py` | With an upstream, the forward proxy resolves target names locally and its byte pump has no idle timeout. | Delegate resolution upstream; add idle timeouts. |
| OPEN-05 | Low | Ultimate · `security/audit.py` | `python -m ultimate_username.security` fails: it imports `security.secrets`, which is not in the published code. | **Fixed.** Built-in scanner module restored from the hardening branch (single file). Tests: `tests/opsec/test_security_entrypoint.py`. |
| OPEN-06 | Low | Toolkit · `osint-mcp/src/osint_mcp/runner.py` | Sub-processes inherit the full environment (no secret scrub, unlike `panel` and `entity-graph`). | **Fixed.** Per-module environment allowlist (`module_env`); proxy variables kept so routing never silently becomes direct. Tests added to `osint-mcp/tests/test_tools.py`. |
| OPEN-07 | Low | Toolkit · `panel/app.py` | `GET /` embeds the session token guarded only by a `Host` check; report files under `/wyniki/` are served without the token. Binding is loopback-only. | Require the token for report files; add an `Origin` check. |
| OPEN-08 | Low | Toolkit · `entity-graph/src/entity_graph/http.py` | No SSRF filter on fetched URLs. | Reuse the `site-audit` target guard. |
| OPEN-09 | Low | Username Engine v1 · `scripts/build_db.py` | Downloads upstream catalogues from the `main` branch without pinning or checksums (supply-chain risk); in proxy mode the resolved IP of a target is not checked; the HTML report has no CSP. | **Partly fixed.** `build_db.py` pins WhatsMyName and Maigret to commits and verifies SHA-256 before parsing (https only, size cap); `build_geo.py` adds https, size cap, optional hash check and records hashes (GeoNames has no versioned dumps). Still open: resolved-IP check in proxy mode, CSP on the HTML report. Tests: `tests/test_build_db_integrity.py` (16). |
| OPEN-10 | Low | Toolkit · `exif-map` | Strip output and `--json`/`--csv` writes are not atomic. | Write to a temporary file and rename. |

Static-analysis notes: bandit flags SHA-1 in `hibp-monitor/passwords.py` and MD5 in
`osint-connectors/.../gravatar_public.py`; both are mandated by the HIBP k-anonymity API and the
Gravatar hash format, not used as security primitives. The f-string SQL in
`ultimate_username/storage.py` selects one of two fixed column names; values are parameterised.
