# Pre-publication Security Review

**Date:** 2026-10-11 · **Scope:** every file in this repository at its initial commit.
**Method:** automated scanning plus manual review. All results below come from tool runs on the
published tree unless stated otherwise.

## 1. Provenance of the published code

| Project | Source | Selection |
|---|---|---|
| OSINT Toolkit | Private working repository, **working tree including uncommitted changes** (2026-10-11) | Approved packages only; `osint-poland` excluded by the owner |
| Username Engine v1 | Private working repository (working tree) | Code, tests, scripts; generated catalogue excluded |
| Ultimate Username Engine | Private repository, branch `main` (contains the merged `faza-6-ekstrakcja` extraction stage) | Engine, tests, tools, benchmark harness; data and results excluded |

Unmerged branches of the Ultimate engine (`cyber-opsec`, `adaptery-platform`,
`feature/email-engine`) were inspected but **not** merged or published. The source repositories were
only read (`git ls-files`, `git archive`); they were not modified.

The public repository starts with a fresh history. No `.git` directory, commit or branch from the
source repositories was imported.

## 2. Secret scanning

| Check | Tool | Result |
|---|---|---|
| Published tree | gitleaks 8.21.2 (`dir`, default rules + `.gitleaks.toml`) | **0 findings** |
| Published tree, before allowlist | same | 6 matches, all synthetic test canaries: `SYNTH-…` keys (3), `tok_SEKRET_…` (1), the public jwt.io sample JWT `{"sub":"1234567890"}` (2) |
| Source repository histories (read-only) | gitleaks 8.21.2 (`git`, all branches) | Toolkit: 6 matches (test canaries, plus 2 test passwords in the excluded `osint-poland`). v1: 0. Ultimate: 150 matches, all in excluded paths (captured third-party pages, upstream catalogue data, research notes on third-party tools) or synthetic test values |

**Credentials requiring rotation: none identified.**

- No credential belonging to this project was found in any scanned tree or history.
- The JWT in the excluded Ultimate import file is a Vimeo token embedded in Maigret's public
  `data.json` (upstream third-party data, `exp` in 2026). It is not a credential of this project and
  cannot be rotated by it. The file is excluded and git-ignored.
- Local secret files of the excluded `osint-poland` project (`.env`, `.env.*`) and a local
  `.webui_secret_key` were git-ignored, have **no commit** in any history, and were not copied.
  If these values were ever shared outside the owner's machine, rotate them as a precaution; this
  review has no evidence that they were.

## 3. Personal and sensitive data

Excluded categories (counts are files):

| Category | Files |
|---|---:|
| Internal audit artefacts, screenshots, backups, test logs | 5,601 |
| `osint-poland` (excluded by owner decision) | 416 |
| Caches, virtual environments, results, logs, local secrets | 545 |
| Internal working prompts, audit reports, research reports | 77 |
| Captured real profile pages used as private regression fixtures | 57 |
| Labelled ground truth with real usernames and its protocol documents (benchmark) | 27 |
| Runtime artefacts, verified-profile lists, measurement sets from real runs | 6 |
| Third-party catalogues / import records (incl. upstream JWT) | 4 |
| Third-party tool installations and source | 1 directory tree |
| Superseded CI workflows, changelog, root launchers tied to excluded code | 13 |
| Other root-level files outside approved packages (binary research material, researcher working directory, unrelated notes) | 7 |

Transformations applied to published files:

- **Pseudonymisation.** Usernames and names of real people found in tests, tools and benchmark
  scripts (the owner's own handle and several public figures used as benchmark references) were
  replaced with synthetic, case-preserving pseudonyms (`Sampler51`, `PublicRefA`, `publicrefb`,
  `PublicRefCh`, `vexalune`, `zelvarocks`, …), keeping the relationships the tests rely on.
  Benchmark write-ups describe references only generically.
- **Local paths.** Absolute paths containing the owner's account name were replaced with
  `%LOCALAPPDATA%` or `C:\path\to\security-engineering-projects\…` placeholders.
- **Unrelated product notes.** Status notes about a separate commercial product (payment provider,
  domain, legal review) were removed from `panel/app.py`'s `LAB_STATUS`.
- Reference usernames in `custom_sites.json` (86) were verified to originate from the public
  WhatsMyName / Maigret lists and were kept with attribution (see NOTICE.md).

Residual-scan heuristics run after the transformations: owner identifiers, local paths, e-mail
addresses, person-name patterns in string literals and the known pseudonymised names: **0 hits**
apart from deliberate placeholders (`Jan Kowalski`, `Alice Smith`, `Łukasz Żółć` transliteration
example).

## 4. Dependency audit

| Environment | Tool | Result |
|---|---|---|
| OSINT Toolkit (all packages, 62 resolved distributions) | pip-audit | No known vulnerabilities |
| Ultimate engine, pinned `requirements-tested.txt` as found | pip-audit | **aiohttp 3.13.5**: 9 advisories (fixed in 3.14.0–3.14.3); **setuptools 80.10.2**: 1 advisory (fixed in 83.0.0) |
| Ultimate engine after update | pip-audit | **No known vulnerabilities** (pins raised to aiohttp 3.14.5, setuptools 84.0.0; full test suite re-run: 1560 passed) |

Unpinned supply-chain input: `username-engine/scripts/build_db.py` downloads upstream catalogues
from the `main` branch without commit pinning or checksums (SECURITY.md, OPEN-09).

## 5. Static analysis

**bandit** (non-test code): 84 findings: 73 low/high-confidence (mostly `assert`, `subprocess`
without shell), 5 low/medium, 3 medium, 2 high, 1 medium/low-confidence. Triage of medium/high:

| Finding | Location | Assessment |
|---|---|---|
| B324 weak hash (SHA-1) | `hibp-monitor/src/hibp_monitor/passwords.py` | Required by the HIBP k-anonymity range API; not a security primitive |
| B324 weak hash (MD5) | `osint-connectors/.../gravatar_public.py` | Gravatar hash format; not a security primitive |
| B310 `urlopen` | `username-engine/scripts/build_db.py`, `build_geo.py` | Fixed HTTPS URLs; supply-chain note above |
| B608 SQL string | `ultimate_username/storage.py:155` | False positive: column chosen from two constants; values parameterised |
| B102 `exec` | `ULTIMATE_USERNAME_ENGINE/tools/enrichment_audit/donor_runtime.py` | Developer audit tool; compiles one function from a locally supplied third-party source with network disabled; not used by the engine |

**ruff** (Ultimate engine, project config): 38 findings, identical in number to the source `main`
branch (mostly line length in `tools/replay_detection_quality.py`). **mypy --strict**: 2 errors, both present on the source `main` branch: missing module
`ultimate_username.security.secrets` (SECURITY.md OPEN-05) and an `lru_cache` argument type in
`domain/codec.py:160` (typing only).

**Manual review** (code read by reviewers): open issues OPEN-01 … OPEN-10 in
[SECURITY.md](../SECURITY.md#known-issues). The most relevant are fail-open parsing of
invalid proxy settings (OPEN-01) and unrestricted `credential_env` names (OPEN-02) in the Ultimate
engine.

## 6. Tests

See the table in [README.md](../README.md#validation-status). Notes:

- Tests that need excluded material skip themselves with an explicit reason (catalogue not built,
  self-signed certificate not shipped, `osint-poland` not published).
- Ultimate: `test_untrusted_tls_certificate_is_error_without_verdict` depended in the source
  repository on a git-ignored certificate that was never committed; it now skips with instructions
  (`tests/fixtures/README.md`).
- Ultimate: tests touching image handling need Pillow, which `pyproject.toml` does not declare
  (CI installs it explicitly).
- Ultimate: timing-sensitive tests (`test_runtime_quality.py`, `test_profile_metadata.py`,
  `test_label_value.py::test_large_text_is_linear`) failed when run in parallel with other heavy
  processes and passed in three consecutive isolated runs.
- Changes made to published tests: pseudonymisation (section 3), explicit skips for excluded data,
  and updated CI self-tests for the monorepo layout. No assertion was weakened.

## 7. Documentation accuracy

Package documentation was written from the code, not only from the original Polish READMEs.
Discrepancies found between the original documents and the code are recorded in the English
READMEs and in the "Translator's status notes" of the translated design documents (for example the
NORMAL-mode budget in `BUDGET_ARCHITECTURE.md` and default variant behaviour in v1).

## 8. Phase 3 remediation (2026-10-11)

Fixed with regression tests: OPEN-01 (fail-closed proxy configuration), OPEN-02 (operator-scoped
credentials), OPEN-05 (security audit entry point), OPEN-06 (osint-mcp subprocess environment),
OPEN-09 partly (pinned + SHA-256-verified catalogue downloads). The new configuration tests fail
36/36 against the pre-fix code. Three existing tests in `test_adaptive_runtime.py` were updated to
the new credential contract (variable renamed to `UEE_CRED_TEST_KEY`, host scope added); their
assertions are unchanged.

**kiwifarms.cc rule** (`custom_sites.json`, `osint_custom.json`): Maigret's pinned upstream data
contains the same site and endpoint, so the local rule is not needed for coverage; it is a
recalibrated override. It was kept unchanged pending the owner's decision. Recommendation: remove
it before any public release to avoid shipping a hand-tuned rule for a forum associated with
harassment campaigns; coverage is unaffected.
