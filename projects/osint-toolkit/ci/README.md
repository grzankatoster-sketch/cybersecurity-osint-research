# ci

Offline quality gates and an end-to-end test for the toolkit's data pipeline. One script, `run_checks.py`, runs the same checks locally and in a CI job: repository hygiene, per-package test suites, lint on ruff-clean files, and a scan of generated artefacts for secrets and unmasked e-mail addresses. `tests/` contains an E2E test of the whole registry-to-graph chain with the network blocked.

> A Polish version of this document is in [README.pl.md](README.pl.md). Script output is in Polish.

**About the `osint-poland` registry adapter.** The original pipeline began with an `osint-poland` adapter (KRS / CEIDG / REGON registry data converted to the `org-intel` input format). That package is **intentionally not published** in this repository. The CI script detects its absence automatically: the `test:osint-poland-feed` and `lint:osint-poland-feed` steps are not created, the E2E fixture `pipe` is skipped (`pytest.skip("osint-poland registry adapter is not part of the public repository")`), and the summary lists `osint-poland` as skipped. The remaining stages (`org-intel` -> `entity-graph`) are covered by the package-level suites.

## Security use cases

- Guarding against committing case data, `.env` files or generated result folders into a public repository.
- Proving by test that the pipeline makes no network connections, leaks no secrets and keeps natural persons and full e-mail addresses out of the graph and exports.
- Making CI output safe to publish: summaries and failed-step output are masked, and uploaded artefacts are scanned first.

## How it works

| File | Role |
|---|---|
| `run_checks.py` | Step runner: `hygiene:*`, `test:*`, `lint:*`, optional `artifacts:scan`; masking and artefact scanner; exit-code convention |
| `tests/conftest.py` | `Runner` that starts `python -m <package>` sub-processes with a scrubbed environment and a network-attempt log; in-process socket blocking |
| `tests/_nonet/sitecustomize.py` | Loaded into every sub-process via `PYTHONPATH`; logs and blocks connection attempts to `CI_NONET_LOG` |
| `tests/test_pipeline_e2e.py` | E2E chain and regression tests |
| `tests/test_run_checks.py` | Tests of the script itself |
| `known_mixed_eol.txt` | Registered legacy files with mixed line endings (known debt) |
| `requirements.txt` | Pinned tool versions (pytest, ruff, and the packages needed by the unpublished adapter test) |

Steps (`python ci/run_checks.py --list`):

| Step | What it does |
|---|---|
| `hygiene:case-data` | Fails if tracked files include case data (`graph.json`, `audit.jsonl`, `graph.graphml`, `maltego.csv`, `store.json` outside `tests/fixtures/`), `wyniki/` or `org-intel-data/` folders, or `*.env` / `.env*` files other than `.env.example` |
| `hygiene:eol` | Fails on a new file with mixed (CRLF + LF) line endings in the pipeline packages |
| `test:osint-connectors`, `test:org-intel`, `test:hibp-monitor`, `test:entity-graph`, `test:meta-search`, `test:ci` | `pytest -q` in the package directory |
| `lint:*` | `ruff check` and `ruff format --check` (line length 120) on the ruff-clean files listed in `LINT_TARGETS` |
| `artifacts:scan` | With `--artifacts DIR`: writes `summary.json` / `summary.md` and scans the directory (JWT, Bearer, private key, well-known token formats, secret assignments, **every** unmasked e-mail) |

## Implemented security mechanisms

- **Network blocked twice.** An autouse fixture replaces `socket.socket.connect`, `connect_ex`, `create_connection` and `getaddrinfo` in the test process, and each sub-process loads `tests/_nonet/sitecustomize.py` which logs and blocks attempts; the log must be empty after every test (`tests/conftest.py`, `tests/_nonet/sitecustomize.py`).
- **Environment scrubbing.** Variables with the prefixes `BRAVE_`, `OSINT_`, `EG_`, `HIBP_`, `ORG_INTEL_`, as well as proxy variables, `PYTHONPATH` and `PYTHONSTARTUP`, are dropped before a step or an E2E sub-process starts (`DROP_PREFIXES`, `DROP_EXACT` in `run_checks.py`; `clean_env` in `tests/conftest.py`).
- **Masking of output.** E-mail addresses, JWTs, bearer tokens, private-key headers, known token formats and secret assignments are masked in the printed summary and in failed-step output (`mask` in `run_checks.py`).
- **Artefact scanner.** `scan_artifacts` checks the artefact directory before it is uploaded; a hit gives exit code 1 and deletes the offending file; hit descriptions never contain the matched value (`Hit.__str__`).
- **Repo hygiene gate.** `hygiene:case-data` blocks case data and environment files from being committed.
- **Fixtures are synthetic.** The E2E chain uses fictional companies and `example.test`-style addresses.
- **E2E regression coverage** (`tests/test_pipeline_e2e.py`), among others: `--report` pointing at case files is refused and the case stays byte-identical; `--dry-run` writes nothing; a foreign temporary file is refused and left untouched; re-import is idempotent; persons and full e-mail addresses never reach the case files; a required but missing proxy gives exit code 3 with zero connection attempts; records without provenance are rejected (exit codes 4 and 5).

## Data handling and privacy boundaries

- No secrets are needed or used. Only synthetic data is processed.
- The only artefacts produced are the step summaries (`summary.md`, `summary.json`), and they are scanned before use.
- `hygiene:*` outside a git checkout falls back to walking the file tree and marks the result accordingly.

## Installation

Python 3.12+. Install the pinned tooling (the pipeline packages themselves are standard-library-only and are run from their `src` directories, so they need not be installed):

```bash
cd projects/osint-toolkit
python -m venv .venv-ci
python -m pip install -r ci/requirements.txt
```

## Usage

```bash
python ci/run_checks.py                          # all steps
python ci/run_checks.py --list
python ci/run_checks.py --only test:org-intel
python ci/run_checks.py --only hygiene --only lint
python ci/run_checks.py --skip lint --fail-fast
python ci/run_checks.py --ruff "path/to/python -m ruff"   # if ruff is not in the current environment
python ci/run_checks.py --artifacts ci-artifacts         # write and scan the summary
```

Exit codes: `0` all steps OK; `1` tests or checks failed (including an artefact-scanner hit); `2` usage or environment error (unknown step, missing pytest/ruff/dependency, Python < 3.12).

## Configuration

Command-line options (`--only`, `--skip`, `--list`, `--fail-fast`, `--ruff`, `--python`, `--artifacts`) and one environment variable, `RUFF` (alternative to `--ruff`). Pinned tool versions are in `requirements.txt`; the lint scope is `LINT_TARGETS` in `run_checks.py`. The script treats the directory above `ci/` (the toolkit root) as the project root.

## Testing

```bash
cd projects/osint-toolkit/ci
python -m pytest -q
```

This runs the E2E tests and the tests of `run_checks.py`. With the registry adapter absent, the chain-dependent E2E tests are skipped.

## Limitations

- The registry stage of the chain (`osint-poland` adapter) is not covered in the published repository; see the note above.
- Lint covers only the explicitly listed ruff-clean files; there is no mypy or pyright configuration.
- The hygiene scope for line endings is limited to the pipeline packages and `ci/`; two legacy files with mixed endings are registered in `known_mixed_eol.txt`.
- `ci-artifacts/` is created in the working directory when `--artifacts` is used; delete it or add it to `.gitignore` locally.
- The GitHub Actions workflow that wraps this script lives at the repository root, outside this directory.
