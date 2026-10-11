# Ultimate Username Engine

An evidence-based username research engine in Python. For a given username it checks a large catalogue of site definitions and reports, per service, whether a public profile exists, with the evidence behind the verdict. It keeps the verdict (`FOUND`, `PROBABLE`, `NOT_FOUND`, `UNKNOWN`) separate from the execution state, never reports a block or an error as "no account", and abstains when the evidence is insufficient. It is the successor of the simpler [Username Engine v1](../osint-toolkit/username-engine) and is aimed at security engineers and OSINT practitioners who want explainable results and bounded, auditable network behaviour.

Status: working research code, version 0.1.0. It is not a finished product, it was measured on a small self-built benchmark, and parts of the data it needs are not published (see below).

## Contents

| Path | What it is |
|---|---|
| [`ULTIMATE_USERNAME_ENGINE/`](ULTIMATE_USERNAME_ENGINE) | The Python package, CLI, tests, tools and design documents. Start with its [README](ULTIMATE_USERNAME_ENGINE/README.md) (architecture, evidence model, modes and budgets, OPSEC, installation, usage, licensing, limitations). |
| [`bench/`](bench) | Benchmark harness: scan runners, evaluators and analysis tools. The labelled ground truth and results are not published. |
| [`docs/BENCHMARK.md`](docs/BENCHMARK.md) | Benchmark methodology, results by phase (including the failed gates), cost, limitations and threats to validity, and how to reproduce the method with your own labelled data. |
| [`docs/SECURITY_ARCHITECTURE.md`](docs/SECURITY_ARCHITECTURE.md) | Threat model and the implemented egress, parsing and report-safety controls mapped to code and tests, with the known gaps. |
| [`ULTIMATE_USERNAME_ENGINE/docs/design/`](ULTIMATE_USERNAME_ENGINE/docs/design) | English translations of four design documents: evidence model, budget architecture, fallback architecture, block classification. Polish originals are kept next to the package. |

## Read this before relying on it

- **Benchmark in one paragraph.** On a labelled holdout of 159 pairs (151 evaluated) the engine reached precision 1.000 and recall 0.769 in the last full integrated measurement (0.779 after the extraction stage), up from recall 0.212 at the baseline, at the cost of 34.5% more requests in exhaustive mode. Two development gates failed: the recall gate (0.769 against 0.80) and the identity gate (0 of 6 target accounts recognised on the holdout). The earlier v1 engine had higher recall on the same holdout (0.962), although that figure is inflated by the sampling design. The holdout is small, was labelled by LLM agents and covers three reference usernames. Read [BENCHMARK.md](docs/BENCHMARK.md) for the numbers with their limitations.
- **Security posture.** Egress controls (SSRF checks on every request and redirect hop, bounded bodies, single-hop transport, an allowlist forward proxy as a library component) were tested with internal adversarial tests against loopback and mock targets only. There has been no external penetration test. The CLI scans directly from your network address unless you pass a proxy. See [SECURITY_ARCHITECTURE.md](docs/SECURITY_ARCHITECTURE.md), including the gaps.
- **Not published.** The site catalogue (`data/catalog.json`) and the import records are derived from third-party data (Maigret, Sherlock, WhatsMyName and Blackbird metadata) and must be rebuilt locally from donor snapshots with `tools/import_catalogs.py`; instructions are in the package README. The labelled benchmark data, raw scan results, and the fixture suites `tests/golden_detection` and `tests/recall_detection` (captured real profile pages) are also not published, so some tests may be skipped or fail in a fresh checkout. Unmerged branches (`cyber-opsec`, `adaptery-platform`, `feature/email-engine`) are not part of this release.
- **Responsible use.** A scan sends the username to every selected site. Use it only with a lawful basis and authorisation, treat outputs as personal data, and remember that a matching username is a lead, not proof of identity.

## Quick start

```bash
cd ULTIMATE_USERNAME_ENGINE
python -m pip install -e ".[dev]"
username-engine demo alice --site found --output -     # offline fixtures, no network, no catalogue
python -m pytest tests/opsec                            # egress-control tests
```

A real search needs the locally rebuilt catalogue; see "Rebuilding the catalogue" in the package README.
