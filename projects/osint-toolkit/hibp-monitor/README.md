# hibp-monitor

Defensive monitor built on the official [Have I Been Pwned](https://haveibeenpwned.com) (HIBP) API for **your own domains and your own passwords**. It reports new public breaches in which a service on a monitored domain was the source, exposes the public breach catalogue as metadata, checks a password with the k-anonymity range API, and (optionally, paid) summarises accounts of a domain you have verified on your HIBP account.

> A Polish version of this document is in [README.pl.md](README.pl.md). Console output is mostly Polish.

## Security use cases

- Notification-by-diff: which breaches involving your domains appeared since the last run (state kept locally).
- Feeding incident metadata (name, date, size, data classes, quality flags) into `org-intel` / `entity-graph` without any account data.
- Checking whether a candidate password appears in known breach corpora, without sending it or its full hash anywhere.
- Aggregate exposure counts for a domain you own (paid HIBP key and verified domain).

## How it works

| Module | Role |
|---|---|
| `src/hibp_monitor/http.py` | Minimal stdlib HTTP client with injectable transport and sleep; 429 handling; key-target check; redirect refusal |
| `src/hibp_monitor/breaches.py` | `/breaches?domain=` and full catalogue (`/breaches`), `Breach` model, state file, diff of new breaches, TOML config |
| `src/hibp_monitor/passwords.py` | Pwned Passwords range lookup (SHA-1 prefix) |
| `src/hibp_monitor/domain_search.py` | Paid `breacheddomain` endpoint, aggregation |
| `src/hibp_monitor/cli.py` | Sub-commands `breaches`, `password`, `domain-search` |

A breach is "new" if its name is unknown, or its `AddedDate` is later than the stored marker. The first run per domain is a baseline.

## Implemented security mechanisms

- **Key only to HIBP, only over HTTPS.** Any request carrying `hibp-api-key` is checked by `check_key_target` (`http.py`): scheme must be `https`, host exactly `haveibeenpwned.com`, no credentials in the URL, port 443 only.
- **Redirects rejected.** `NoRedirectHandler` raises on any redirect, because `urllib` would otherwise forward headers (including the key) to the new location (`http.py`).
- **Key from environment only.** `HIBP_API_KEY` is the sole source; it is never read from files or CLI arguments, and without it `domain-search` stops with a message and no network traffic (`get_api_key` in `domain_search.py`). The package does not use the `logging` module.
- **k-anonymity for passwords.** Only the first five hex characters of the SHA-1 are sent, with `Add-Padding: true`; the suffix is matched locally and padding rows (count 0) are ignored (`passwords.py`). The prompt uses `getpass` and aborts if the terminal cannot suppress echo (`_secure_getpass` in `cli.py`).
- **Strict response parsing.** Non-JSON, wrong-shape or empty responses raise an error instead of being interpreted as "no breach" (`parse_breaches`, `parse_range`). Quality flags are true only for explicit truth values (`_flag`).
- **Bounded input.** Response bodies are capped at 20 MB (`read_limited`); `Retry-After` is clamped to 120 s; retries on 429 are limited to 3 (`HttpClient.get`); a 1.6 s pause is inserted between domains (`cli.py`).
- **Domain validation** with a strict regex (`normalize_domain` in `breaches.py`).
- **Terminal safety and minimisation.** Control characters from API data are rendered as `\xNN` (`safe_text`); descriptions have HTML stripped; the JSON catalogue output contains no logo paths and no account data (`Breach.to_dict`).
- **Atomic state writes** via temporary file and `os.replace` (`breaches.py`).
- **Default aggregation.** `domain-search` returns per-breach counts; addresses are shown only with `--show-addresses` (`domain_search.py`).

## Data handling and privacy boundaries

- Only the official HIBP APIs are used. No third-party breach-content services, and no linking of data to individuals.
- `breaches` and `password` need no key and never transmit one.
- The password is never logged, stored or printed; only a 5-character hash prefix leaves the machine.
- `domain-search` is limited by HIBP itself to domains verified on your account (a 404 means "not verified"). It is not a way to look up other people's addresses.
- Local state (`state.json`, next to `config.toml`) holds known breach names, an `AddedDate` marker and the last-run time. `config.toml` and `state.json` are git-ignored.
- HIBP terms apply (attribution under CC BY 4.0 for catalogue data, an honest User-Agent, request limits, no queries intended to harm breach victims).

## Installation

Python 3.12+; no runtime dependencies (stdlib `urllib`).

```bash
cd projects/osint-toolkit/hibp-monitor
python -m venv .venv
python -m pip install -e ".[dev]"
cp config.example.toml config.toml     # set your own domains and a User-Agent
```

On Windows, `START_HIBP_MONITOR.cmd` bootstraps `.venv` and `config.toml` and provides the alias `hibp`.

## Usage

```bash
python -m hibp_monitor breaches                        # only NEW breaches since the last run
python -m hibp_monitor breaches --domain example.com --no-save
python -m hibp_monitor breaches --catalog --since 2026-09-01 --limit 10 --json
python -m hibp_monitor password                        # prompts without echo
python -m hibp_monitor domain-search example.com       # paid key + verified domain
```

Exit codes: `0` OK; `2` usage/configuration error or missing key; `3` network or API error.

## Configuration

| Item | Purpose |
|---|---|
| `config.toml` (from `config.example.toml`) | `domains`, `user_agent`, `state_file` |
| `HIBP_API_KEY` (environment) | Paid key for `domain-search` only |
| `--user-agent` | Overrides `user_agent` from the config |

If no User-Agent is configured the client falls back to a built-in default (`DEFAULT_USER_AGENT` in `http.py`).

## Testing

```bash
cd projects/osint-toolkit/hibp-monitor
python -m pytest -q
```

Tests use a fake HTTP client and fixtures in `tests/fixtures/`; no network access is required. `tests/test_security.py` and `tests/test_catalog_boundary.py` cover key handling and endpoint boundaries.

## Limitations

- `breaches?domain=` lists breaches where a service on that domain was the **source**, not breaches containing `@domain` addresses; the latter needs the paid `domain-search`.
- "New" is based on name and `AddedDate`; later modifications (`ModifiedDate`) are not reported.
- No notifications; schedule the command externally and consume `--json`.
- The paid `domain-search` endpoint has not been exercised against the live service (no key available); tests use fixtures.
- No hit for a password does not mean it is strong; a hit means it should be changed everywhere.
