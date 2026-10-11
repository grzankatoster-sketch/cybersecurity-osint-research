# Username Engine v1

Username Engine is an OSINT tool that checks whether a given username exists on several thousand websites and reports each result with a status, a confidence value and the reason for the decision. It is written in Python (asyncio, aiohttp) and is designed to prefer "unknown" over a wrong answer: a transport failure, a rate limit, a CAPTCHA or a login wall is never reported as "no account".

This is the earlier, simpler engine (version 0.1.0). It is still used by the toolkit integration: sibling tools in `projects/osint-toolkit` (for example `entity-graph` and `panel`) invoke it as a subprocess, which is why it lives in this directory. A successor, "Ultimate Username Engine", is developed separately in `projects/ultimate-username-engine`. Polish documentation for v1 is kept in [README.pl.md](README.pl.md).

## Security and OSINT use cases

- Authorised investigations: enumerating accounts that a subject has registered under a known handle or close variants, as a starting point for further, manual verification.
- Own-account exposure review: checking which public services expose a handle you use, and which have profile data (display name, bio, location, links) that is publicly readable.
- Passive reconnaissance: `--level quick` and `--dorks-only` send no requests to the target sites (see OPSEC).

Use it only where you have a lawful basis. Scanning sends the username to every selected site.

## Architecture

All modules are in `src/username_engine/`.

| Module | Responsibility |
|---|---|
| `models.py` | `Site` (catalogue rule, validated on load), `Response`, `Result`, `Status` (`FOUND`, `NOT_FOUND`, `ERROR`, `UNSUPPORTED`). |
| `sources.py` | Converts WhatsMyName and Maigret entries and the bundled custom rules to `Site`; deduplicates by normalised URL; atomic catalogue write; tolerant load (a malformed entry is skipped with a warning). |
| `urlnorm.py` | URL normalisation shared by deduplication and link comparison; `is_http_url` guard for links. |
| `engine.py` | Per-site check (`check_site`), concurrent `scan`, proxy circuit breaker, `rescan_errors` (retries on fresh circuits), name/regex guards. |
| `classify.py` | The decision function: response (plus optional control response) to status, confidence, reason. |
| `http.py` | `Fetcher` (aiohttp): public-address enforcement, SOCKS5 proxy support, TLS policy, redirects, retries, `preflight` channel check. |
| `extract.py` | Pulls name, bio, location, avatar, website, links from a confirmed profile (JSON API or HTML meta/JSON-LD). Offline; stores no page body. |
| `correlate.py` | Rates whether accounts found under different name variants belong together; output is an evidence level, not a probability. |
| `geo.py` | Offline country inference from profile hints (location text, flag emoji, language, domain). |
| `variants.py` | Username variants from a handle or a person's name, capped by `--max-variants`. |
| `dorks.py` | Search-engine query links (never fetched) and Wayback CDX queries/parsing. |
| `health.py` | Catalogue health states (dead, blocked, false positive, stale, unstable) stored in `data/health.json`. |
| `retention.py` | Per-scan directories, manifests and expiry purge. |
| `report.py` | Single-file HTML report and CSV export. |
| `fsutil.py` | Atomic file writes. |
| `cli.py` | Argument parsing, channel selection, orchestration, exit codes, terminal output. |

Scripts in `scripts/`: `build_db.py` (build the site catalogue), `build_geo.py` (optional GeoNames gazetteer), `health_check.py` (catalogue health), `calibrate_sites.py` (verify candidate rules against live sites before adding them to `resources/custom_sites.json`). `metryki/trafienia.py` is a classification test set built from synthetic `.example` rules. `START_USERNAME_ENGINE.cmd` is a Windows convenience launcher.

## Detection and evidence logic

Each site check ends in one of four statuses (`models.py`):

| Status | Meaning |
|---|---|
| `FOUND` | Account likely exists; `confidence` 0-1 and `reason` explain why. |
| `NOT_FOUND` | The site answered and the evidence indicates no account. |
| `ERROR` | Undecidable: network failure, rate limit, challenge, login wall, 5xx, unreliable rule. |
| `UNSUPPORTED` | The name does not satisfy the site's rules; no request was sent. |

Each result also carries `http_status`, `channel` (`direct`, `proxy`, `proxy-retry`, `fallback`), matched presence strings (`evidence`), extracted profile fields and an `insecure` flag.

A check is decided in `classify.classify` (`classify.py`) in this order:

1. **Blocks first** (`_blocked`). No response, HTTP 429, 5xx, a Cloudflare/DDoS-Guard challenge marker on a 403/503, and 401/403/407/451 without a matching "absent" rule all return `ERROR`.
2. **Rule evidence** (`_evidence`). Order: absence string or absence status code gives `NOT_FOUND`; HTTP 202 and redirects to a login path give `ERROR`; an unrecognised status code gives `ERROR` (only 404/410, or a 2xx where the rule discriminates by status code, give `NOT_FOUND`); a redirect away from the profile or to the site's own search page gives `NOT_FOUND`; a presence string gives `FOUND` (0.90).
3. **Presence strings are bound to the name.** A string containing `{username}` must match the checked name (case-insensitive), and a trailing `{username}` must not be followed by further name characters, so `alice1` does not confirm `alice` (`_has_presence`). Search-based endpoints require the exact name in the response (`_exact_name`).
4. **Control request** (`engine.check_site`). For rules without presence strings the engine requests a random name (length 14, shorter if the site's regex requires) in parallel. For rules with presence strings the control is requested lazily, only after a hit. If the control also looks like `FOUND` the result becomes `ERROR` "rule unreliable: matches a random name" (`classify.py:274-277`); if the control is a clear `NOT_FOUND`, confidence rises to 0.97.
5. **Rules with no text** (status code only) are decided by comparing with the control: different status and a page that is not the same page after removing the name gives `FOUND` 0.80; no usable control gives 0.45; a page that differs only by content gives 0.50; a same-page match gives `NOT_FOUND` (soft 404). Page equality requires similar length, equal title and at least 0.8 word overlap (`_same_page`).
6. **Guards.** Responses cut at the 2 MB body cap (`truncated`) never prove absence. A password form instead of a profile gives `ERROR`. If a rule knows both presence and absence strings and the page matches neither, the result is `ERROR`. Rules flagged `absence_unproven` never yield `NOT_FOUND` from a missing marker.
7. **Untrusted regexes.** Catalogue name patterns longer than 500 characters or with nested unbounded quantifiers (a ReDoS heuristic in `engine.has_nested_quantifier`) are not used: the site returns `UNSUPPORTED` without a request. Names over 128 characters are rejected the same way.

Hits below `--min-confidence` (default 0.6) are hidden in terminal output. `NOT_FOUND` results carry `not_found_kind`: `negative_match` (the rule affirmatively said "absent") or `no_match_default` (inferred from a missing marker).

Correlation (`correlate.py`) treats copyable fields (website, avatar, display name, bio, location, one-way link) as one dependent group capped at "moderate"; only reciprocal links yield "strong". Default or name-generated avatars, avatars shared by three or more services, and page titles used as display names are discarded as noise. The same rule is used in `entity-graph`.

## OPSEC

Only behaviour implemented in the code is listed.

- **Channel selection** (`cli.py`, `resolve_network`): `--proxy URL` or `OSINT_PROXY`; `--proxy-fallback`/`OSINT_PROXY_FALLBACK` for a second proxy; `--direct` forces direct traffic, ignores both environment variables and conflicts with the proxy options. Without any of them the scan is direct and the terminal says so.
- **SOCKS5 only.** `socks5://` and `socks5h://` are accepted; HTTP proxies are rejected (`http.py:107-109`). Target hostnames are resolved by the proxy (`rdns=True`), so no local DNS query is made for targets.
- **Fail-closed.** Before any target request, `preflight` queries `check.torproject.org/api/ip` through the proxy. A failure exits with code 3 and sends no direct traffic (`cli.py:196-223`, `392-394`). A proxy that is not a Tor exit (`IsTor=false`) triggers a warning and the scan continues. A proxy failure during a scan never falls back to a direct connection.
- **Circuit breaker.** After 15 consecutive "proxy unreachable" results (`PROXY_ABORT_AFTER`, `engine.py`) the scan stops, the remaining sites are recorded as `ERROR` (never `NOT_FOUND`), a partial report is written and the exit code is 3. This breaker applies to proxy channels only.
- **Circuit isolation.** Each `Fetcher` gets a random SOCKS username (Tor stream isolation) unless the proxy URL carries credentials. Proxy URLs are never printed or stored with credentials (`proxy_label`).
- **Retries.** Only transport failures with no HTTP response are retried on a new circuit (`--proxy-retries`, default 2), then once through the fallback proxy. Responses such as 401/403/429, CAPTCHA, login walls and 5xx are not retried, so a block is not circumvented by changing identity (`engine.rescan_errors`).
- **TLS.** Direct mode: on a certificate error the request is repeated without verification and the result is marked `insecure` (confidence capped at 0.6, no profile extraction, excluded from correlation and geo inference). `--strict-tls` disables the retry. Through a proxy the unverified retry is never performed; the CLI does not expose the override.
- **Rate limiting.** Two connections per host, 50 overall, 50 concurrent checks. Retries use exponential backoff (cap 10 s); `Retry-After` is a minimum, upward jitter only; waits over 60 s are not taken. A 429 gets at most one retry of up to 30 s, then `ERROR` "rate limited". There is no per-site circuit breaker.
- **Request restrictions.** Methods GET, HEAD and POST only; at most 5 redirects, each target re-checked; 2 MB body cap. In direct mode the resolver rejects loopback, private, link-local, multicast and reserved addresses at connect time (`SafeResolver`). Through a proxy the resolved address is not visible to the client, so only literal IPs and `.localhost`, `.local`, `.internal`, `.onion` names are refused.
- **Fingerprint.** The default User-Agent is a generic desktop Chrome string; per-site headers from the catalogue are sent as given. The Meta rules that relied on a link-preview crawler User-Agent were removed.
- **Passive features.** `--dorks`/`--dorks-only` build search links for you to open manually; nothing is fetched. `--level quick` queries only the Wayback CDX API. Wayback and any other traffic use the selected channel.
- **Caveat.** `scripts/build_db.py`, `build_geo.py`, `health_check.py` and `calibrate_sites.py` have no proxy option and connect directly.

## Data retention and report safety

- Every scan with an export (`--report`, `--csv`, `--json`) writes into `<results-dir>/<scan-id>/` with a `manifest.json` (creation time, expiry, file names, sizes, SHA-256). The manifest does not contain the username. Default lifetime is 12 hours (`--ttl-hours`; `0` disables expiry and must be explicit). Default results directory is `wyniki/` in the project directory (git-ignored).
- `python -m username_engine purge [--results-dir DIR] [--dry-run]` removes expired scans; the same purge runs at the start of every scan. There is no background service: expired data persists until one of these runs.
- Deletion is restrictive (`retention.py`): only direct subdirectories whose name is a scan id with a matching manifest and a past expiry; symlinks, junctions, nested directories and foreign files are skipped; the directory is first renamed atomically to `.usuwanie-...`. Files are removed with ordinary unlink (no overwrite). An append-only `usuniecia.jsonl` records scan id, timestamps, file count and hashes, without username or content. Copies made by the user are outside retention.
- HTML report (`report.py`): one file, no JavaScript and no external resources; every dynamic value passes through `html.escape`; links are emitted only for http/https URLs (`rel="noreferrer noopener"`), other schemes are plain text. No Content-Security-Policy is set by the file itself; if you serve reports, add one at the server.
- CSV neutralises formula injection (`csv_safe`). Terminal output escapes control characters from untrusted fields. Raw profile data (location, nationality, names, websites) is printed only with `--details`; the HTML and JSON reports contain it, so treat them as personal data. Exports are written atomically.
- Output file names must be plain names (`retention.safe_output_name`); paths, drive letters and reserved names are rejected.

## Installation

Requires Python 3.12 or newer.

```bash
python -m pip install aiohttp aiohttp-socks pytest
python scripts/build_db.py          # builds data/sites.json (required)
python scripts/build_geo.py         # optional: GeoNames gazetteer for country inference
python scripts/health_check.py      # optional: marks dead/blocked entries (several minutes)
```

The site catalogue is not shipped. `build_db.py` downloads, over HTTPS without pinning or checksum:

- `https://raw.githubusercontent.com/WebBreacher/WhatsMyName/main/wmn-data.json`
- `https://raw.githubusercontent.com/soxoj/maigret/main/maigret/resources/data.json`

and merges them with the bundled `resources/custom_sites.json` (own calibrated rules take precedence on duplicates) and `resources/tag_overrides.json`. Both downloads track the upstream `main` branch, so results can change between builds; `--wmn` and `--maigret` accept local files instead. The build records sources, URLs and licences in the `meta` block of `data/sites.json`. `build_geo.py` fetches GeoNames data (CC BY 4.0) from `download.geonames.org`; without it a built-in dictionary is used.

The package is not installed; run it with `src` on the path.

## Usage

```bash
export PYTHONPATH=src               # cmd: set PYTHONPATH=src
python -m username_engine alice --no-variants --tags social,pl
python -m username_engine alice --sites GitHub,Reddit --no-variants --report alice.html --json alice.json
python -m username_engine Sampler51 --show-variants          # list variants, no network
python -m username_engine "Jane Doe" --dorks-only            # search links only, no catalogue, no scan
python -m username_engine alice --level quick --proxy socks5h://127.0.0.1:9150
python -m username_engine alice --level standard --proxy socks5h://127.0.0.1:9150 --report alice.html
python -m username_engine alice --direct --strict-tls --all
python -m username_engine purge --dry-run
```

Variants are enabled by default: unless `--no-variants` is given, up to `--max-variants` (6) names are scanned, the typed name first. `--level` selects `quick` (Wayback and dork links only), `standard` (sites tagged `social` or `pl`, plus `--tags`, with Wayback) or `full` (default). Sites listed in `data/health.json` as dead, blocked or false-positive are skipped unless `--include-broken` is given. Exit codes: 0 success, 1 an export or analysis step failed, 2 invalid options or catalogue, 3 proxy unavailable or lost.

## Testing

```bash
python -m pytest
```

`pytest` is configured in `pyproject.toml` (`pythonpath = ["src"]`, `testpaths = ["tests"]`). HTTP tests run against a local loopback server. `tests/_lab/` holds additional regression tests produced by an automated internal process; they run with the rest of the suite.

## Third-party data and licensing

- WhatsMyName site data: CC BY-SA 4.0. Maigret site data: MIT. Both are fetched at build time into the local, git-ignored `data/sites.json` and are not redistributed in this repository. Entries record their origin (`source`). If you redistribute a built catalogue, the upstream licence terms (attribution, and share-alike for WhatsMyName data) apply to that file.
- GeoNames data (optional gazetteer): CC BY 4.0, also fetched at build time.
- `resources/custom_sites.json` contains this project's own rules.

## Limitations

- A matching username is a lead, not proof of identity. The same handle is routinely held by different people. Correlation output is an evidence level for further manual checking.
- Coverage is limited to the catalogue; entries age, and rules can break when sites change. Run `health_check.py` after each build.
- Sites that block automation (anti-bot challenges, 403, login walls, rate limits) yield `ERROR` with the reason, not `NOT_FOUND`. They appear in the "to check manually" list and need a browser. A meaningful share of a full scan can end this way.
- `NOT_FOUND` with `no_match_default` is an inference from a missing marker, not an explicit statement by the site.
- Facebook, Instagram and Threads have no rules; use `--dorks` and manual review. `build_db.py` has no explicit exclusion for them; the test `test_built_db_has_no_meta_rules_nor_crawler_user_agent` checks the built catalogue.
- Country and account-linking output is inferred from public profile text and can be wrong.

## Roadmap

Planned (not implemented): none is documented in this directory. The successor project covers further development.
