# meta-search

Lookups in Meta services through their **official APIs only**, behind one common result contract: Threads (profile lookup, keyword search), Instagram Business Discovery and public Facebook Page data (Graph API). Standard library only; no scraping fallback.

> A Polish version of this document is in [README.pl.md](README.pl.md). Console and report text is in Polish.

## Security use cases

- Verifying whether a handle or brand has an official presence on Threads, Instagram (professional accounts) or Facebook (Pages), using your own app credentials.
- Producing attributable, timestamped lead records (`found` / `no_result` / `rate_limited` ...) for `entity-graph` to import.
- Generating manual-check links for a handle without fetching anything.

A match on a handle does not confirm identity: every result is a lead to verify, and the contract carries that caveat.

## How it works

| Module | Role |
|---|---|
| `src/meta_search/config.py` | Loads tokens and proxy settings from the environment or an env-file outside the repository; never prints values |
| `src/meta_search/contract.py` | `MetaResult` with statuses `found`, `no_result`, `not_configured`, `auth_error`, `permission_denied`, `rate_limited`, `source_error`, `invalid_input`, `manual`; exit-code mapping |
| `src/meta_search/graph.py` | Shared Graph API client: transport, pinned proxy, error classification, token redaction, field sanitising |
| `src/meta_search/threads.py`, `instagram.py`, `facebook_pages.py` | Thin per-service clients on top of `graph.py` |
| `src/meta_search/links.py` | Manual links for a handle (`manual` status; nothing is fetched) |
| `src/meta_search/report.py`, `cli.py` | HTML report, CLI, retention `purge` command |

Result fields (`--json`): `tool`, `schema`, `platform`, `operation`, `query`, `status`, `source{kind, endpoint, api_version}`, `fetched_at`, `items`, `message`, `caveats`, `http_status`, `error_code`.

## Implemented security mechanisms

- **Tokens never surface.** Token values are redacted from endpoints, queries, messages and error text, including URL-encoded variants and any `access_token=` parameter (`redact`, `_scrub`, `GraphClient._result` in `graph.py`). `config` prints only "set / missing" (`Config.describe`, `config.py`).
- **Env-file outside the repository.** A configuration file located inside the repository tree is ignored with a warning (`_inside_repo` in `config.py`); the environment takes precedence over the file.
- **No traffic without configuration.** Missing token/configuration yields `not_configured` and nothing is sent (`_not_configured` in `graph.py`).
- **Fail-closed proxy.** `META_PROXY` pins all traffic to one HTTP(S) proxy using a CONNECT tunnel, HTTPS only; `NO_PROXY`, system exceptions and `*_PROXY` variables cannot bypass it. A malformed proxy, or `META_REQUIRE_PROXY=1` with a token and no proxy, blocks all requests rather than falling back to a direct connection (`_PinnedProxy`, `proxy_transport` in `graph.py`; `load_config`). SOCKS/Tor is deliberately unsupported.
- **No redirects and bounded bodies.** Redirects are not followed (the request URL carries the token) and responses are capped at 2 MB (`_NoRedirect`, `MAX_BODY`).
- **Controlled retries.** One retry for transient errors only (network, 5xx, Graph codes 1/2); none for rate limits or authorisation errors (`GraphClient._call`).
- **Error classification.** Graph error codes map to explicit statuses; ambiguous errors become `source_error` with a non-zero exit code and are never treated as an empty search result (`GraphClient._failure`).
- **Input validation.** Handle syntax is validated (`USERNAME` regex), API version strings are validated, the Instagram user id must be numeric, and token format is sanity-checked (`config.py`, `graph.py`).
- **Output sanitising.** API text has control characters stripped and is length-limited; URLs from the API are accepted only with an allowed scheme and without credentials (`clean`, `https_url` in `graph.py`). The HTML report is script-free and escapes every API value (`report.py`); terminal output escapes control characters (`safe` in `cli.py`).
- **Atomic report writes** (`_write` in `cli.py`).
- **Retention.** `purge` lists (default) or deletes (`--delete`) `meta_*.json`/`.html` files older than N days, touching only regular files with matching names directly in the given directory (not symlinks, not subdirectories) (`purge` in `cli.py`).
- **No automatic fallback to scraping** after an API failure.

## Data handling and privacy boundaries

- Official APIs and your own credentials only; no HTML scraping, no login emulation, no CAPTCHA handling.
- Platform limits as documented by Meta at the time of writing: `profile_lookup` covers public profiles meeting Meta's follower threshold (100 followers); `keyword_search` without approved permission returns only the token owner's posts; Instagram Business Discovery sees professional accounts only; private and personal accounts are invisible.
- Results can contain public profile fields and post excerpts. Delete result files when they no longer serve a purpose (`purge`).
- The `entity-graph` importer for this format keeps provenance (API endpoint, retrieval time) and does not carry post text or bio text; for profiles it keeps comparison signals only (website, URLs found in the bio, and a bio fingerprint of hashed word tokens) (`entity-graph/src/entity_graph/importers/meta_search.py`).
- Your requests identify your Meta app/token holder to Meta; a stable egress IP (via `META_PROXY` or a system VPN) is recommended over rotating addresses.

## Installation

Python 3.12+; no dependencies. The package has no installable build configuration; run it from the package directory with `PYTHONPATH=src`.

```bash
cd projects/osint-toolkit/meta-search
export PYTHONPATH=src            # Windows (cmd): set PYTHONPATH=src
python -m pip install pytest
```

## Usage

```bash
python -m meta_search config                                  # configuration state, no secrets
python -m meta_search threads-profile alice --json out.json --html out.html
python -m meta_search threads-search "osint" --type RECENT --limit 25 [--author alice]
python -m meta_search instagram-profile alice --media 5 --json out.json
python -m meta_search facebook-page example --html page.html
python -m meta_search links alice                            # manual links only
python -m meta_search purge ./results --days 30 [--delete]   # preview unless --delete
```

Exit codes: `0` result / no result / links; `1` source error; `2` invalid query; `3` not configured; `4` token or permission problem; `5` rate limited.

## Configuration

Names only; values come from the environment or from `~/.osint/meta.env` (override the path with `META_SEARCH_ENV_FILE`).

| Variable | Purpose |
|---|---|
| `THREADS_ACCESS_TOKEN`, `THREADS_API_VERSION` | Threads API |
| `INSTAGRAM_ACCESS_TOKEN`, `INSTAGRAM_USER_ID` | Instagram Business Discovery (token owner's professional account id) |
| `FACEBOOK_ACCESS_TOKEN` | Facebook Pages |
| `GRAPH_API_VERSION` | Graph API version for Instagram and Facebook |
| `META_PROXY`, `META_REQUIRE_PROXY` | Pinned HTTP(S) proxy; `1` = block requests when no usable proxy |
| `META_SEARCH_ENV_FILE` | Alternative env-file path |

## Testing

```bash
cd projects/osint-toolkit/meta-search
python -m pytest -q
```

Tests use a fake transport and local subprocesses; they need no network access or credentials.

## Limitations

- No authorised calls to the three live APIs were made when this package was reviewed; limits, fields and permission requirements must be confirmed with your own Meta app.
- `no_result` does not prove an account does not exist.
- Only the first page of results is fetched; paging is not implemented. Searching Pages by phrase (`/pages/search`) is not implemented because its requirements were not confirmed.
- Facebook responses lacking `category`/`fan_count` are rejected; Business Discovery media is limited to 0-50 items, one page.
- `threads-search` is limited to one page (up to 100 items).
