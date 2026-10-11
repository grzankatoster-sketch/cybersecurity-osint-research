# panel

A local, browser-based control panel that orchestrates the toolkit's command-line packages. It is a single-file standard-library HTTP server (`app.py`) plus a static page (`index.html`) bound to `127.0.0.1`. It starts each tool as a sub-process from that tool's own virtual environment, shows the output together with a result "data sheet" (source, time, status, network channel, limitations, SHA-256), and serves HTML reports in a sandboxed frame.

> A Polish version of this document is in [README.pl.md](README.pl.md). The UI is in Polish.

## Security use cases

- One local front end for the DNS, phone, HIBP, EXIF, username, e-mail/domain (theHarvester) and Meta tools, with consistent result statuses.
- Case management on top of `entity-graph` (create a case, record relation claims with sources, confirm or reject candidates, view the audit log, download GraphML / Maltego CSV).
- Keeping the operator's network channel explicit (Tor by default for the username scan, direct only when requested).

## How it works

| Item | Role |
|---|---|
| `app.py` | HTTP handler, request validation, command builders (`build_command`, `build_case`, `build_meta`), sub-process launcher (`launch`, `tool_env`), report serving (`safe_report_path`), result classification (`classify`, `envelope`) |
| `index.html` | UI tabs: username, e-mail and domain, DNS, phone, EXIF, Meta, Case (`entity-graph`), Laboratory |
| `tests/` | `test_panel.py`, `test_sprawa.py`, `test_profile_search.py`, `test_metryczka.py` |

Tools map to packages in `TOOLS` (`app.py`): `dns-audit`, `phone-check`, `hibp-monitor`, `exif-map`, `username-engine`, `meta-search`, `entity-graph`. theHarvester is launched from a venv under `narzedzia/` (the third-party tool is not part of this repository).

Result statuses never conflate failure and emptiness: `found`, `no_result`, `error`, `blocked`, `partial`. A proxy/Tor failure, a timeout with partial output, or a source block is never shown as "no result".

## Implemented security mechanisms

- **Loopback only, session token.** The server binds to `127.0.0.1`; the `Host` header must be `127.0.0.1` or `localhost`; every POST and every data-bearing GET (`/api/raporty`, `/api/sprawy`, `/api/postep`, `/api/lab`, `/api/sprawa_plik`) requires the per-process `X-Panel-Token`, compared with `secrets.compare_digest` (`Handler`, `TOKEN` in `app.py`).
- **Strict request typing.** The POST body must be a JSON object (else HTTP 400), of bounded size, and each field must have the expected type (else HTTP 422); in both cases no tool starts (`do_POST`, `_text`, `_flag`, `_opt_int`, `BadField`).
- **No shell, no option injection.** Sub-processes get an argument list; free-text fields that begin with `-` are rejected (`_req`).
- **Path safety.** Case names must match a safe pattern and resolve to a direct sub-directory of `panel/wyniki/sprawy/`; symlinks, junctions, `..`, drives and absolute paths are refused before anything runs (`case_dir`). Reports are served only from `wyniki/` under a safe file name (`safe_report_path`); downloads are limited to `graph.graphml` and `maltego.csv` of a case (`case_file`).
- **Response headers.** `X-Content-Type-Options: nosniff`, `Cache-Control: no-store`, and a CSP on every response: a nonce-based CSP for the main page, `default-src 'none'` for API responses, and for reports `default-src 'none'; style-src 'unsafe-inline'; img-src data:` plus `sandbox`. EXIF maps get a sandbox CSP without the network restriction because they need Leaflet and tiles (and carry their own warning banner).
- **Secret hygiene for sub-processes.** Case tools (`entity-graph`) run with an environment stripped of variables whose names contain KEY/TOKEN/SECRET/PASSWORD/PASSWD/CREDENTIAL; the only exception is the Brave key for the profile-search tool. The Brave variable is removed for every other tool, and the key is never accepted from a form (`tool_env`, `launch`).
- **Password handling.** A HIBP password check sends the password to the sub-process via `stdin`, never via arguments; only the 5-character SHA-1 prefix leaves the machine (`check_password_proc`). Operator-supplied material (up to 20,000 characters) also goes via `stdin`.
- **Concurrency limits.** A global cap of four concurrent tool sub-processes and one long scan at a time (HTTP 429 / 409 otherwise), with per-tool timeouts (`MAX_PROCS`, `_LONG_LOCK`, `TIMEOUTS`).
- **Fail-closed network channels.** `OSINT_PROXY` (default Tor Browser SOCKS endpoint) is passed to the tools; the Meta tool is run with `META_REQUIRE_PROXY=1`. Behaviour when the channel is down is implemented in the respective tools (`username-engine`, `meta-search`, `entity-graph`).
- **Quiet logging.** The request log omits query strings and bodies (`log_message`).

## Data handling and privacy boundaries

- All results are written under `panel/wyniki/` (reports and case folders). Cases do not expire automatically; delete a case folder when the purpose ends. Scan reports and Meta results can be pruned (`meta-search purge`).
- The laboratory tab reports whether configuration variables are set, never their values.
- The panel does not collect person data on its own, does not accept file paths from the browser, and deliberately omits phone variant/dork search and phone location from its phone tab.
- The page is served with the session token embedded; anything able to reach `127.0.0.1` with a valid `Host` header can fetch it. Run it only on a single-user workstation.

## Installation

Python 3.13+ is expected by the launcher (`START_PANEL.cmd` looks for a Python under `%LOCALAPPDATA%`, then on `PATH`). The panel itself needs only the standard library; the tools it launches use their own `.venv` (create each with its `START_*.cmd`) or fall back to the current interpreter.

```bash
cd projects/osint-toolkit/panel
python app.py              # add --no-browser to skip opening a browser
```

## Usage

Open `http://127.0.0.1:8765/`. On Windows, `START_PANEL.cmd` starts the server and opens the browser.

## Configuration

| Variable | Purpose |
|---|---|
| `OSINT_PANEL_PORT` | Listening port (default 8765) |
| `OSINT_PROXY` | Network channel for the username scan and for tools launched indirectly; defaults to a Tor Browser SOCKS endpoint on the loopback interface |
| `BRAVE_SEARCH_API_KEY` | Passed only to the profile-search tool of a case |
| `META_PROXY` | Pinned proxy for the Meta tool (panel sets `META_REQUIRE_PROXY=1`) |
| `HIBP_API_KEY`, `THREADS_ACCESS_TOKEN`, `INSTAGRAM_ACCESS_TOKEN`, `FACEBOOK_ACCESS_TOKEN` | Only reported as set / not set in the Laboratory tab; consumed by the respective tools |

## Testing

```bash
cd projects/osint-toolkit/panel
python -m pytest -q tests
```

Tests run without network access (they exercise command building, validation and the HTTP handler locally).

## Limitations

- Windows-oriented launcher; `app.py` assumes a Windows layout for the username-engine interpreter and the theHarvester venv (`UE_PY`, `HARVESTER_PY`), falling back to the current interpreter where it can.
- A full username scan needs the browser tab to stay open; background jobs and resume are not implemented (listed as "to do" in the Laboratory tab).
- The username-engine package is documented separately and is launched by the panel from its sibling directory.
- `app.py` contains a static "Laboratory" status block (`LAB_STATUS`) that reflects the original author's working notes and refers to topics outside this toolkit; treat it as informational text, not as documentation of this repository.
- Concurrent writes to a single case are not serialised by the panel (a per-case lock is listed as an open item in the same block).
