# osint-connectors

A small, clean-room core for OSINT "connectors": a plug-in registry, a uniform result record, a bounded asynchronous runner with per-connector error isolation, and privacy-preserving target references. It borrows only the architectural *concept* of account-presence checkers (plug-in registry, uniform result, async fan-out) and replaces their weak points; the code is original and has no GPL dependency.

> **Status: frozen prototype.** Per the package's documented architecture decision, `entity-graph` and its transforms are the product core. This package accepts bug fixes and documentation corrections only; no new connectors and no further production integration are planned. A Polish version of this document is in [README.pl.md](README.pl.md).

## Security use cases

- A reference implementation of a safe connector contract: explicit four-state result (`FOUND` / `NOT_FOUND` / `UNKNOWN` / `ERROR`) with explicit confidence, so that rate limits or format changes are never read as "not found".
- Privacy-preserving evidence handling: the target is represented by `subject_ref` (HMAC-SHA256 with a per-case salt) and the raw e-mail/number does not appear in results.
- Source policy enforcement: connectors declare `OFFICIAL_API`, `PASSIVE` or `MANUAL`; there is no active probing of third-party sign-up or login flows.

## How it works

| Module | Role |
|---|---|
| `src/osint_connectors/model.py` | `Status`, `InputKind`, `SourceKind`, `Subject`, `Finding` (frozen, serialisable, no raw target) |
| `src/osint_connectors/errors.py` | Typed exceptions mapped to statuses (rate-limit / auth / not-configured to `UNKNOWN`; timeout / transport / parse / schema-change / rejected request to `ERROR`) |
| `src/osint_connectors/connector.py` | `Connector` Protocol, explicit `ConnectorRegistry` with `@connector` decorator, `discover()` that isolates import failures |
| `src/osint_connectors/runner.py` | `run()` with a semaphore, per-connector timeout, exception-to-`Finding` mapping; `summarize()` |
| `src/osint_connectors/privacy.py` | `subject_ref()` HMAC-SHA256 with a required salt |
| `src/osint_connectors/http.py` | `HttpClient` Protocol; `UrllibClient` (stdlib) and `HttpxClient` (lazy `httpx` import) |
| `src/osint_connectors/connectors/` | `manual_confirm` (always `UNKNOWN`, asks for human confirmation), `passive_local_dataset` (offline match against a supplied set of refs), `gravatar_public` (public Gravatar profile by e-mail hash), `brave_search` (official Brave Search API, person-name queries) |
| `src/osint_connectors/integration/case_mapping.py` | Maps `Finding` to the run-record shape used by `entity_graph.model.RunRecord`; the package does not import `entity-graph` |

## Implemented security mechanisms

- **Hashed target reference.** `subject_ref` is an HMAC-SHA256 over `kind:normalised-value` with a mandatory, per-case salt; `Finding.to_dict()` never contains the raw target (`privacy.py`, `model.py`).
- **Failures are never negatives.** Unexpected exceptions become `ERROR/unexpected`; unsupported input kinds are rejected as `UNKNOWN` before the connector or HTTP client is touched; a connector returning anything but a `Finding` becomes an error (`runner.py`).
- **Bounded concurrency and time.** Semaphore-limited fan-out and `asyncio.wait_for` per connector (`runner.py`).
- **Strict response validation for Brave Search.** Error documents, wrong `type`, missing sections or a non-empty result list with no valid record raise `SchemaChanged` (an `ERROR`), never `NOT_FOUND`; mixed lists keep valid records and count skipped ones (`brave_search.py`).
- **Query-injection guard.** Person names are accepted only as 2-6 words of letters, with quotes, colons and search operators rejected (`brave_search.py`).
- **Key handling.** The Brave key is passed through the connector context and sent only in the `X-Subscription-Token` header; a missing key yields `NotConfigured` (`UNKNOWN`) with nothing sent.
- **Hardened stdlib HTTP client.** No redirects, response-size cap, an overall request deadline enforced by shutting down the sockets (and on coroutine cancellation), and an optional proxy pinned to a single `http://host:port` CONNECT route over HTTPS only that blocks any direct fallback (`_PinnedProxy`, `Deadline`, `UrllibClient` in `http.py`). A malformed proxy address raises `ValueError` at construction, before any traffic.
- **Import isolation.** `ConnectorRegistry.discover()` records a module import failure in `load_errors` instead of failing start-up.

## Data handling and privacy boundaries

- Only `subject_ref` is hashed. `Finding.evidence` and `extra` are carried **verbatim** into the case record by the integration mapper, so a connector must not put raw personal data there; the node id (often a plain e-mail) belongs to the case graph and is not hashed by this package (`integration/case_mapping.py`).
- `gravatar_public` sends the MD5 hash of the lower-cased e-mail address (the scheme Gravatar requires) to a public Gravatar endpoint; the raw address is not placed in the `Finding`.
- `brave_search` transmits the supplied person name (and optional context) to the Brave Search API with the operator's own key.
- The package makes no request unless a connector that uses the HTTP client is run with a client in `Context.http`.
- Nothing is persisted by the package itself.

## Installation

Python 3.11+ per `pyproject.toml` (the rest of the toolkit targets 3.12+). No mandatory runtime dependencies; `httpx` is needed only if you use `HttpxClient`.

```bash
cd projects/osint-toolkit/osint-connectors
python -m venv .venv
python -m pip install -e . pytest
```

## Usage

```python
import asyncio
from osint_connectors import Context, InputKind, Subject, registry, run
import osint_connectors.connectors.manual            # registers connectors
import osint_connectors.connectors.passive_local

subject = Subject(InputKind.EMAIL, "alice@example.com")
ctx = Context(salt="per-case-secret-salt", dataset={"known_refs": set()})
findings = asyncio.run(run(registry.all(), subject, ctx, concurrency=10))
for f in findings:
    print(f.to_dict())        # the raw address never appears in the result
```

Mapping to a case run record:

```python
from osint_connectors.integration import findings_to_runs
runs = findings_to_runs(findings, node_id="email:alice@example.com")
```

The result is a serialised dictionary in the shape of `RunRecord.to_dict()`; rebuild it with `Graph.from_dict(...)` or construct a `RunRecord` from its keys.

## Configuration

The package itself reads no environment variables. The Brave connector expects its key and parameters in `Context.extra` (`api_key`, `query`, `count`); the CLI integration that supplies them from `BRAVE_SEARCH_API_KEY` lives in `entity-graph` (`eg szukaj-profili`).

## Testing

```bash
cd projects/osint-toolkit/osint-connectors
python -m pytest -q
```

The suite runs offline against injected HTTP doubles and a redacted synthetic Gravatar fixture (`tests/fixtures/gravatar_found.json`).

## Limitations

- Frozen prototype: the async runner has no global time budget or per-host rate limit and is not used by the synchronous `entity-graph` transform engine.
- `gravatar_public`: a 404 means "no public Gravatar profile", not "e-mail unused".
- The Brave Search response shape is implemented from the provider's documented `query` / `web.results[]` structure; the exact `type` value and error-document shape are assumptions covered by test doubles, not verified against the live API.
- `getaddrinfo` cannot be interrupted, so a hung system resolver blocks its worker thread until it returns, after which nothing is sent.
- Connectors for credentialed official APIs (for example HIBP) are not included.
