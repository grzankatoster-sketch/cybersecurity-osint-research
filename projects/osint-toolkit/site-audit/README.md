# site-audit

Auditor of the publicly visible configuration of a web site: redirect chain, TLS certificate and negotiated parameters, security headers (HSTS, CSP, framing, referrer, permissions), cookies, mixed content, `security.txt`, `robots.txt` and the sitemap. Pure Python standard library, no runtime dependencies.

> A Polish version of this document is in [README.pl.md](README.pl.md). Report text and recommendations produced by the tool are in Polish.

## Security use cases

- Baseline review of your own web properties (header and cookie hardening, certificate expiry, HTTP-to-HTTPS redirect).
- Authorised external review of a client site before an engagement, with a bounded and predictable request footprint.
- Checking `security.txt` (RFC 9116) validity and expiry; spotting sensitive paths advertised in `robots.txt`.

Companion to `dns-audit`: DNS and mail there; HTTP, TLS and site files here.

## How it works

`collector.py` fetches the start page, probes `http://` (does it redirect to `https://`?), then `robots.txt`, `security.txt` (well-known path and fallback) and the sitemap. `analyze.py` turns the data into graded findings (`OK` / `INFO` / `WARN` / `FAIL`); `report.py` renders text, JSON or standalone HTML.

| Module | Role |
|---|---|
| `src/site_audit/target.py` | URL normalisation (IDN to punycode, userinfo rejected, control characters rejected) and the address guard |
| `src/site_audit/fetch.py` | HTTP(S) client: connection pinned to a vetted IP, manual redirects, global time budget with a socket-killing watchdog, response size cap |
| `src/site_audit/parsers.py` | Pure parsers (HSTS, CSP, Set-Cookie, security.txt, robots, sitemap via expat, HTML) |
| `src/site_audit/collector.py` | Orchestrates requests; helper files only from the final host (`in_scope`) |
| `src/site_audit/analyze.py`, `report.py`, `cli.py` | Findings, rendering, CLI |

A failed fetch (timeout, reset, exhausted budget) is reported as "could not check", never as "absent".

## Implemented security mechanisms

- **SSRF guard.** Every host name is resolved and the target is refused if **any** returned address is non-public (private, loopback, link-local incl. `169.254.169.254`, CGNAT, reserved, multicast). IPv4 embedded in IPv6 (IPv4-mapped, NAT64 `64:ff9b::/96` and `64:ff9b:1::/48`, 6to4, Teredo) is evaluated separately (`is_public`, `resolve_checked` in `target.py`). Overridable only with `--allow-private`.
- **Applied at every redirect hop.** Redirects are followed manually (`Fetcher.get` in `fetch.py`), each hop is re-parsed and re-vetted, with loop detection and a maximum of 10 redirects.
- **DNS-rebinding resistance.** The connection goes to the already-vetted IP (`_PinnedHTTP`, `_PinnedHTTPS`); the host name is used only for SNI/`Host`, with no second resolution.
- **Scope restriction.** Helper files (`robots.txt`, `security.txt`, sitemap) are requested only from the final host; the scope check runs before each request and each redirect hop (`in_scope` in `collector.py`). A sitemap URL pointing to another host is ignored.
- **Hard time budget.** One budget for the whole audit; DNS resolution runs in a bounded thread and a watchdog timer closes the socket when the budget is exhausted, including during headers and chunked bodies (`Deadline`, `Fetcher._send`). Bodies are read with `read1()`, so slow-drip servers cannot hold the client past the budget.
- **Size limits.** Per-request byte cap (`--max-bytes`), `Accept-Encoding: identity` to avoid compression bombs.
- **XML hardening.** Sitemaps are parsed with expat; DOCTYPE/ENTITY declarations are refused (`parse_sitemap` in `parsers.py`).
- **Output sanitisation.** Control and bidi-control characters are neutralised in terminal and HTML output; HTML values are escaped; the HTML report carries a `default-src 'none'` CSP meta tag (`report.py`).
- **Atomic report write.** `write_atomic` in `cli.py`.
- **TLS behaviour.** Certificates are verified. If verification fails, the failure is recorded as a `FAIL` finding and the request is repeated without verification solely to observe headers; that response is not trusted for anything else (`Fetcher._request`).

## Data handling and privacy boundaries

- Traffic to the target is a handful of ordinary GET requests, like opening the page in a browser. There is no port scanning, no JavaScript execution, no form submission, no crawling beyond the helper files.
- No authentication, no cookies are sent, no content is stored. The only artefact is the optional `--html` report.
- URLs with embedded credentials (`user:pass@host`) are rejected.
- Query parameters in the audited URL appear in the report. If you share a report externally, remove tokens from URLs manually.

## Installation

Python 3.12+; no runtime dependencies.

```bash
cd projects/osint-toolkit/site-audit
python -m venv .venv
python -m pip install -e ".[dev]"
```

On Windows, `START_SITE_AUDIT.cmd` bootstraps `.venv` and opens a console with aliases `sa` and `sa-testy`.

## Usage

```bash
python -m site_audit example.com
python -m site_audit https://example.com/shop --json
python -m site_audit example.com --html report.html --budget 30 --no-extra
python -m site_audit 192.0.2.10 --allow-private       # own network only
```

Options: `--json`, `--html FILE`, `--timeout S` (per operation, default 8), `--budget S` (whole audit, default 60), `--max-bytes N` (default 2,000,000), `--no-extra` (start page only), `--allow-private`. A scheme-less address gets `https://`.

Exit codes: `0` audit performed; `1` HTML report could not be written; `2` invalid arguments; `3` site unreachable or blocked.

## Configuration

No environment variables are read.

## Testing

```bash
cd projects/osint-toolkit/site-audit
python -m pytest -q
```

Tests run offline (a local `127.0.0.1` server and injected resolvers); regression cases for the SSRF and time-budget behaviour are in `tests/test_fetch.py` and `tests/test_regressions.py`.

## Limitations

- The reported TLS version is the one negotiated by the local Python/OpenSSL (minimum TLS 1.2); it is not a protocol-support scan. Use a dedicated tool such as `testssl.sh` on your own host for that.
- No JavaScript execution: script-set cookies, trackers and technology fingerprinting are out of scope.
- "External script" means a host outside the audited domain and its subdomains; there is no Public Suffix List, so a sibling CDN domain of the same organisation is also flagged as `INFO`.
- The PGP signature of `security.txt` is recognised but not verified.
- Not a vulnerability scanner: it reports configuration, not exploitability.
