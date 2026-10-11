# net-intel

Passive intelligence about publicly visible network infrastructure: **IP address context**, **domain RDAP registration data** and **subdomain enumeration from public sources**. Standard-library only (HTTP through `urllib`), no runtime dependencies. It queries third-party public databases about IP addresses and domains; it never contacts the investigated infrastructure itself.

> A Polish version of this document is in [README.pl.md](README.pl.md). Report text produced by the tool is in Polish.

## Security use cases

- Attack-surface inventory of your own domains from certificate-transparency and passive-DNS sources.
- Ownership and lifecycle checks: registrar, creation/expiry dates, hold and pending-delete statuses, DNSSEC delegation signal.
- Quick triage of an IP address: ASN/organisation, geolocation (country level and city/region as returned by the source), reverse DNS, bogon detection.

## How it works

| Module | Role |
|---|---|
| `src/net_intel/http.py` | A single injectable `urllib_fetch(url, headers, timeout) -> Response`; tests substitute a fake with the same signature |
| `src/net_intel/ipinfo.py` | `ip` sub-command: ipinfo.io plus reverse DNS (`gethostbyaddr` run in a thread with a time limit) as an independent second source; `local_scope()` short-circuits non-public addresses |
| `src/net_intel/rdap.py` | `rdap` sub-command: IANA RDAP bootstrap (fetched once per run) with `rdap.org` fallback; reads technical data and the registrar name only |
| `src/net_intel/subdomains.py` | `subdomains` sub-command: HackerTarget, Cert Spotter (up to 2 pages) and crt.sh; per-source status; optional A/AAAA resolution (`--resolve`) |
| `src/net_intel/report.py`, `cli.py`, `domain.py`, `models.py` | Findings model, text/JSON/HTML rendering, CLI, domain normalisation |

Principle: a failed source is never presented as "zero results". Each source reports `OK(n)` or `ERROR(reason)`; the aggregate `status` is `ok`, `partial` or `failed`. Rate-limit messages delivered with HTTP 200, empty bodies, HTML instead of JSON, HTTP 429 and timeouts are all `ERROR`.

## Implemented security mechanisms

- **No query for non-public IPs.** Private, loopback, link-local, multicast, unspecified and reserved addresses are described locally; no request is made to ipinfo.io or DNS (`local_scope` in `ipinfo.py`).
- **Strict input validation.** IP literals are parsed with `ipaddress`; domain names are normalised and validated per label (`domain.py`); `--timeout` must be finite and greater than zero; `--concurrency` is limited to 1-50 and `--resolve` to at most 1000 names (`cli.py`, `MAX_RESOLVE` in `subdomains.py`).
- **Redirect policy.** Redirects are followed only to `https` targets and the `Authorization` header is stripped when the host changes (`_SafeRedirect` in `http.py`).
- **Bounded responses.** Response bodies are capped at 30 MB (`MAX_BODY_BYTES`, `_read_limited` in `http.py`).
- **Result filtering.** Collected subdomain names are lower-cased, stripped of `*.`, and only names equal to or ending in `.<domain>` are kept; e-mail addresses from certificates and foreign domains are dropped (`subdomains.py`).
- **No contact data from RDAP.** Only the registrar name/IANA number and technical fields are read; registrant, administrative, technical and abuse vCard data are not parsed (`rdap.py`).
- **Secret handling.** The optional `IPINFO_TOKEN` is sent only as a request header and is not printed; fetch errors carry messages without headers or tokens (`http.py`, `ipinfo.py`).
- **Output hardening.** Control characters from third-party data are rendered as visible `\xNN` in text output; HTML output is escaped; HTML reports are written atomically (temp file + `os.replace`, `write_atomic` in `cli.py`).

## Data handling and privacy boundaries

- Subject matter is IP addresses and domain names only. It does not collect e-mail addresses, does not search for accounts or persons, and does not read registrant contact records.
- Every query reveals the target IP/domain to the third-party service concerned (ipinfo.io, IANA/RDAP servers, `rdap.org`, HackerTarget, Cert Spotter, crt.sh) and your egress address to them. With `--resolve`, the local system resolver additionally sees the discovered names.
- The package has no proxy option of its own. The default `urllib` opener honours the standard proxy environment variables of the host; it does not read `OSINT_PROXY`.
- Nothing is cached or stored on disk except the optional `--html` report.
- Each request carries `User-Agent: net-intel/<version> (...)` (`http.py`).

## Installation

Python 3.12+; no runtime dependencies.

```bash
cd projects/osint-toolkit/net-intel
python -m venv .venv
python -m pip install -e ".[dev]"
```

On Windows, `START_NET_INTEL.cmd` bootstraps `.venv` and provides the alias `ni`.

## Usage

```bash
python -m net_intel ip 198.51.100.7
python -m net_intel rdap example.com --json
python -m net_intel subdomains example.com --resolve --concurrency 10 --html subs.html
```

Common options: `--json`, `--html FILE`, `--timeout S` (default 20). The domain may be given as a URL or e-mail address; the host part is extracted and IDN is converted to punycode.

Exit codes: `0` checked, no WARN/FAIL findings (a genuine "0 subdomains" and partial results included); `1` WARN/FAIL findings, **or** all sources failed ("could not check"), or the `--html` report could not be written; `2` usage error.

RDAP findings are graded: expired or expiring in under 7 days is `FAIL`; under 30 days, `clientHold`/`serverHold`, `pendingDelete`/`redemptionPeriod` or an unknown name is `WARN`.

## Configuration

| Variable | Effect |
|---|---|
| `IPINFO_TOKEN` | Optional ipinfo.io token for the `ip` sub-command (header only; never printed or logged). |

## Testing

```bash
cd projects/osint-toolkit/net-intel
python -m pytest -q
```

Tests inject a fake fetcher (`tests/conftest.py`) and use recorded fixtures in `tests/fixtures/`; no network access is needed.

## Limitations

- Passive sources are not exhaustive: absence from the list does not prove a subdomain does not exist, and presence does not prove it is live (`--resolve` checks DNS only).
- Cert Spotter without an API key has a low hourly quota and crt.sh is frequently overloaded; both surface as `ERROR` for that source. HackerTarget has a daily per-IP limit without a key.
- RDAP coverage and content differ between registries; some ccTLDs omit dates or statuses.
- IP geolocation from ipinfo.io without a token is approximate and is not the location of physical infrastructure.
- `gethostbyaddr` has no native timeout and depends on the system resolver; on a hung resolver the result is "could not check" and the worker thread ends on its own.
