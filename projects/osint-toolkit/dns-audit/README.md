# dns-audit

DNS and mail-configuration auditor for a domain. It reads **public DNS records only** and reports SPF, DMARC, DKIM, DNSSEC, MTA-STS, TLS-RPT, BIMI, CAA, MX and TXT-based service-verification records as graded findings (`OK` / `INFO` / `WARN` / `FAIL`) with a remediation hint. An optional OPSEC mode sends every query as DNS-over-HTTPS through a SOCKS5 proxy (for example Tor).

> A Polish version of this document is in [README.pl.md](README.pl.md). Report text and recommendations produced by the tool are in Polish.

## Security use cases

- Review the mail-authentication posture of your own domains (spoofing exposure: missing or `p=none` DMARC, SPF `+all`/`?all`, SPF lookup limit).
- Pre-engagement or due-diligence review of a domain's public DNS footprint, with the owner's agreement.
- Detect dangling or broken mail routing (MX hosts that do not resolve, explicit null MX).
- Inventory third-party services referenced by TXT verification records.

## How it works

Pipeline: `collector.py` (parallel queries) -> `analyze.py` (findings) -> `report.py` (text / JSON / HTML).

| Module | Role |
|---|---|
| `src/dns_audit/resolver.py` | `Resolver` protocol; `DnsPythonResolver` (plain DNS, EDNS0 with DO bit) and `DohResolver` (RFC 8484 POST over a hand-rolled SOCKS5 CONNECT, TLS to the DoH host); `preflight()` control query |
| `src/dns_audit/collector.py` | Issues apex, `_dmarc`, `_mta-sts`, `_smtp._tls`, `default._bimi` and DKIM selector queries in a thread pool; resolves MX hosts |
| `src/dns_audit/spf.py`, `dmarc.py`, `dkim.py`, `verification.py` | Pure parsers with no network access (SPF lookup counting, DMARC tags, DKIM key parsing incl. a DER RSA length reader, verification-record recognition) |
| `src/dns_audit/analyze.py` | Turns collected data into findings |
| `src/dns_audit/report.py` | Text, JSON and self-contained HTML renderers |
| `src/dns_audit/cli.py` | Argument handling, channel selection, atomic HTML write |

A query failure (timeout, SERVFAIL) is never reported as "record absent"; it yields an `INFO` finding that the check could not be completed (`DnsAnswer.absent` vs `DnsAnswer.failed` in `resolver.py`).

## Implemented security mechanisms

- **Input validation.** Domain names are normalised (URL or e-mail input reduced to the host, IDN converted to punycode) and checked label by label (`normalize_domain` in `cli.py`). `--timeout` must be finite and greater than zero. `--resolver` must be an IP literal (`resolver.py`).
- **Fail-closed proxy channel.** With `--proxy` (or `OSINT_PROXY`) all queries are DoH over SOCKS5. A control query runs first; if the proxy/DoH path fails the tool exits with code 3 and issues **zero direct queries** (`cli.py`, `preflight` in `resolver.py`). `--resolver` combined with a proxy is rejected, and `--proxy`/`--direct` are mutually exclusive.
- **No local name resolution in OPSEC mode.** The DoH host name is passed to the proxy as a domain (SOCKS5 ATYP=3); only the proxy address itself is resolved locally (`_socks5_connect`, `_SocksHTTPSConnection`).
- **Tor circuit isolation.** Without proxy credentials a random login is generated once per run (`DohResolver.__init__`).
- **Credential scrubbing.** The resolver description shown in reports never contains proxy credentials; error strings are scrubbed of the proxy login/password (`DohResolver._scrub`).
- **Bounded DoH responses.** Bodies larger than 64 KiB and non-200 responses are rejected (`DohResolver._post`).
- **Untrusted-record handling.** Control characters in TXT data are rendered as visible `\xNN` in text output (`printable` in `report.py`); the HTML report escapes all values with `html.escape`.
- **SPF analysis budget.** Each domain is expanded once and the global include/redirect budget is bounded, ending with an explicit error rather than looping (`spf.py`, `collector.py`).
- **Atomic report writes.** `--html` writes a temporary file in the target directory and `os.replace`s it (`write_atomic` in `cli.py`).

## Data handling and privacy boundaries

- Reads public DNS records of infrastructure names only. It does not query for persons, does not brute-force subdomains, and does not scan hosts.
- In direct mode the configured resolver sees the audited domain; the tool states this on stderr (`Kanał: bezpośrednio ...`). Use the proxy mode if that matters.
- Nothing is persisted except the optional `--html` report. There is no cache and no state file.
- It does not verify DKIM signatures, fetch the MTA-STS policy file over HTTPS, or inspect SMTP TLS.

## Installation

Requires Python 3.12+. The single runtime dependency is `dnspython`.

```bash
cd projects/osint-toolkit/dns-audit
python -m venv .venv
python -m pip install -e ".[dev]"
```

On Windows, `START_DNS_AUDIT.cmd` creates `.venv` on first run and opens a console with the aliases `da` and `da-testy`.

## Usage

```bash
python -m dns_audit example.com
python -m dns_audit example.com --json
python -m dns_audit example.com --selectors selector1,mail --html report.html
python -m dns_audit example.com --resolver 1.1.1.1          # validating resolver for the DNSSEC AD flag

# OPSEC mode: DoH over SOCKS5 (Tor)
python -m dns_audit example.com --proxy socks5h://127.0.0.1:9150 --doh https://cloudflare-dns.com/dns-query
python -m dns_audit example.com --direct                    # ignore OSINT_PROXY
```

Options: `--json`, `--selectors a,b` (added to ~25 default DKIM selectors; `--only-selectors` uses only yours), `--resolver IP`, `--html FILE`, `--timeout SECONDS` (default 4; raised to at least 10 s with a proxy), `--proxy URL | --direct`, `--doh URL`.

Exit codes: `0` audit completed; `1` HTML report could not be written (the full report is still printed); `2` usage error; `3` proxy/DoH channel unavailable.

## Configuration

| Variable | Effect |
|---|---|
| `OSINT_PROXY` | Default value for `--proxy` (must be `socks5://` or `socks5h://`). `--direct` overrides it. |

## Testing

```bash
cd projects/osint-toolkit/dns-audit
python -m pytest -q
```

Tests use a `FakeResolver` (`tests/conftest.py`) and local stub SOCKS5/DoH servers; they need no internet access. The TLS-based DoH tests create a certificate with `openssl` and are skipped if it is unavailable (`tests/test_doh.py`).

## Limitations

- DKIM selectors are arbitrary: not finding one on the list does not prove DKIM is absent. Wildcard `*._domainkey` is detected with a random control selector.
- DNSSEC `AD` depends on the resolver; the tool does not validate the chain of trust itself.
- DMARC is read only at `_dmarc.<domain>`; there is no Public Suffix List, so organisational-domain inheritance is not resolved.
- SPF `a`/`mx`/`exists` mechanisms count as one lookup each (hosts are not expanded, void lookups are not counted); macros are skipped.
- CAA is read only on the queried name (no tree climbing, no CNAME following).
- MTA-STS and TLS-RPT checks cover the TXT record only.
- DoH over Tor is slower than plain DNS.
