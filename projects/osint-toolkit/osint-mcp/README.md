# osint-mcp

A [Model Context Protocol](https://modelcontextprotocol.io) server (FastMCP, stdio transport) that exposes a deliberately small, **infrastructure-only** subset of the toolkit to an MCP client such as Claude: DNS/mail audit, RDAP, subdomain enumeration, IP context, a domain's public HIBP breach metadata, and offline phone-number validation.

> A Polish version of this document is in [README.pl.md](README.pl.md). Tool descriptions served to the MCP client are in Polish.

## Security use cases

- Letting an AI assistant answer defensive questions about your own or an authorised client's infrastructure ("what does the mail-auth posture of this domain look like?") by calling vetted, bounded tools instead of free-form shell access.
- Keeping a clear scope boundary: no person-oriented capabilities are exposed.

## How it works

| Module | Role |
|---|---|
| `src/osint_mcp/server.py` | FastMCP registration of six `async` tools; the blocking work runs in a worker thread (`asyncio.to_thread`) |
| `src/osint_mcp/tools.py` | Tool logic: input validation plus the exact sub-process arguments; no MCP dependency, so it can be tested offline |
| `src/osint_mcp/runner.py` | Input validators, `.venv` discovery, `run_module()` (sub-process, timeout, JSON parsing, `ToolFailure`) |

Tools and the module each one runs (as `python -m <package> ...` from that module's own `.venv`):

| Tool | Module | Timeout |
|---|---|---|
| `dns_audit(domain)` | `dns-audit` | 120 s |
| `phone_check(number, region="PL")` | `phone-check` (offline; result via a temporary file) | 30 s |
| `hibp_domain_breaches(domain)` | `hibp-monitor breaches --domain ... --no-save` | 90 s |
| `ip_info(ip)` | `net-intel ip` | 60 s |
| `rdap(domain)` | `net-intel rdap` | 90 s |
| `subdomains(domain)` | `net-intel subdomains` | 150 s |

A result with `status: failed`, or a source reported as `ERROR`, means "could not check", not "no results".

## Implemented security mechanisms

- **Input validation before anything runs** (`runner.py`): domains must be a bare host name (no scheme, path, `@`, port or spaces); IPs go through `ipaddress`; phone numbers are digits with an optional `+` and separators; regions are two letters. Any value beginning with `-` is rejected (CLI option injection), as are newlines and NUL bytes (`_clean`).
- **No shell.** Arguments are passed to `subprocess.run` as a list.
- **Hard timeouts per tool** and a 20 MB cap on result size (`MAX_OUTPUT_BYTES`).
- **Sub-process isolation.** `stdin` is `DEVNULL` so a module cannot read the MCP protocol channel; the working directory is a temporary directory removed afterwards (so `hibp-monitor` neither reads nor writes `state.json`); the server itself prints nothing on stdout, which is the protocol channel (`run_module`).
- **Errors are never empty results.** Validation failures, timeouts, an exit code other than 0 or 1, and non-JSON output are returned as tool errors (`ToolFailure`). Exit code 1 from a module (findings present, invalid number, partial result) still carries valid JSON and is returned.
- **Scope by construction.** No tool wraps `username-engine`, `entity-graph`, person search or e-mail-to-account lookups. Each tool description restates the defensive scope.
- **No self-registration.** The server does not register itself in any client configuration.
- **Per-module failure containment.** A missing `.venv` for one module yields a descriptive error for that module's tools only (`module_python`).

## Data handling and privacy boundaries

- Stateless: nothing is persisted outside the temporary working directory.
- Each tool forwards the supplied domain/IP to whatever third-party sources the underlying module uses (see the `net-intel`, `hibp-monitor` and `dns-audit` READMEs). `phone_check` makes no network requests.
- `hibp_domain_breaches` uses only the public, keyless HIBP breaches endpoint and returns breach metadata, never addresses or accounts.
- RDAP registrant contact data is not read by the underlying module and so is not returned.
- Sub-processes inherit the server's environment (plus UTF-8 settings), so variables such as `IPINFO_TOKEN` are visible to `net-intel` by design.

## Installation

Python 3.12+; runtime dependency `mcp>=1.0,<2`. The tools additionally require each module's own `.venv` (`dns-audit`, `phone-check`, `hibp-monitor`, `net-intel`), created by that module's `START_*.cmd` on Windows or manually:

```bash
cd projects/osint-toolkit/osint-mcp
python -m venv .venv
python -m pip install -e ".[dev]"
# for each module you want to expose, e.g.:
cd ../net-intel && python -m venv .venv && python -m pip install -e .
```

The module root defaults to the parent of this package and can be overridden with `OSINT_ROOT`.

## Usage

Register with an MCP client manually (the server does not do this itself). Claude Code example:

```bash
claude mcp add osint -- C:\path\to\security-engineering-projects\projects\osint-toolkit\osint-mcp\.venv\Scripts\python.exe -m osint_mcp
```

Claude Desktop (`claude_desktop_config.json`):

```json
{
  "mcpServers": {
    "osint": {
      "command": "C:\\path\\to\\security-engineering-projects\\projects\\osint-toolkit\\osint-mcp\\.venv\\Scripts\\python.exe",
      "args": ["-m", "osint_mcp"]
    }
  }
}
```

Then ask, for example: "Run the DNS audit for example.com". On Linux/macOS use `.venv/bin/python` (the runner also looks for `.venv/bin/python` in module directories).

## Configuration

| Variable | Effect |
|---|---|
| `OSINT_ROOT` | Overrides the directory that contains the module folders |

Environment variables of the underlying modules (for example `IPINFO_TOKEN`) are inherited.

## Testing

```bash
cd projects/osint-toolkit/osint-mcp
python -m pytest -q
```

Tests inject a fake `subprocess.run`; they need no network access and no module `.venv`.

## Limitations

- Third-party source limits (for example Cert Spotter without a key, an overloaded crt.sh) surface as per-source `ERROR` inside the `subdomains` result; they are not server failures.
- `phone_check` validates against the numbering plan only and never identifies a number's owner.
- The output-size cap is applied after the sub-process finishes, not as a streaming limit.
- Scripts and launch hints (`START_OSINT_MCP.cmd`) target Windows.
