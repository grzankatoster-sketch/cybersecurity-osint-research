# Security architecture and threat model

This document describes the security-relevant design of the Ultimate Username Engine as implemented on the published `main` branch: what the engine protects, which threats it considers, which controls exist in code (with the tests that exercise them), and where it falls short. It is written for security engineers who intend to run, review or extend the tool.

Statements below were checked against the source in `ULTIMATE_USERNAME_ENGINE/src/ultimate_username` and the tests in `ULTIMATE_USERNAME_ENGINE/tests`. Where the code and an older document disagree, the code is described and the disagreement is listed in section 7. File paths are relative to `ULTIMATE_USERNAME_ENGINE/` unless stated otherwise.

## 1. Scope and assurance level

- **Scope.** The published package: the CLI and library, the `opsec/` egress-control module, the detection and extraction pipeline, the report writers, and the benchmark harness in `bench/`.
- **Not in scope / not published.** Three branches are not part of the published code: `cyber-opsec` (extended OPSEC work), `adaptery-platform` (platform adapters) and `feature/email-engine`. Anything those branches add is not described here.
- **Assurance.** The controls were developed with unit, integration and adversarial tests and with internal review rounds. The adversarial tests and the internal review rounds were run **only against loopback and mock targets** (see `tests/opsec/test_proxy_server.py`: "All targets are loopback or policy-denied, so nothing leaves the host"; `tests/conftest.py` additionally fails any test that opens a non-loopback socket or resolves a non-local name). This is internal adversarial testing. **No external penetration test, third-party audit or formal verification has been performed**, and none should be inferred.
- **Not a sandbox.** The engine contacts third-party sites by design. The controls reduce, but do not remove, the risk of doing so.

## 2. System model and trust boundaries

```
 operator / analyst
   | username(s), CLI flags, optional runtime-config JSON
   v
 +--------------------------- engine process (operator host) -----------------------------+
 | planning -> scheduler -> transport --[GuardedTransport: public egress check]--> network |
 |                 ^                                                                  |    |
 |   catalogue / registry (data/*.json: semi-trusted)                                 |    |
 |                                                                                    v    |
 |  detection -> evidence -> enrichment (killable child processes) -> identity -> reports  |
 +-------------------------------------------------------------------------------|---------+
                                                                                 v
   optional: HTTP/SOCKS proxy (operator-chosen)  ->  target sites (UNTRUSTED)  <-  hostile responses
   local files: journal (SQLite), results JSON, *.analyst.json, *.selection.json, HTML report
```

Trust boundaries:

| Boundary | Trusted side | Untrusted / semi-trusted side |
|---|---|---|
| Network | operator host | every target site, every redirect target, avatar host, Wayback API |
| Catalogue | engine code | `data/catalog.json` (imported third-party data), `osint_custom.json`, any `--registry` file: they define URLs, regexes, headers and extraction rules that the engine executes |
| Local files | engine | outputs on disk (readable by any local user with file access) |
| Configuration | engine | `--runtime-config`, `--identity-weights` JSON (validated strictly, see section 4.7) |

Assets: the operator's network identity (source IP), the confidentiality of the searched usernames and of collected profile data, secrets in the operator's environment, and the integrity of verdicts.

## 3. Threat model

The adversaries considered are (a) operators or sites hosting hostile responses (a target site, a redirect target, a user who controls a profile page), (b) a tampered or careless catalogue/registry file, (c) a local observer with read access to the output directory, and (d) network observers on the operator's path. A malicious operator or a compromised host are out of scope.

| ID | Threat | Impact | Section |
|---|---|---|---|
| T1 | Operator IP and tool exposure: every scan sends the searched username from the operator's address to every selected site | Attribution of the investigator; tipping off the subject; IP-based blocking | 4.1 |
| T2 | SSRF through catalogue URLs, redirects, avatar URLs, Wayback targets and follow-up URLs: a hostile site or entry steers the engine to loopback, private, link-local or cloud-metadata addresses | Access to internal services of the operator's network | 4.2 |
| T3 | Hostile response bodies: oversized or compressed bodies, catastrophic regexes, pathological HTML/JSON, markup in profile fields rendered in reports, spreadsheet formulas in exports | Memory/CPU exhaustion, stored XSS in reports, formula injection | 4.3 |
| T4 | Tampered catalogue/registry: rules that cause spurious verdicts, URL templates that change the origin, credential headers | False evidence, request forgery, secret exfiltration | 4.4 |
| T5 | Secret leakage in logs, results and reports | Credential or token disclosure | 4.5 |
| T6 | Data retention: usernames and profile data (names, bios, locations, avatar URLs) persist in local files | Personal-data exposure; compliance risk | 4.6 |
| T7 | Misattribution: a matching username is read as the same person | Wrong conclusions about a real person | 4.8 |
| T8 | Supply chain: donor data and Python dependencies | Poisoned rules, vulnerable libraries | 4.9 |

## 4. Implemented controls

### 4.1 Operator exposure (T1)

What exists:

- `--proxy URL` accepts `http`, `https`, `socks4` and `socks5` schemes (`http_transport.HttpConfig`). SOCKS needs the optional dependency `aiohttp-socks`. Environment proxy variables are ignored (`trust_env=False`). When a proxy is configured, the egress guard performs no local DNS lookup of target names (`cli._real_transport`, `resolve_dns=not proxy`), so the engine itself does not resolve them.
- No code path retries a failed proxied request directly.
- Cookies are disabled (`aiohttp.DummyCookieJar`), so no session state carries over between sites or runs.
- Control and request budgets bound how many requests leave the host (`runtime_policy.MODES`).
- `--dorks` only builds query text and sends nothing (`dorks.py`; the output records `"sent": false`).

What does not exist (see gaps G-1 to G-3): the default is a **direct connection**; there is no proxy pre-flight, no Tor check and no stream isolation; the User-Agent is the constant `UltimateUsernameEngine/0.1` (`HttpConfig.user_agent`), which identifies the tool to every site. Control requests additionally send a random control name to each tested site (`control.py`).

### 4.2 Egress control and SSRF (T2)

The egress controls live in `src/ultimate_username/opsec/`:

| Module | Control |
|---|---|
| `policy.py` | `EgressPolicy`: deny-by-default allowlist (exact or parent-domain match), scheme and port restriction, userinfo-in-URL rejection, literal-IP and legacy numeric-IPv4 handling (`127.1`, `0177.0.0.1`, `2130706433`, `0x7f000001` via `numeric_ipv4`), local-name refusal (`localhost`, `.local`, `.internal`, `.lan`, ...), and `classify_ip` which rejects loopback, link-local (including `169.254.169.254`), private, CGNAT (`100.64.0.0/10`), multicast, reserved, documentation, NAT64 and unique-local ranges and unwraps IPv4-mapped IPv6 addresses. Any resolved address in a forbidden range denies the destination; a resolver failure is fail-closed. |
| `guard.py` | `GuardedTransport` wraps any `Transport` and refuses a request before the inner transport opens a socket. The DNS lookup runs in a thread so it does not block the event loop. Refused requests return an `UNSUPPORTED` transport error with the reason; a counter `blocked` is kept. |
| `transport_factory.py` | `public_egress_transport()`: the guard used by the CLI for **all** traffic (search requests, redirect hops, avatars, Wayback and health probes). No allowlist and no port limit, because site definitions decide those, but internal destinations are refused. Unresolvable names pass through so DNS errors keep their normal verdicts; `.onion` hosts are left to the inner transport, which requires a proxy. `build_transport()`: a library entry point that wraps a transport in the allowlist guard and **refuses to build a direct transport when a mandatory proxy is configured** (`enabled` + `fail_closed`). |
| `server.py` | `ForwardProxy`: a local HTTPS `CONNECT` forward proxy. Binds to loopback unless a token is configured (`config.validate`), requires `Proxy-Authorization: Bearer <token>` compared with `hmac.compare_digest`, validates every target against the policy **before** opening an outbound socket, and connects to the already validated resolved IP (this closes the DNS-rebinding window for traffic that goes through the proxy). Only `CONNECT` is accepted; headers are limited to 16 KiB; with `fail_closed` an unreachable upstream stops traffic instead of going direct. |
| `config.py` | `ProxyConfig`: settings from `OSINT_PROXY_*` environment variables; `validate()` refuses a non-loopback bind without a token and an empty allowlist under fail-closed. |
| `redaction.py` | `redact_text`, `redact_url`, `redact_headers`: mask e-mail addresses, JWTs, `bearer`/`token`/`apikey`-style assignments and long opaque tokens; reduce URLs to `scheme://host[:port]`; fully redact sensitive headers. |

Redirects and other URL sources inside the engine:

- **Single hop.** The HTTP transport never follows redirects itself (`allow_redirects=False`). Each hop is a new scheduled request, so it passes the per-origin limiter and the egress guard again (`policies.redirect_request`).
- **Redirect rules.** A loop, a hop-budget overrun and an HTTPS-to-HTTP downgrade are errors. A cross-origin hop needs an explicit `allowed_origins` entry unless `safe_cross_origin` accepts it: the target must be a public host (`domain.urls.is_public_host`), on a standard port, and either the same host up to `www.`, the same approximate registrable domain, or a path that still contains the username. Non-safe request headers are dropped across origins, and a request body is never replayed across origins; a 303 turns the request into a GET, while a POST that receives 301/302 is only converted to GET under an explicit `post_to_get` policy and is otherwise an error.
- **URL templates.** A profile or probe template whose `{username}` placeholder could change the origin is rejected at load (`domain.urls.validate_template`); the username is percent-encoded as a single component (`render_url`); credentials in URLs and control characters are rejected (`domain.urls.origin`).
- **Avatars and Wayback.** Avatar URLs are filtered with the same host check and fetched through the guarded transport with a 5 MiB limit (`identity.fetch_avatar_records`); Wayback lookups use the engine transport and a separate budget (`dorks.check_wayback`).
- **Cooldown.** An origin returning 429 gets a bounded cooldown (at most 60 s); a hostile `Retry-After` cannot park an origin for a day (`engine._SearchWork._observe_origin`, `policies.retry_wait`).

### 4.3 Hostile response bodies (T3)

- **Bounded bodies.** The transport reads at most `body_limit` bytes (default 1 MiB) **after decompression**; gzip/deflate are decoded incrementally with a size cap, truncated or concatenated streams are errors, and unsupported `Content-Encoding` values are rejected (`http_transport.AiohttpTransport.send`). Exceeding the limit yields `BODY_LIMIT` and an incomplete response that cannot support a positive verdict.
- **Errors never mean "absent".** A transport error, an incomplete body, 401/403/429/5xx, a challenge or a login wall can only produce `verdict=UNKNOWN` with an execution state; `DetectionResult.__post_init__` raises if a non-`OK` state carries a non-`UNKNOWN` verdict (`domain/models.py`).
- **Regex and parsing limits.** Catalogue regexes run with the `regex` module and a per-match timeout of 0.05 s (`detection.DetectionEngine`); HTML signal extraction reads at most 1 MiB (`response_quality.PageSignals`); JSON is parsed without executing anything, and embedded-state literals are read by a restricted literal reader that rejects expressions and calls (`literal_data.py`). Extraction fields are capped (64 rules, 16 KiB per value, `extraction.py`).
- **Killable parsers.** Profile extraction runs in separate `spawn`ed child processes with a deadline, so a hanging parser is terminated and the base verdict is already committed (`profile_service.py`, `extraction.py`, ADR-004). This is process isolation for liveness, not a security sandbox.
- **Reports.** The HTML report is one file with no JavaScript and no external resources; all third-party text is escaped, control characters are stripped, links are emitted only for `http`/`https` with `rel="noopener noreferrer"`, and a `Content-Security-Policy` meta tag sets `default-src 'none'` (`html_report.py`).
- **Exports.** Files are written atomically (temporary file, `fsync`, `os.replace`); CSV cells that start with `=`, `+`, `-`, `@`, tab or CR are prefixed with an apostrophe while JSON keeps the exact value (`storage.csv_chunks`).

### 4.4 Catalogue and registry integrity (T4)

- **Import without execution.** The importer reads donor snapshots as data; no donor code is imported or run (`importers.py`, ADR-003). Unsupported protocols, activations, host placeholders and ambiguous engine conflicts are quarantined, and every discarded record is accounted for.
- **Strict validation.** `domain/validation.py` validates each definition (schema version, method, URL templates, timeouts, retry bounds, strategies); invalid or duplicate entries stay visible as `ValidationIssue`s and are not executed. Snapshots carry a SHA-256 and are promoted with a lock and compare-and-swap (`storage.SnapshotStore`).
- **Conservative evidence.** Imported historical rules receive no invented owner binding; a positive signal gives at most `PROBABLE`. `FOUND` requires profile-specific evidence plus an owner binding or a reviewed adapter. See the main README.
- **Integrity inputs.** `data/import-summary.json` records the SHA-256 of each donor file used for the original import, so a rebuilt catalogue can be compared with the donor versions that were used.

### 4.5 Secret handling (T5)

- API credentials are never part of a definition: a definition names an environment variable (`credential_env`) and a header; the value is read at request time, rejected if it contains CR/LF, never written to results, and not forwarded to fallback endpoints or to another origin after a redirect (`engine.py`, `policies.redirect_request`, `domain/validation.py`; tests in `tests/unit/test_adaptive_runtime.py`).
- Result records keep URLs, statuses, timings, redirect history and a body SHA-256, **not** request headers and not response bodies (`domain/models.AttemptRecord`, `storage.ResultJournal`).
- Proxy authentication uses a bearer token read from the environment only and compared in constant time; proxy log lines contain a status and a policy reason, not headers.
- `redaction.py` provides masking helpers for diagnostics, but see gap G-7: they are not called by the CLI.

### 4.6 Data retention (T6)

Controls are limited. Each run writes a SQLite journal (`results/<run-id>.sqlite`, WAL mode), the full results JSON, an analyst document and a selection document, and optionally an HTML report. The journal stores the full result objects (including extracted profile metadata and avatar URLs). `results/` is git-ignored. There is **no built-in retention period, purge command or encryption** (gap G-6). Operators must treat all outputs as personal data and manage them accordingly.

### 4.7 Configuration safety

`RuntimePolicy`, `IdentityConfig` and `HttpConfig` validate their fields on construction and reject non-finite, negative or out-of-range values. `--runtime-config` is parsed through the strict typed codec (`domain/codec.py`). The proxy configuration is the exception: see gap G-5.

### 4.8 Evidence discipline (T7)

Verdicts separate the account verdict from the execution state; `confidence.value` stays `null`; blocks and challenges are never reported as absence; identity output is a separate, opt-in layer that never changes an existence verdict (`identity.py`). Matching usernames are leads, not proof of identity.

### 4.9 Supply chain (T8)

Runtime dependencies are `aiohttp` and `regex`; `aiohttp-socks` and (for avatar hashing) Pillow are optional. `requirements-tested.txt` pins the tested versions of the main packages and `requirements-lock-windows-py314.txt` lists the full environment of the maintainer's Windows/Python 3.14 setup. Donor catalogues are third-party data (see the main README for licences) and are not redistributed.

## 5. Control-to-test map

| Control | Code | Tests |
|---|---|---|
| Allowlist: deny-by-default, parent-domain match, port and scheme limits, userinfo rejection | `opsec/policy.py` | `tests/opsec/test_policy_allowlist.py` (`test_empty_allowlist_with_require_denies_all`, `test_exact_and_parent_domain_match`, `test_port_not_allowed`, `test_scheme_restricted_to_https_by_default`, `test_credentials_in_url_rejected`) |
| SSRF address classes, mixed DNS answers, fail-closed resolver | `opsec/policy.py` | `tests/opsec/test_policy_ssrf.py` (`test_forbidden_addresses_are_rejected`, `test_literal_metadata_ip_blocked_without_dns`, `test_hostname_resolving_to_private_ip_blocked`, `test_mixed_result_set_blocks_if_any_ip_forbidden`, `test_resolver_failure_is_fail_closed`) |
| Application-side guard refuses before connecting | `opsec/guard.py` | `tests/opsec/test_guard.py` |
| Mandatory proxy cannot degrade to direct; DNS-rebinding style answers refused | `opsec/transport_factory.py` | `tests/opsec/test_integration_factory.py` (`test_mandatory_proxy_not_routed_refuses_to_build_direct`, `test_dns_rebinding_blocked_when_resolution_includes_forbidden_ip`) |
| Forward proxy: policy before connect, auth, fail-closed upstream | `opsec/server.py` | `tests/opsec/test_proxy_server.py` (`test_disallowed_host_is_forbidden`, `test_ssrf_to_metadata_is_forbidden_before_connect`, `test_missing_auth_is_rejected`, `test_correct_auth_allows_tunnel`, `test_unreachable_upstream_fails_closed`) |
| Proxy configuration validation | `opsec/config.py` | `tests/opsec/test_config.py` |
| Redaction helpers | `opsec/redaction.py` | `tests/opsec/test_redaction.py` |
| Numeric/legacy host spellings and local names rejected; resolved addresses checked on request; redirect to a private resolution stopped at the transport; `.onion` skips local DNS; avatar host filter | `domain/urls.py`, `opsec/transport_factory.py` | `tests/unit/test_security_review_fixes.py` (`test_non_public_host_forms_are_rejected`, `test_resolved_addresses_are_checked_on_request`, `test_transport_refuses_non_public_destinations_without_dns`, `test_transport_refuses_a_name_that_resolves_to_a_private_address`, `test_redirect_to_a_private_resolution_is_stopped_at_the_transport`, `test_onion_hosts_skip_dns_so_a_configured_proxy_keeps_working`, `test_avatar_url_filter_uses_the_shared_host_check_and_standard_ports`) |
| ReDoS in name cleaning; cooldown cap; report escaping; generator cleanup | `enrichment.py`, `engine.py`, `html_report.py`, `health_probe.py` | `tests/unit/test_security_review_fixes.py` (`test_clean_name_is_not_quadratic`, `test_429_retry_after_cooldown_is_capped_at_the_give_up_limit`, `test_requested_url_with_markup_in_the_host_gives_no_live_tag`, `test_probe_closes_the_search_stream_generator`) |
| Redirect policy: harmless aliases followed, other hosts rejected, private targets blocked, HTTPS downgrade/loop/hop limits, body dropped on POST-to-GET | `policies.py`, `domain/urls.py` | `tests/unit/test_redirect_policy.py` |
| Single hop, no cookies, decoded body limit, TLS failure is an error without verdict, `.onion` needs a proxy | `http_transport.py` | `tests/integration/test_http_transport.py` (`test_pool_reused_redirect_not_automatic_and_cookies_disabled`, `test_decoded_body_limit`, `test_untrusted_tls_certificate_is_error_without_verdict`, `test_onion_without_configured_transport_does_not_resolve`) |
| Report escaping, control-character stripping, safe links, self-contained page | `html_report.py` | `tests/unit/test_html_report.py` (`test_third_party_text_is_escaped_not_executed`, `test_control_characters_are_stripped`, `test_links_open_safely_and_only_for_http`, `test_attribute_injection_through_url_is_neutralised`, `test_self_contained_no_external_resources`) |
| CSV formula neutralisation | `storage.py` | `tests/integration/test_cli.py::test_validate_offline_registry_and_csv_output` |
| Missing credential neither sends nor asserts absence | `engine.py` | `tests/unit/test_adaptive_runtime.py` (`test_missing_credential_does_not_send_or_assert_absence`) |
| Parser deadline, cancellation cleanup, owner guard | `extraction.py`, `profile_service.py` | `tests/unit/test_extraction.py` |

Tests that depend on the unpublished catalogue or fixture suites (see the main README) may be skipped or fail in a fresh checkout; the table lists the intent of the tests, not their current results.

## 6. Known gaps and residual risks

| ID | Gap | Detail |
|---|---|---|
| G-1 | **The allowlist proxy is not wired into the CLI.** | `ForwardProxy`, `EgressPolicy` with an allowlist and `build_transport()` are library components. Nothing in the CLI starts the proxy or reads the `OSINT_PROXY_*` variables; the only in-tree users of `ForwardProxy` are the tests and the `security/audit.py` smoke check. The CLI applies `public_egress_transport()` (SSRF belt, no allowlist). An operator who needs an allowlist must assemble it in code. |
| G-2 | **Check-then-connect gap in direct mode.** | `GuardedTransport` resolves the name to check it, then `aiohttp` resolves it again when connecting. A hostile DNS server can answer differently the second time (DNS rebinding). `ForwardProxy` avoids this by connecting to the validated IP, but the CLI does not use it. With `--proxy`, no local resolution happens, so resolved-address checks are skipped by design: only literal and local spellings are refused, and protection against internal targets then depends on the proxy. |
| G-3 | **No operator-identity protection by default.** | Direct connection is the default; there is no proxy health check, no Tor verification, no per-request circuit isolation, and the User-Agent is a constant that names the tool. For `socks4://` the library default resolves target names locally, which leaks them to the local resolver and bypasses the resolved-address check (with SOCKS5 the inspected `python-socks` default is remote resolution; this was read in version 0.12.0 of `aiohttp-socks` and is not asserted for other versions). The CLI rejects the `socks5h://` spelling. |
| G-4 | **Registry files are code-equivalent trusted input.** | A definition may name any environment variable in `credential_env` (only the name syntax is validated) and the value is sent as a header to the definition's host. A tampered `--registry` file could therefore exfiltrate any variable of the engine's environment to a host of its choosing. The shipped files contain no `credential_env` entries (`data/osint_custom.json`: 0 of 16 definitions), but nothing enforces an allowlist of variable names or hosts. Regexes from the catalogue are bounded by a match timeout, not rejected. |
| G-5 | **Proxy configuration fails open on typos.** | `opsec/config.py` parses leniently: an unrecognised boolean string such as `flase` becomes `False`, so a typo in `OSINT_PROXY_FAIL_CLOSED` silently disables fail-closed; `OSINT_PROXY_ENABLED=maybe` silently disables the proxy (and `build_transport` then returns the inner transport unchanged); an `OSINT_PROXY_ALLOWED_PORTS` value without any digit token (for example `abc`) produces an empty port set, which the policy treats as "no port restriction", and `validate()` does not report it. Verified by running the parser on those inputs. These affect the library path (G-1), not the default CLI. |
| G-6 | **No retention policy, purge or encryption of outputs.** | Journals, results, analyst files and HTML reports contain the searched usernames and collected profile data (display names, bios, locations, avatar URLs). Files are created with default permissions in a directory relative to the working directory (`results/`). There is no expiry. |
| G-7 | **Redaction helpers are not applied.** | `redact_*` are exported but no CLI, engine or proxy code calls them. Diagnostics are kept safe by construction (no headers or bodies are logged), not by redaction. |
| G-8 | **Redirect policy trades safety for coverage.** | `safe_cross_origin` follows a redirect to any **public** host whose path contains the username (3 or more characters), and approximates registrable domains with a small built-in suffix list rather than the Public Suffix List, so tenants of multi-tenant domains such as `github.io` are treated as one site. The maintainers' final review identified this and deferred the fix because it changes verdicts and needs a measurement. A hostile site can therefore steer requests to third-party public hosts, although never to internal addresses. |
| G-9 | **Forward-proxy details.** | With `upstream_url` the target name is resolved locally for the policy check before the upstream is contacted, so the local resolver sees the name; the upstream connection is plain TCP even for an `https://` upstream URL and carries no credentials; the byte pump has no idle timeout and the server has no connection limit. |
| G-10 | **Avatar decoding.** | With `--identity-images` third-party images (max 5 MiB, public hosts only) are decoded by Pillow in the engine process; image decoders are a known attack surface and the process is not sandboxed. The option is off by default and needs the optional dependency. |
| G-11 | **Child processes are not a sandbox.** | Extraction workers run as the same OS user with no seccomp, namespace or filesystem restriction. |
| G-12 | **Security automation is incomplete.** | `python -m ultimate_username.security` imports `ultimate_username.security.secrets`, which is not present in the published tree (it belongs to the unpublished `cyber-opsec` work), so `audit` and `test-proxy` fail at import. There is no automated dependency audit or secret scan in this tree. |
| G-13 | **Each run is observable by the targets.** | Besides the searched username, control requests send a random name to the same site, and health probes and retries add traffic. Request counts per run are documented in `docs/BENCHMARK.md`. |

## 7. Discrepancies between documents and code

- `BLOCK_CLASSIFICATION.md` (Polish original) describes an uncapped 429 cooldown; the code caps it at 60 s and drops retries when `Retry-After` exceeds 60 s.
- `BUDGET_ARCHITECTURE.md` lists NORMAL as 200 services / 250 requests; the code uses 800 / 1100 (plus a control-request budget). English translations with status notes are in `ULTIMATE_USERNAME_ENGINE/docs/design/`.
- `EVIDENCE_MODEL.md` maps evidence level 2 to `PROBABLE`; control-derived `FOUND` results carry level 2 (`control.py`).
- `README.pl.md` and several Polish documents reference artifacts (`artifacts/...`, `DETECTION_QUALITY_RESULTS.md`, `REGRESSION_STATUS.md`) and specifications (`docs/SPEC_CONTROL_REQUEST.md`, `docs/SPEC_IDENTITY.md`) that are not in the published tree.
- The module docstring of `opsec/config.py` refers to `env.opsec.example`, which is not in the published tree.

## 8. Reporting vulnerabilities

This project directory contains no security policy file. If the repository root provides one, follow it; otherwise contact the maintainer privately rather than opening a public issue, and include the affected file and a minimal reproduction that does not contact third-party systems.
