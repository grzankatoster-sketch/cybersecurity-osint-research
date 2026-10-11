# Maintainers

| GitHub | Role | Scope |
|---|---|---|
| [@grzankatoster-sketch](https://github.com/grzankatoster-sketch) | Creator, lead maintainer and security maintainer | All projects in this repository |

There are currently no other maintainers or contributors.

## Role and responsibilities

**Project creator.** Defined the scope, threat model and engineering rules of the three projects
(OSINT Toolkit, Username Engine v1, Ultimate Username Engine) and directed their development in
private repositories between 2026-10-03 and 2026-10-11 (111 commits across three source
repositories, all authored under this account). The code was consolidated into this repository
with a fresh history; the source histories are not published because they contain research data.

**Security maintainer.** Owns the security decisions recorded in this repository:

- the responsible-use boundaries of the tools (no CAPTCHA/login bypass, no leaked datasets, no
  automatic identity attribution; see [CONTRIBUTING.md](CONTRIBUTING.md));
- the pre-publication review: secret scanning of all source histories, exclusion of personal data
  and third-party datasets, pseudonymisation of test data ([docs/SECURITY_REVIEW.md](docs/SECURITY_REVIEW.md));
- remediation of the vulnerabilities found in that review, each with regression tests
  ([SECURITY.md](SECURITY.md#known-issues)): fail-closed proxy configuration (OPEN-01),
  operator-scoped credential isolation (OPEN-02), the security audit entry point (OPEN-05),
  subprocess environment isolation (OPEN-06) and, partly, pinned and hash-verified catalogue downloads (OPEN-09);
- triage of vulnerability reports received through GitHub private vulnerability reporting.

**Development method.** Development was AI-assisted: implementation and documentation were
produced in pair-programming sessions with Anthropic's Claude (visible as `Co-Authored-By`
trailers), with the maintainer setting requirements, choosing between alternatives, approving
changes and making the release and security decisions. Every behavioural claim in the
documentation is backed by code and tests in this repository.

## Contact

- Security issues: GitHub private vulnerability reporting ("Security" tab). See [SECURITY.md](SECURITY.md).
- Everything else: GitHub issues.
