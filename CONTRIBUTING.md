# Contributing

Thank you for considering a contribution. This repository contains security and OSINT tooling, so
contributions are held to two standards at once: correctness and responsible scope.

## Scope rules (read first)

Changes that will not be accepted, regardless of code quality:

- Circumventing access controls: CAPTCHA solving, login walls, paywalls, rate limits or anti-bot measures.
- Ingesting leaked or breached datasets, credential dumps, stealer logs or paste-site content.
- Facial recognition, reverse phone lookup to identify a person, or automated attribution of an
  account to a real identity.
- Features whose main use is tracking, stalking or harassing an individual.
- Offensive payloads or exploitation of third-party systems. Internal adversarial tests must target
  loopback or mock services only.

Defensive features (auditing your own assets, reducing exposure, improving evidence quality,
provenance, privacy-preserving defaults) are welcome.

## Development workflow

1. Each project is self-contained. Work inside its directory and use its own virtual environment:

   ```bash
   cd projects/osint-toolkit/dns-audit          # or any other package
   python -m venv .venv
   .venv/bin/python -m pip install -e ".[dev]"   # Windows: .venv\Scripts\python.exe
   .venv/bin/python -m pytest -q
   ```

   For the Ultimate Username Engine:

   ```bash
   cd projects/ultimate-username-engine/ULTIMATE_USERNAME_ENGINE
   python -m pip install -r requirements-tested.txt -e ".[dev,socks]"
   python -m pytest -q && python -m ruff check src tests tools
   ```

2. **Tests must be offline.** Use local fixture servers, mocks or recorded synthetic responses.
   Never add tests that contact real third-party services.
3. **Fixtures must be synthetic.** Use `alice`, `example.com` / `example.test`, documentation IP
   ranges (`192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`) and obviously fake numbers. Do not
   commit captured pages of real profiles, real usernames of private people, or real case data.
4. **No secrets.** Credentials are read from environment variables only. Test canaries that look
   like secrets must use the `SYNTH-` prefix (or be added explicitly to `.gitleaks.toml` with a
   justification).
5. Run `gitleaks dir . --config .gitleaks.toml --redact` before pushing.
6. Keep documentation truthful: describe implemented behaviour, cite the module, and label anything
   else as "Planned (not implemented)". Do not report test counts or benchmark numbers you did not
   reproduce.

## Pull requests

- One logical change per PR, with tests.
- CI (`tests`, `security`, `codeql`) must pass.
- Describe the security impact of the change (new network egress, new data stored, new inputs parsed).

## Reporting vulnerabilities

Do not open a public issue for a vulnerability. Follow [`SECURITY.md`](SECURITY.md).
