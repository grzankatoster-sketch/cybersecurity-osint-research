# osint-env

A reproducible, disposable Docker environment for running the toolkit and a few third-party OSINT tools with a degree of separation from the host. One command builds it from scratch; one script removes it. It is intended for defensive use on your own assets or under written authorisation.

> A Polish version of this document is in [README.pl.md](README.pl.md). Launcher messages are in Polish.

## Security use cases

- Running the toolkit's CLI tools (`username-engine`, `dns-audit`, `hibp-monitor`, `exif-map`, `phone-check`, `net-intel`, `site-audit`) plus theHarvester, ExifTool and `dig` from a locked-down, non-root container instead of the host.
- Keeping a research workspace separate from everyday activity (no mixing with a personal profile, browser or password manager).
- Optional containerised SpiderFoot, BBOT and a browser for authorised reconnaissance.

## How it works

| Item | Role |
|---|---|
| `Dockerfile` | Multi-stage build: `builder` (pip-installs the toolkit packages and a pinned theHarvester commit), `runtime` (image `osint-toolbox`), `tests` (adds pytest and copies the test suites) |
| `docker-compose.yml` | Services `toolbox` (default), `selftest` (profile `test`), `spiderfoot` (profile `spiderfoot`), `bbot` (profile `bbot`), `browser` (profile `browser`) |
| `run-tests.sh` | Runs pytest in each packaged project inside the `tests` image |
| `START_OSINT_ENV.cmd`, `RESET_OSINT_ENV.cmd` | Windows launchers: build + shell, and teardown with confirmation |
| `../.dockerignore` | Allow-list build context |

The build context is the parent directory (`projects/osint-toolkit`). The toolbox contains the Python packages listed above (editable install for `username-engine`, which locates `data/sites.json` relative to its sources), theHarvester from a pinned commit, Debian's ExifTool and `dig`.

## Implemented security mechanisms

- **Hardened toolbox container** (`docker-compose.yml`): non-root user (uid 1000), `read_only` root filesystem, `cap_drop: ALL`, `no-new-privileges`, `pids_limit: 512`, a 2 GB memory limit, `/tmp` and `$HOME` on tmpfs (gone on exit).
- **Single writable host mount.** Only `./work` is mapped (to `/work`); no host drive, user profile, browser or password-manager mount.
- **Loopback-only ports.** SpiderFoot (`127.0.0.1:5001`) and the browser (`127.0.0.1:6901`) are published on the loopback interface only.
- **Allow-list build context.** `../.dockerignore` excludes everything except the listed projects and drops `.venv`, results, `.env*`, `config.toml`, `state.json`, PDFs and `START_*.cmd`, so secrets and results do not enter the image.
- **Pinned third-party source.** theHarvester is fetched at a fixed commit (`THEHARVESTER_REF` in the `Dockerfile`); the `kasmweb/firefox` image is pinned to a tag.
- **Secrets by environment only.** `HIBP_API_KEY` and `KASM_VNC_PW` come from host environment variables and are never written to files in the repository.
- **Safe teardown.** `RESET_OSINT_ENV.cmd` asks for confirmation, removes only this project's containers, network, volumes and the two `osint-toolbox` images, and explicitly leaves `work\` untouched.
- **Reduced profile for services that need it.** `bbot` and `browser` run with `cap_drop: ALL` and `no-new-privileges` but with writable root filesystems (documented in the compose file).

## Data handling and privacy boundaries

- What the container does **not** isolate: your outgoing IP address (traffic leaves through the host connection; use a VPN on the host if you need a different exit), the DNS resolver (inherited from Docker Desktop), accounts and API keys you use, and operator mistakes such as logging into a personal account in the containerised browser.
- It is not a malware sandbox: the kernel is shared (WSL2), BBOT runs as root inside its container, and SpiderFoot is an unmaintained project with old dependencies.
- Files in `work/` are ordinary, unencrypted host files (for example photos with EXIF and tool output).
- SpiderFoot's web UI has no login. Keep it on loopback and do not publish the port to a network.
- The `kasmweb/firefox` image is licensed for non-commercial use in its community edition; check the current terms before using the `browser` profile. The image has not been exercised in this repository's build.

## Installation

Requires Docker Desktop. Run commands from `osint-env/`.

```bash
docker compose build toolbox
docker compose run --rm toolbox            # bash shell; /work is the only writable host mount
```

On Windows, `START_OSINT_ENV.cmd` does both. Building needs network access (apt, PyPI, GitHub). The `spiderfoot` profile expects a locally built `spiderfoot:local` image, which is not produced by this directory.

## Usage

Inside the toolbox:

```bash
python -m dns_audit example.com
python -m hibp_monitor --help
python -m exif_map /work/photos --map /work/map.html
python -m phone_check "+48 000 000 000"
username-engine --help
exiftool photo.jpg
dig example.com MX +short
theHarvester -d example.com -b duckduckgo -l 50
```

Other services (each needs its profile):

```bash
docker compose --profile spiderfoot up -d spiderfoot
docker compose --profile bbot run --rm bbot -t example.com -f subdomain-enum -rf passive
docker compose --profile browser up -d browser        # requires KASM_VNC_PW in the host environment
```

`docker compose up` without a service name also starts `toolbox`; name the service you want. Write results to `/work`, since the rest of the container filesystem is read-only. `hibp-monitor` reads `config.toml` and `state.json` from the current directory (`/work`).

## Configuration

| Variable | Purpose |
|---|---|
| `HIBP_API_KEY` | Passed from the host into the toolbox for `hibp-monitor domain-search`; empty if unset |
| `KASM_VNC_PW` | Password for the browser service (required for it to start) |
| `THEHARVESTER_REPO`, `THEHARVESTER_REF`, `PYTHON_IMAGE` | Docker build arguments in the `Dockerfile` |

## Testing

```bash
cd projects/osint-toolkit/osint-env
docker compose --profile test run --rm selftest
```

This runs, inside the `tests` image, `python -m pytest -q -p no:cacheprovider` in each of `username-engine`, `dns-audit`, `hibp-monitor`, `exif-map`, `phone-check`, `net-intel` and `site-audit` (`run-tests.sh`).

## Limitations

- Debian's ExifTool is an older version than a recent portable build.
- The base image is referenced by tag (`python:3.14-slim`), not by digest; the toolkit packages are not version-pinned (`>=` constraints in their `pyproject.toml`).
- The image is large (system, Python and a virtual environment with several scientific and browser-automation dependencies).
- The Polish README describes five bundled projects; the current `Dockerfile` and `run-tests.sh` include seven (`net-intel` and `site-audit` were added).
- The containerised browser, SpiderFoot and BBOT profiles weaken some of the hardening of the toolbox (see above) and are not covered by automated tests here.
