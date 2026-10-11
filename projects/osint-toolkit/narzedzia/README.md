# narzedzia

Windows launchers (`.cmd`) for third-party OSINT and DNS tools that are installed **locally and separately**. The tools themselves are **not** part of this repository: only the launcher scripts and two command shims are. Each launcher opens a console with the right environment and a short cheat sheet; none of them contains tool logic.

> A Polish version of this document is in [README.pl.md](README.pl.md). Launcher messages are in Polish. The directory name means "tools".

## Security use cases

- Attack-surface reconnaissance on **your own** domains and IPs, or under written authorisation: theHarvester, BBOT, SpiderFoot.
- DNS inspection with `dig` without installing BIND on Windows.
- File-metadata inspection and sanitising with ExifTool (also used by `exif-map`).
- Username enumeration with Maigret (kept as a second engine for comparison).

## How it works

| Launcher | Tool | How the launcher runs it |
|---|---|---|
| `START_THEHARVESTER.cmd` | theHarvester | Activates a virtual environment `theharvester-venv\` expected in this directory; changes to `wyniki\` |
| `START_BBOT.cmd`, `bin\bbot.cmd` | BBOT | Runs the `blacklanternsecurity/bbot:stable` Docker image; results in `wyniki\bbot-data` |
| `START_SPIDERFOOT.cmd` | SpiderFoot | Starts a locally built `spiderfoot:local` Docker image with its web UI on `127.0.0.1:5001` |
| `START_DIG.cmd`, `bin\dig.cmd` | dig (BIND) | Runs a locally built `dig-tools:local` Docker image |
| `START_EXIFTOOL.cmd` | ExifTool | Adds a portable `exiftool\` folder to `PATH` |
| `START_MAIGRET.cmd` | Maigret | Activates `maigret-venv\` |

What you must provide yourself: the tool installations (`theharvester-venv\`, `theharvester-src\`, `exiftool\`, `maigret-venv\`), the Docker images `spiderfoot:local` (built from a local SpiderFoot source checkout) and `dig-tools:local` (the Dockerfile is not included in this repository), and Docker Desktop for BBOT, SpiderFoot and dig. `wyniki\` (results) is created on demand and should not be committed.

Other packages use this directory: `exif-map` looks for `exiftool` here when it is not on `PATH`, and the `panel` runs theHarvester from `narzedzia\theharvester-venv`.

## Implemented security mechanisms

These are properties of the launchers as written, not of the third-party tools:

- **SpiderFoot is bound to loopback and hardened at the container level.** The container publishes `127.0.0.1:5001` only and runs with `--security-opt no-new-privileges`; data lives in a named Docker volume (`START_SPIDERFOOT.cmd`).
- **Authorisation reminder on every launcher.** Each start banner states "own domains/IPs or written consent" and that a hit is a lead, not proof.
- **Passive-first guidance for BBOT.** The banner shows the passive-only invocation (`-f subdomain-enum -rf passive`) and warns that active presets send traffic to the target (`START_BBOT.cmd`).
- **Metadata removal on copies.** The ExifTool cheat sheet reminds you to strip metadata from a copy, not the original (`START_EXIFTOOL.cmd`).
- **Containers are ephemeral where possible.** `bbot` and `dig` shims use `docker run --rm`.

## Data handling and privacy boundaries

- Nothing here is collected or sent by the launchers themselves; the tools they start do contact third-party services and, in active modes, the target.
- theHarvester sources that need API keys read them from the tool's own configuration; do not commit key files.
- SpiderFoot's UI has no login: it is reachable only from the local machine, and the port must not be exposed to a network.
- Results are written under `wyniki\` and in the SpiderFoot Docker volume; they may contain personal data if you scan people, which these tools should not be used for.

## Installation

There is nothing to install from this repository. Place the tool installations next to the launchers as listed above, install Docker Desktop for the container-based tools, and build the local images (`spiderfoot:local`, `dig-tools:local`) from sources you have reviewed. The Polish README records the versions the author used (ExifTool 13.59, theHarvester 5.0.0, BBOT 3.0.2, SpiderFoot 4.0.0, BIND 9.18) and update commands.

## Usage

Double-click a launcher, or from a console:

```bat
START_THEHARVESTER.cmd
rem then, inside the opened console:
theHarvester -d example.com -b crtsh

START_BBOT.cmd
rem then:
bbot -t example.com -f subdomain-enum -rf passive

START_DIG.cmd
rem then:
dig example.com MX +short
```

## Configuration

The launchers read no environment variables of their own. They modify `PATH` for the session (`bin\`, `exiftool\`) and set `PYTHONUTF8` / `PYTHONIOENCODING` for the Python-based tools.

## Testing

There are no automated tests for the launchers.

## Limitations

- Windows only (`.cmd`).
- The Docker images referenced by tag (`blacklanternsecurity/bbot:stable`) are not pinned by digest, and the locally built images depend on whatever sources you build them from.
- SpiderFoot's upstream is described in the Polish README as inactive since 2023 with outdated dependencies; treat it as an untrusted, local-only tool.
- Maigret is retained as a comparison engine; the toolkit's own `username-engine` replaced it in the panel workflow.
- BBOT presets other than passive send traffic to the target. Use them only with authorisation.
