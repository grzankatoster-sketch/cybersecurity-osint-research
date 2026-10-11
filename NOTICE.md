# NOTICE

security-engineering-projects
Copyright 2026 The security-engineering-projects authors.

Unless stated otherwise below, the original source code, tests and documentation in this
repository are licensed under the Apache License, Version 2.0 (see [`LICENSE`](LICENSE)).

## Third-party data: fetched at build time, NOT redistributed

The username engines rely on community-maintained site catalogues. This repository ships the
code that imports them, **not the catalogues themselves**. Users build them locally and are
responsible for complying with the upstream licences when they do so.

| Upstream | Licence | How it is used here | Shipped? |
|---|---|---|---|
| [WhatsMyName](https://github.com/WebBreacher/WhatsMyName) (`wmn-data.json`) | CC BY-SA 4.0 (LICENSE.md verified at pinned commit `062bcfe`) | Downloaded by `projects/osint-toolkit/username-engine/scripts/build_db.py`; imported offline by `projects/ultimate-username-engine/ULTIMATE_USERNAME_ENGINE/tools/import_catalogs.py` | No |
| [Maigret](https://github.com/soxoj/maigret) (`maigret/resources/data.json`) | MIT (verified at pinned commit `eaf8206`) | Same as above | No |
| [Sherlock](https://github.com/sherlock-project/sherlock) site data | MIT (verified at `e40a45e`) | Imported offline by `tools/import_catalogs.py` | No |
| [Blackbird](https://github.com/p1ngul1n0/blackbird) metadata rules (`wmn-metadata.json`) | No licence detected by GitHub (checked 2026-10-11) — no redistribution rights; never shipped | Imported offline by `tools/import_catalogs.py` | No |
| [GeoNames](https://www.geonames.org/) | CC BY 4.0 | Downloaded by `projects/osint-toolkit/username-engine/scripts/build_geo.py` | No |
| [Have I Been Pwned](https://haveibeenpwned.com/) public breach catalogue | CC BY 4.0 (attribution required) | Fetched at run time by `hibp-monitor` / `org-intel`; attribution is written into exports | No |

Generated files that must stay out of version control are listed in [`.gitignore`](.gitignore)
(`username-engine/data/`, `ULTIMATE_USERNAME_ENGINE/data/catalog.json`, `import-records.json`,
`conflicts.json`, `blackbird-metadata.json`).

### Reference usernames in shipped rule files

`projects/osint-toolkit/username-engine/src/username_engine/resources/custom_sites.json` contains
`known` reference usernames used to self-check detection rules. All 86 values were verified to also
appear in the public WhatsMyName / Maigret data, where they serve the same purpose; they are
attributed to those projects. They are not research subjects of this repository.

## Third-party tools: NOT included

`projects/osint-toolkit/narzedzia/` contains only Windows launchers (`START_*.cmd`) for tools that
the user installs separately: theHarvester, BBOT, SpiderFoot, Maigret, ExifTool and `dig`. Their
source code, virtual environments and binaries are not part of this repository. `osint-env/`
builds a Docker image that downloads some of them at build time under their own licences.

`ULTIMATE_USERNAME_ENGINE/tools/enrichment_audit/donor_runtime.py` can execute one function of a
locally checked-out Maigret / socid_extractor source tree for an offline comparison. That source is
not included and is read from the path in `UEE_DONOR_ROOT`.

## Runtime dependencies (installed from PyPI, not vendored)

dnspython (ISC), phonenumbers (Apache-2.0), Pillow (MIT-CMU), folium (MIT), mcp (MIT),
aiohttp (Apache-2.0), aiohttp-socks (Apache-2.0), regex (Apache-2.0), pytest (MIT), ruff (MIT),
mypy (MIT). See each project's `pyproject.toml` for exact constraints.
