# phone-check

Offline phone-number validator and metadata extractor built on the [`phonenumbers`](https://pypi.org/project/phonenumbers/) library (a Python port of Google's libphonenumber). It parses a number in any format and reports validity, line type, country, geographic description, numbering-plan carrier (with a number-portability caveat), time zones and canonical formats (E.164, international, national, RFC 3966).

> A Polish version of this document is in [README.pl.md](README.pl.md). Console output and descriptions are in Polish by default (`--lang` changes the language of geographic descriptions).

## Security use cases

- Normalising and validating phone numbers from your own contact lists, incident records or case notes before they are used as indicators.
- Batch validation of a list of numbers to CSV/JSON for downstream tooling (`entity-graph` has an importer for the JSON/CSV output).
- Generating text variants of a number for a *manual* search in a search engine (`--dorks`), as a lead-generation aid. The tool itself sends nothing.

## How it works

| Module | Role |
|---|---|
| `src/phone_check/core.py` | `analyze()` returns a `PhoneInfo` using only data bundled in `phonenumbers` (no network); never raises on bad input |
| `src/phone_check/dorks.py` | `dork_result()` builds quoted spelling variants (with/without `+CC`, `00CC`, spaces, hyphens, dots, 3-3-3 grouping and 2-3-2-2 for fixed lines) as text only |
| `src/phone_check/cli.py` | Single-number and batch modes, JSON/CSV writers, path-collision checks |

Geographic description, carrier and time zones are computed only for numbers that are valid in the numbering plan; for invalid numbers they are omitted because they can mislead.

## Implemented security mechanisms

- **Offline by construction.** The package imports no HTTP client and performs no network I/O (`core.py`, `dorks.py`, `cli.py`).
- **CSV formula neutralisation.** Any text value starting with `=`, `+`, `-`, `@`, TAB or CR gets a leading apostrophe (`csv_safe` in `cli.py`). This includes `+48...` numbers in CSV. JSON output is left untouched.
- **Atomic exports.** JSON and CSV are written to a temporary file in the target directory, `fsync`ed and `os.replace`d (`_atomic_write`); a failure leaves neither a truncated file nor destroys the previous version.
- **Path-collision protection.** `--file`, `--json` and `--csv` are compared by resolved path and by file identity (`os.path.samefile`, so hard links are caught) before anything is written, so the input file cannot be overwritten (`find_path_collision`).
- **Strict input handling.** Batch input must be UTF-8 (a clear error otherwise), an empty or comments-only file is an error, an unsupported `--region` is rejected before any processing, and positional number plus `--file` are mutually exclusive.
- **No traffic from `--dorks`.** The variants are printed as text; nothing is opened or sent (`dorks.py`).

## Data handling and privacy boundaries

- It does **not** query any service: no account-existence checks, no HLR lookups, no reverse lookup, no scraping, and no attempt to link a number to a person.
- The carrier is the original numbering-plan allocation, not the current operator; the output carries a note to that effect (`CARRIER_NOTE_PL`, `CARRIER_NOTE_GENERIC` in `core.py`). For Poland it points to the national regulator's lookup for manual verification; the tool does not query it.
- Intended for your own numbers, company numbers, or numbers in an authorised engagement; it is not a means of establishing who owns someone else's number.
- Output files contain exactly the numbers you supplied; no state or cache is kept.

## Installation

Python 3.12+; one runtime dependency (`phonenumbers>=8.13`).

```bash
cd projects/osint-toolkit/phone-check
python -m venv .venv
python -m pip install -e ".[dev]"
```

On Windows, `START_PHONE_CHECK.cmd` bootstraps `.venv` and provides the alias `pc`.

## Usage

```bash
python -m phone_check "+48 000 000 000"
python -m phone_check "000 000 000" --region PL --dorks
python -m phone_check --file numbers.txt --csv results.csv --json results.json
```

Batch input (`--file`): one number per line, blank lines and `#` comments ignored. CSV uses `;` as the separator and UTF-8 with BOM. Columns: `input, valid, possible, region, country_name, country_code, geo_description, line_type, carrier, carrier_note, carrier_check_url, timezones, e164, international, national, rfc3966, error`; the technical fields `region_hint`, `parsed`, `line_type_code` appear in JSON only.

Exit codes: `0` all numbers valid; `1` at least one invalid; `2` usage or I/O error (bad argument, path collision, empty or unreadable file, failed write).

Note: the fake `+48 000 000 000` style placeholders used in documentation are not valid numbers, so the tool reports them as invalid. Use a real numbering-plan example when you need to see the full output.

## Configuration

No environment variables are read. Defaults live in `core.py`: `DEFAULT_REGION = "PL"` and `DEFAULT_LANG = "pl"`; override with `--region` and `--lang`.

## Testing

```bash
cd projects/osint-toolkit/phone-check
python -m pytest -q
```

Tests run offline (`tests/test_phone_check.py`, `tests/test_review_fixes.py`).

## Limitations

- "Valid" means consistent with the numbering plan in the library data, not that the number is active or who it belongs to.
- Carrier names may be outdated because of number portability.
- Mobile numbers in many countries carry no city-level geography; fixed-line geography reflects the area code, not the user's location.
- Results depend on the installed `phonenumbers` version; keep it updated.
- The CLI reads the whole file and keeps results in memory; it is intended for tens to hundreds of numbers, not large lists.
