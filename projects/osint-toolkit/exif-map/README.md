# exif-map

Metadata and geotag inspector for **your own** photos and files, with an HTML map and an OPSEC "strip" mode that writes metadata-free copies before publication. It reads EXIF (camera, software, timestamps), GPS position, altitude and heading, reports which files leak location, and verifies that stripped copies are actually clean.

> A Polish version of this document is in [README.pl.md](README.pl.md). Console output is in Polish.

## Security use cases

- Pre-publication check: what does this image reveal (location, device, software, time)?
- Sanitising images for release: lossless removal of EXIF/XMP/comment and trailing data, with post-write verification.
- Reviewing evidence files you are authorised to handle: extracting GPS/time to a table, CSV/JSON or a map with a time-ordered track.
- Feeding GPS observations into `entity-graph` (it has an `exif-map` importer for the JSON/CSV output).

## How it works

| Module | Role |
|---|---|
| `src/exif_map/reader.py` | Pillow reader (EXIF, GPS IFD with N/S/E/W handling, altitude reference, heading); optional `exiftool` reader; per-file fallback to Pillow |
| `src/exif_map/gps.py`, `models.py` | DMS-to-decimal conversion, `PhotoMeta` model; (0, 0) and out-of-range coordinates are treated as "no GPS" |
| `src/exif_map/strip.py` | Writes cleaned copies; JPEG whole-stream parser; post-write verification (`leftover_metadata`) |
| `src/exif_map/mapview.py` | folium map with thumbnails and a time-ordered route |
| `src/exif_map/report.py` | Text table, warnings, JSON, CSV |
| `src/exif_map/reverse.py` | Prints manual reverse-image-search guidance; sends nothing |
| `src/exif_map/cli.py` | Argument handling and orchestration |

## Implemented security mechanisms

- **Originals are never overwritten.** `--strip FOLDER` writes copies; a name that collides with an existing file or with the original receives `_clean`, `_clean2`, ... (`unique_target` in `strip.py`). A strip folder located inside the scanned folder is excluded from the scan.
- **Lossless JPEG strip over the whole stream.** The parser removes APP1 (Exif/XMP), APP3-13, APP15, COM, non-ICC APP2 (MPF), non-JFIF APP0 and non-Adobe APP14 segments, including those located between progressive scans, and truncates everything after EOI (for example an appended archive or text). JFIF, ICC, Adobe APP14 and scan data are copied unchanged (`_parse_jpeg`, `_jpeg_lossless_strip`). A truncated JPEG without EOI is an error rather than an uncertain copy.
- **Re-encode path.** Other formats and JPEGs with an EXIF orientation are re-created from a clean pixel copy; orientation is baked into pixels and the ICC profile is kept (`_clean_copy`, `strip_file`).
- **Post-write verification.** The whole output file is re-parsed for leftover EXIF/GPS/XMP/comments/trailing data (`leftover_metadata`); results that are not verified are reported and exit code 3 is returned.
- **Input size limit.** Files over 200 MB are skipped with a message (`MAX_INPUT_BYTES` in `strip.py`).
- **Hardened exiftool invocation.** `-config ""` as the first argument (no user config code), `--` before absolute file paths so a file named like an option cannot change behaviour, read-only JSON mode, 120 s timeout, chunks of 40 files (`build_exiftool_cmd`, `run_exiftool` in `reader.py`).
- **Output escaping.** Map texts are HTML-escaped and additionally `$`, backtick and backslash are converted to entities to neutralise JavaScript template literals in folium output (`mapview.py`). CSV cells starting with `=`, `+`, `-`, `@`, TAB or CR receive an apostrophe (`csv_safe` in `report.py`); control characters in the text table are shown as `\xNN`.
- **Map privacy banner.** Generated maps carry a banner stating that the browser contacts OpenStreetMap and a CDN and that the file contains locations (`mapview.py`).
- **No face recognition.** `--reverse` deliberately lists no face-search engines.

## Data handling and privacy boundaries

- Local files only. The tool downloads nothing, performs no face recognition or identification of people, and `--reverse` only prints instructions for manual use.
- Reports, CSV/JSON and especially the map contain exact coordinates and thumbnails. Do not publish them.
- **The generated map is not offline.** When opened, the browser loads OpenStreetMap tiles and Leaflet from a CDN, so those servers see your IP and the viewed area. `--no-tiles` removes the OSM tiles but the JS/CSS libraries are still loaded from a CDN.
- Stripping removes embedded metadata only; it does not remove what is visible in the image content, the file name, or file-system timestamps.

## Installation

Python 3.12+. Runtime dependencies: `Pillow>=10`, `folium>=0.17`. Optional: `pillow-heif` (HEIC/HEIF) and the external `exiftool` binary (not installed by this package; found on `PATH` or in the sibling `narzedzia/` directory).

```bash
cd projects/osint-toolkit/exif-map
python -m venv .venv
python -m pip install -e ".[dev]"          # add ,heic for HEIC support
```

On Windows, `START_EXIF_MAP.cmd` bootstraps `.venv` and provides the alias `em`.

## Usage

```bash
python -m exif_map ./photos                                   # table + GPS warnings + summary
python -m exif_map ./photos --json report.json --csv report.csv
python -m exif_map ./photos --map map.html --no-tiles
python -m exif_map ./photos --strip ./clean --reverse
python -m exif_map photo.jpg --json --quiet                   # JSON to stdout, comments to stderr
```

Supported inputs: jpg, jpeg, png, tif, tiff, heic/heif (folders recursively). `--no-exiftool` forces Pillow only; `--quiet` suppresses the table.

Exit codes: `0` OK; `1` no supported files; `2` path does not exist; `3` `--strip` did not fully clean at least one file (including skipped oversized files).

## Configuration

No environment variables are read. `exiftool` is discovered from `PATH`, then by searching the sibling `narzedzia/` directory (`TOOLS_DIR` in `reader.py`).

## Testing

```bash
cd projects/osint-toolkit/exif-map
python -m pytest -q
```

Tests are offline and generate their own synthetic image fixtures (`tests/conftest.py`).

## Limitations

- EXIF timestamps are camera-local with no time zone; the route assumes one zone.
- HEIC/HEIF requires `pillow-heif` (also for `--strip`); otherwise use `exiftool` for reading.
- Strip loads a JPEG fully into memory (hence the 200 MB limit); multi-page TIFF keeps only the first frame.
- Pillow does not read video, RAW or XMP-only metadata; `exiftool` is needed for those. `exiftool` cannot see metadata hidden between progressive scans or after EOI, but `--strip` removes and verifies it.
- `--json` / `--csv` / `--map` writes are plain file writes (not atomic).
