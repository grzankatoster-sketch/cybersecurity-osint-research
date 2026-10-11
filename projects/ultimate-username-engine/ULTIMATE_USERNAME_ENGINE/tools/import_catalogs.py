"""Rebuild pinned catalog artifacts from local, read-only donor snapshots."""

import argparse
import json
from collections import Counter
from pathlib import Path

from ultimate_username.domain.codec import to_json
from ultimate_username.domain.json_types import parse_json
from ultimate_username.importers import find_conflicts, import_file
from ultimate_username.metadata_import import import_metadata
from ultimate_username.storage import atomic_write


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--donors", required=True, type=Path)
    parser.add_argument("--output", type=Path, default=Path(__file__).resolve().parents[1] / "data")
    args = parser.parse_args()
    sources = {
        "maigret": "maigret/maigret/resources/data.json",
        "sherlock": "sherlock/sherlock_project/resources/data.json",
        "whatsmyname": "whatsmyname/wmn-data.json",
    }
    batches = [import_file(donor, args.donors / relative) for donor, relative in sources.items()]
    sites = tuple(site for batch in batches for site in batch.sites)
    conflicts = find_conflicts(sites)
    metadata_path = args.donors / "blackbird/data/wmn-metadata.json"
    metadata = import_metadata(parse_json(metadata_path.read_text("utf-8")))
    summary = {
        batch.donor: {
            "total": len(batch.records),
            **dict(Counter(r.status for r in batch.records)),
            "disabled_imported": sum(s.disabled for s in batch.sites),
            "source_sha256": batch.source_sha256,
        }
        for batch in batches
    }
    summary["conflict_groups"] = len(conflicts)
    summary["blackbird_metadata"] = dict(Counter(r.status for r in metadata))
    for name, payload in [
        ("catalog.json", sites),
        ("import-records.json", tuple(batches)),
        ("conflicts.json", conflicts),
        ("blackbird-metadata.json", metadata),
    ]:
        atomic_write(args.output / name, [to_json(payload, indent=2)])
    atomic_write(args.output / "import-summary.json", [json.dumps(summary, indent=2)])
    lines = [
        "# Import definicji — lokalne snapshoty",
        "",
        "Nie wykonano zapytań do platform. IMPORTED oznacza poprawną konwersję offline, "
        "nie potwierdzoną skuteczność online.",
        "",
        "| Donor | Wszystkie | Imported | Invalid | Unsupported | Disabled w imported |",
        "|---|---:|---:|---:|---:|---:|",
    ]
    for batch in batches:
        counts = Counter(r.status for r in batch.records)
        lines.append(
            f"| {batch.donor} | {len(batch.records)} | {counts['IMPORTED']} | "
            f"{counts['INVALID']} | {counts['UNSUPPORTED']} | "
            f"{sum(s.disabled for s in batch.sites)} |"
        )
    lines.extend(
        [
            "",
            f"Konflikty: **{len(conflicts)} grup**; warianty zachowano bez automatycznego "
            "scalania. Grupy po nazwie i szablonie mogą częściowo się nakładać.",
            "",
            "Odrzucone z wykonywalnego katalogu = INVALID + UNSUPPORTED. Pełne rekordy, "
            "surowe dane i mapa każdego pola: `data/import-records.json`.",
            "",
            f"Blackbird: {len(metadata)} reguł metadanych; "
            + str(summary["blackbird_metadata"])
            + ". "
            "Nie przypisano automatycznie do platform bez weryfikacji kontekstu profilu.",
            "",
            "Historyczne reguły nie otrzymują wymyślonego profile binding ani kalibracji. "
            "Pozytywny sygnał daje najwyżej PROBABLE; błędy/blokady zawsze UNKNOWN. "
            "Puste markery pominięto z jawną diagnostyką. Nieobsługiwane protokoły, "
            "aktywacje, placeholdery hosta i niejednoznaczne konflikty silników trafiają "
            "do kwarantanny. `ignore403` jest zachowane jako metadana; gate nadal odrzuca 403.",
            "",
            "## Integralność wejścia",
            "",
        ]
    )
    lines.extend(f"- {b.donor}: SHA-256 `{b.source_sha256}`" for b in batches)
    atomic_write(args.output.parent / "IMPORT_REPORT.md", ["\n".join(lines) + "\n"])
    print(json.dumps(summary, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
