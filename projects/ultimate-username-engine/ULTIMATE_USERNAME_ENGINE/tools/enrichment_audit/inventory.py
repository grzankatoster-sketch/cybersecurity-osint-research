import collections
import inspect
import json
import re
from pathlib import Path
from urllib.parse import urlsplit

from donor_runtime import BASE, load

ROOT = Path(__file__).resolve().parents[2] / "artifacts/enrichment"
main, _ = load()
schemes = main.schemes
source = BASE / "maigret" / "maigret" / "resources" / "data.json"
data = json.loads(source.read_text(encoding="utf-8"))
sites = data["sites"]
rows = []
fields = collections.defaultdict(list)
for name, scheme in schemes.items():
    names = set(scheme.get("fields", {}))
    if "regex" in scheme:
        names.update(k.removesuffix("_raw") for k in re.compile(scheme["regex"]).groupindex)
    hints = scheme.get("url_hints", ())
    domains = [h for h in hints if "/" not in h and "." in h and not h.endswith(".")]
    matches = []
    for site, definition in sites.items():
        hosts = [
            urlsplit(definition.get(k, "")).hostname or "" for k in ("url", "urlMain", "urlProbe")
        ]
        if any(host == hint or host.endswith("." + hint) for host in hosts for hint in domains):
            matches.append(site)
    mechanisms = []
    for key, kind in [
        ("regex", "REGEX"),
        ("bs", "HTML"),
        ("extract_json", "JSON"),
        ("transforms", "TRANSFORM"),
    ]:
        if scheme.get(key):
            mechanisms.append(kind)
    row = {
        "name": name,
        "fields": sorted(names),
        "mechanisms": mechanisms,
        "flags": scheme["flags"],
        "url_hints": hints,
        "potential_definitions": matches,
        "mutations": scheme.get("url_mutations", []),
        "field_sources": {
            k: inspect.getsource(v).strip() for k, v in scheme.get("fields", {}).items()
        },
    }
    rows.append(row)
    for field in names:
        fields[field].append(name)
derived = {
    "gravatar_url": ["Gravatar"],
    "gravatar_email_md5_hash": ["Gravatar"],
    "gravatar_username": ["Gravatar"],
    "email": ["YandexUsernameToEmail"],
}
for field in list(fields):
    if "email" in field:
        derived[field + "_username"] = ["EmailToUsername"]
catalog = json.loads((ROOT.parents[1] / "data/catalog.json").read_text(encoding="utf-8"))
if isinstance(catalog, dict):
    print("catalog keys", list(catalog))
    catalog = catalog.get("sites", catalog.get("definitions", []))
stats = {
    "source_definitions": len(sites),
    "imported_maigret": sum(s.get("provenance", {}).get("donor") == "maigret" for s in catalog),
    "all_imported_with_extractors": sum(bool(s.get("extractors")) for s in catalog),
    "schemes": len(rows),
    "static_field_names": len(fields),
    "derived_field_names": len(derived),
    "multi_field_schemes": sum(len(r["fields"]) > 1 for r in rows),
    "html_schemes": sum("HTML" in r["mechanisms"] for r in rows),
    "json_schemes": sum("JSON" in r["mechanisms"] for r in rows),
    "transform_schemes": sum("TRANSFORM" in r["mechanisms"] for r in rows),
    "regex_schemes": sum("REGEX" in r["mechanisms"] for r in rows),
    "hint_matched_definitions": len(set(s for r in rows for s in r["potential_definitions"])),
    "definition_keys": dict(collections.Counter(k for s in sites.values() for k in s)),
    "runtime_service_coverage": "UNKNOWN: flags inspect body, not definition or URL hints",
}
(ROOT / "inventory.json").write_text(
    json.dumps(
        {"stats": stats, "schemes": rows, "fields": fields, "derived": derived},
        ensure_ascii=False,
        indent=2,
    ),
    encoding="utf-8",
)
print(json.dumps(stats, indent=2))
