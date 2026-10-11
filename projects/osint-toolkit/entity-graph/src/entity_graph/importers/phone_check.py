"""Import wyniku phone-check (JSON albo CSV z `;`): węzeł Phone WYŁĄCZNIE z metadanymi planu numeracji.
Żadnych powiązań z osobami: nie istnieje i nie powstanie transformacja numer -> osoba (patrz README)."""
from __future__ import annotations

from ..model import Status
from ..normalize import EntityType
from ..transforms.phone import parse_phone_check, phone_attrs
from .base import ImportCtx, Imported, as_bool, failed, unformula

TOOL = "phone-check"
CSV_HEADER = {"input", "valid", "e164"}


def detect_json(data) -> bool:
    rows = data if isinstance(data, list) else [data]
    return bool(rows) and all(isinstance(r, dict) and "parsed" in r and "input" in r for r in rows)


def detect_csv(header: list[str]) -> bool:
    return CSV_HEADER <= {h.strip().lower() for h in header}


def rows_from_csv(rows: list[dict]) -> list[dict]:
    """CSV nie ma pola parsed: numer uznajemy za sparsowany, gdy ma e164 i brak błędu."""
    out = []
    for r in rows:
        r = {k: unformula(v) for k, v in r.items()}
        e164 = (r.get("e164") or "").strip()
        err = (r.get("error") or "").strip() or None
        row = {"input": r.get("input", ""), "parsed": bool(e164) and not err, "valid": bool(as_bool(r.get("valid"))),
               "possible": bool(as_bool(r.get("possible"))), "error": err, "e164": e164 or None,
               "region_hint": r.get("region") or "PL"}
        for k in ("region", "country_name", "geo_description", "line_type", "carrier"):
            row[k] = (r.get(k) or "").strip() or None
        row["timezones"] = [t for t in (r.get("timezones") or "").split(",") if t.strip()]
        out.append(row)
    return out


def parse(rows: list, ctx: ImportCtx) -> Imported:
    imp = Imported(TOOL)
    for raw in rows:
        row = parse_phone_check(raw) if isinstance(raw, dict) else None
        label = str((row or {}).get("input") or "?")[:40]
        if row is None:
            imp.runs.append((label, Status.ERROR, "phone-check: nieprawidłowy rekord"))
            continue
        if not row.get("parsed"):
            imp.runs.append((label, Status.ERROR, f"phone-check nie sparsował numeru: {row.get('error')}"))
            continue
        try:
            node = ctx.node(EntityType.PHONE, str(row.get("e164") or row.get("input")), phone_attrs(row),
                            str(row.get("region_hint") or "PL"))
        except ValueError as exc:
            imp.runs.append((label, Status.ERROR, f"nieprawidłowy numer: {exc}"))
            continue
        imp.nodes.append(node)
        valid = bool(row.get("valid"))
        imp.runs.append((node.id, Status.FOUND if valid else Status.NOT_FOUND,
                         "" if valid else f"numer niepoprawny w planie numeracji: {row.get('error')}"))
    return imp if imp.runs else failed(TOOL, "brak rekordów phone-check")
