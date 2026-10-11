"""Import wyniku exif-map (JSON albo CSV): węzeł Photo z aparatem, oprogramowaniem i współrzędną GPS jako ATRYBUTAMI.
Bez geokodowania odwrotnego i bez żadnych powiązań z osobami: współrzędna to dana pliku, nie ustalenie o człowieku."""
from __future__ import annotations

import math

from ..model import Status
from ..normalize import EntityType
from .base import ImportCtx, Imported, as_bool, failed, unformula

TOOL = "exif-map"
CSV_HEADER = {"path", "has_gps", "camera"}
TEXT_FIELDS = ("taken", "taken_field", "camera", "make", "model", "software", "source")


def detect_json(data) -> bool:
    return (isinstance(data, list) and bool(data) and all(isinstance(r, dict) and "path" in r for r in data)
            and any(("has_gps" in r) or ("taken" in r) or ("camera" in r) for r in data))


def detect_csv(header: list[str]) -> bool:
    return CSV_HEADER <= {h.strip().lower() for h in header}


def _num(value, lo: float, hi: float) -> float | None:
    if isinstance(value, bool) or value in (None, ""):
        return None
    try:
        x = float(value)
    except (TypeError, ValueError):
        return None
    return x if math.isfinite(x) and lo <= x <= hi else None


def rows_from_csv(rows: list[dict]) -> list[dict]:
    out = []
    for r in rows:
        r = {k: unformula(v) for k, v in r.items()}
        out.append({**r, "has_gps": as_bool(r.get("has_gps"))})
    return out


def parse(rows: list, ctx: ImportCtx) -> Imported:
    imp = Imported(TOOL)
    for r in rows:
        if not isinstance(r, dict) or not str(r.get("path") or "").strip():
            imp.runs.append(("?", Status.ERROR, "exif-map: rekord bez ścieżki pliku"))
            continue
        label = str(r["path"])[:80]
        if r.get("error"):
            imp.runs.append((label, Status.ERROR, f"exif-map nie odczytał pliku: {str(r['error'])[:200]}"))
            continue
        attrs: dict = {"kind": "photo"}
        for k in TEXT_FIELDS:
            if str(r.get(k) or "").strip():
                attrs[k] = str(r[k]).strip()[:120]
        for k in ("width", "height"):
            v = _num(r.get(k), 0, 10**6)
            if v is not None:
                attrs[k] = int(v)
        lat, lon = _num(r.get("lat"), -90, 90), _num(r.get("lon"), -180, 180)
        note = ""
        if lat is not None and lon is not None:
            gps = {"lat": lat, "lon": lon}
            for k, lo, hi in (("altitude", -1000, 100000), ("direction", 0, 360)):
                v = _num(r.get(k), lo, hi)
                if v is not None:
                    gps[k] = v
            attrs["gps"] = gps
            attrs["gps_note"] = "współrzędna z metadanych pliku; nie jest ustaleniem miejsca pobytu osoby"
        elif r.get("lat") not in (None, "") or r.get("lon") not in (None, ""):
            note = "współrzędne GPS poza zakresem lub nieczytelne: pominięte"
        try:
            node = ctx.node(EntityType.PHOTO, str(r["path"]), attrs)
        except ValueError as exc:
            imp.runs.append((label, Status.ERROR, f"nieprawidłowa ścieżka: {exc}"))
            continue
        imp.nodes.append(node)
        imp.runs.append((node.id, Status.FOUND, note))
    return imp if imp.runs else failed(TOOL, "brak rekordów exif-map")
