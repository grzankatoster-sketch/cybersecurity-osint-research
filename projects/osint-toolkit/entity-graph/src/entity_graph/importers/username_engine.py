"""Import wyniku username-engine (--json albo --csv): Username -> konta (URL, kind=profile) z pewnością DOKŁADNIE taką,
jak podał skaner. Rekordy NOT_FOUND i ERROR nie tworzą węzłów kont; zostają policzone na węźle Username, a skan,
w którym nic nie dało się sprawdzić, dostaje status ERROR (nigdy NOT_FOUND)."""
from __future__ import annotations

from ..model import Status
from ..normalize import EntityType
from ..transforms.username import aggregate_status, parse_scan, scan_result
from .base import ImportCtx, Imported, failed, finite_confidence, from_transform

TOOL = "username-engine"
MAX_ERROR_SITES = 50
CSV_HEADER = {"nazwa", "serwis", "status", "pewnosc", "url"}


def detect_json(data) -> bool:
    results = data.get("results") if isinstance(data, dict) else None
    return isinstance(results, dict) and bool(results) and all(isinstance(v, list) for v in results.values())


def detect_csv(header: list[str]) -> bool:
    return CSV_HEADER <= {h.strip().lower() for h in header}


def from_csv_rows(rows: list[dict]) -> dict:
    """Wiersze CSV username-engine -> struktura jak w JSON (bez danych profilu, których CSV nie zawiera)."""
    results: dict[str, list] = {}
    for r in rows:
        results.setdefault(str(r.get("nazwa", "")), []).append({
            "site": r.get("serwis", ""), "url": r.get("url", ""), "status": str(r.get("status", "")).strip().upper(),
            "confidence": r.get("pewnosc", ""), "reason": r.get("uzasadnienie", "")})
    return {"results": results}


def _clean_rows(rows: list) -> tuple[list[dict], int]:
    """Wiersze nie-słowniki wypadają; FOUND z nieczytelną pewnością (tekst, NaN) staje się ERROR, nie trafieniem."""
    out, bad = [], 0
    for r in rows:
        if not isinstance(r, dict):
            bad += 1
            continue
        r = dict(r)
        r["status"] = str(r.get("status", "")).upper()
        conf = finite_confidence(r.get("confidence"))
        if r["status"] == "FOUND" and conf is None:
            r["status"], r["reason"], conf = "ERROR", "nieczytelna pewność w pliku", 0.0
        r["confidence"] = conf if conf is not None else 0.0
        out.append(r)
    return out, bad


def parse(data: dict, ctx: ImportCtx) -> Imported:
    imp = Imported(TOOL)
    for name, rows in data["results"].items():
        rows, bad = _clean_rows(rows)
        try:
            user = ctx.node(EntityType.USERNAME, str(name))
        except ValueError as exc:
            imp.runs.append((f"username:{name}"[:60], Status.ERROR, f"nieprawidłowa nazwa użytkownika: {exc}"))
            continue
        try:
            hits, counts = parse_scan({"results": {name: rows}}, ctx.min_confidence) if rows else ([], {})
        except ValueError:
            imp.runs.append((user.id, Status.ERROR, "pusta lista wyników skanu"))
            continue
        status, note = aggregate_status(hits, counts)
        checked = counts.get("FOUND", 0) + counts.get("NOT_FOUND", 0)
        if not hits and counts.get("ERROR", 0) and not checked:
            status, note = Status.ERROR, (f"żaden serwis nie dał rozstrzygnięcia ({counts['ERROR']} błędów): "
                                          "to nie jest dowód braku kont")
        elif not hits and counts.get("FOUND", 0):
            status, note = Status.UNKNOWN, f"{counts['FOUND']} trafień poniżej progu pewności {ctx.min_confidence}"
        user.attrs["scan_counts"] = {k: v for k, v in counts.items() if v}
        errors = [str(r.get("site", "?"))[:60] for r in rows if r["status"] == "ERROR"]
        if errors:
            user.attrs["scan_error_sites"] = errors[:MAX_ERROR_SITES]
        res = scan_result(user, hits, counts, ctx)
        res.status, res.note = status, note + (f"; pominięto {bad} nieczytelnych rekordów" if bad else "")
        res.error = note if status is Status.ERROR else ""
        res.note = "" if status is Status.ERROR else res.note
        for edge in res.edges:   # status i pewność dokładnie jak w skanie (nic nie podnosimy)
            dst = next((n for n in res.nodes if n.id == edge.dst), None)
            if dst is not None:
                dst.attrs["account_status"] = "FOUND"
                dst.attrs["account_confidence"] = edge.confidence
        from_transform(imp, ctx, user, res, user.id)
    if not imp.runs and not imp.nodes:
        return failed(TOOL, "brak wyników skanu w pliku")
    return imp
