"""Transformacja nazwy użytkownika: skan username-engine (podproces, jego baza ~5800 serwisów).

Z profilu zostają tylko pola potrzebne do porównania (nazwa wyświetlana, skrót awatara, strona www, linki, typ encji,
odcisk bio: skróty słów zamiast treści). Treść bio i lokalizacja nie są przenoszone (minimalizacja danych)."""
from __future__ import annotations

import json
import tempfile
from pathlib import Path

from .. import siblings
from ..evidence import bio_fingerprint
from ..model import Node, Status, parse_confidence
from ..normalize import EntityType, avatar_hash_from_url, normalize_url
from .base import Context, TransformResult, register

MAX_PROFILE_LINKS = 10


def profile_attrs(result: dict) -> dict:
    prof = result.get("profile") if isinstance(result.get("profile"), dict) else {}
    links = []
    for raw in prof.get("links") or []:
        try:
            links.append(normalize_url(str(raw))[1])
        except ValueError:
            continue
    attrs = {
        "kind": "profile", "site": str(result.get("site", "")),
        "display_name": str(prof.get("name") or "")[:120],
        "avatar_hash": avatar_hash_from_url(str(prof["avatar"])) if prof.get("avatar") else "",
        "website": str(prof.get("website") or "")[:300],
        "links": list(dict.fromkeys(links))[:MAX_PROFILE_LINKS],
        "created": str(prof.get("created") or "")[:40],
        "bio_fingerprint": bio_fingerprint(str(prof.get("bio") or "")),
        "entity_kind": str(prof.get("entity_kind") or "") if prof.get("entity_kind") in ("person", "organization") else "",
        "insecure": bool(result.get("insecure")),
    }
    return {k: v for k, v in attrs.items() if v}


def parse_scan(payload: dict, min_confidence: float) -> tuple[list[dict], dict]:
    """-> (trafienia FOUND z pewnością >= próg, liczniki statusów)."""
    results = payload.get("results") if isinstance(payload, dict) else None
    if not isinstance(results, dict) or not results:
        raise ValueError("brak sekcji results")
    rows = next(iter(results.values()))
    counts = {"FOUND": 0, "NOT_FOUND": 0, "ERROR": 0, "UNSUPPORTED": 0}
    hits = []
    for r in rows:
        status = str(r.get("status") or "").strip().upper()
        conf = parse_confidence(r.get("confidence"))
        if status == "FOUND" and conf is None:
            status = "ERROR"   # pewność inf/NaN/bool/spoza 0-1 to błąd serwisu, nie trafienie
        counts[status] = counts.get(status, 0) + 1
        if status == "FOUND" and conf >= min_confidence:
            hits.append({**r, "confidence": conf})
    return hits, counts


def aggregate_status(hits: list, counts: dict) -> tuple[Status, str]:
    """Status całego skanu. Błędy serwisów nigdy nie zamieniają się w NOT_FOUND:
    brak trafień przy jakichkolwiek błędach to UNKNOWN (nie wszystkie serwisy dało się sprawdzić)."""
    if hits:
        return Status.FOUND, ""
    if counts.get("ERROR", 0):
        return Status.UNKNOWN, (f"brak pewnych trafień, ale {counts['ERROR']} serwisów nie dało się sprawdzić "
                                "(blokady, timeout): to nie jest dowód braku kont")
    if counts.get("NOT_FOUND", 0):
        return Status.NOT_FOUND, "wszystkie sprawdzone serwisy jawnie odpowiedziały, że konta nie ma"
    return Status.UNKNOWN, "nie sprawdzono żadnego serwisu"


@register("username_scan", (EntityType.USERNAME,), "username-engine (siostrzane): konta w ~5800 serwisach")
def username_scan(node: Node, ctx: Context) -> TransformResult:
    s = ctx.settings
    with tempfile.TemporaryDirectory(prefix="eg-ue-", dir=ctx.tmp_dir) as tmp:
        # username-engine przyjmuje w --json samą nazwę pliku i zapisuje ją w podkatalogu skanu w --results-dir
        args = ["--no-variants", "--json", "scan.json", "--results-dir", tmp, "--timeout", "15",
                "--min-confidence", str(s.ue_min_confidence)]
        if s.ue_tags:
            args += ["--tags", s.ue_tags]
        if s.ue_limit:
            args += ["--limit", str(s.ue_limit)]
        args += ["--", node.value]   # "--": nazwa zaczynająca się od "-" nie zostanie wzięta za opcję
        try:
            out = siblings.run_sibling("username-engine", args, ctx.tools_dir, s.ue_timeout, ctx.runner)
        except siblings.SiblingUnavailable as exc:
            return TransformResult.failed(Status.UNKNOWN, f"username-engine niedostępny: {exc}")
        except TimeoutError as exc:
            return TransformResult.failed(Status.ERROR, f"username-engine: {exc}")
        out_path = next(Path(tmp).rglob("scan.json"), None)
        if out.returncode != 0 or out_path is None:
            return TransformResult.failed(
                Status.ERROR, f"username-engine: kod {out.returncode}, {out.stderr.strip()[:200] or 'brak pliku wyniku'}")
        try:
            hits, counts = parse_scan(json.loads(out_path.read_text(encoding="utf-8")), s.ue_min_confidence)
        except (ValueError, TypeError, AttributeError) as exc:   # JSONDecodeError dziedziczy po ValueError
            return TransformResult.failed(Status.ERROR, f"username-engine: nieprawidłowy plik wyniku ({type(exc).__name__})")
    return scan_result(node, hits, counts, ctx)


def scan_result(node: Node, hits: list, counts: dict, ctx: Context) -> TransformResult:
    """Wynik transformacji z trafień skanu (parse_scan). Używane też przez importer plików."""
    status, note = aggregate_status(hits, counts)
    res = TransformResult(status, note=note, stats=counts)
    for r in hits:
        try:
            prof = Node.make(EntityType.URL, str(r.get("url", "")), profile_attrs(r), "username_scan")
        except ValueError:
            continue
        res.nodes.append(prof)
        res.edges.append(ctx.edge(
            "username_scan", node, prof, "has_account", float(r["confidence"]),
            f"username-engine: {r.get('site')}: {r.get('reason') or 'trafienie'}. Ta sama nazwa nie dowodzi tej samej osoby"))
    return res
