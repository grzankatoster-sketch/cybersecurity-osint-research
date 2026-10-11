"""Sprawa: katalog badania (graph.json + audit.jsonl) jako jedno miejsce na teczkę osoby, twierdzenia o relacjach,
kontekst numerów i kandydatów profili. Używają go polecenia CLI i panel (przez CLI), więc reguły są w jednym miejscu.

Zasady wspólne:
  * sprawę otwiera się tylko ze spójnym dziennikiem audytu; cel sprawy pochodzi z pierwszego wpisu dziennika
  * każda akcja zmieniająca sprawę zapisuje wpis "przed" (zanim cokolwiek zmieni) i "po" (wynik); gdy wpisu "przed"
    nie da się zapisać, akcja się nie wykonuje
  * źródło informacji to publiczny adres http(s) albo dokument już leżący w katalogu sprawy (zapisujemy ścieżkę
    względną, skrót SHA-256 i rozmiar, nigdy treść)
"""
from __future__ import annotations

import hashlib
import json
import re
import unicodedata
from dataclasses import dataclass
from pathlib import Path
from typing import Callable
from urllib.parse import urlsplit

from .export import render_html, to_graphml, to_maltego_csv
from .guardrails import AuditLog, GuardrailError, validate_purpose, verify_audit
from .kropki import render_svg
from .model import Graph, write_atomic

DOC_PREFIX = "dokument:"
CASE_FILES = frozenset({"graph.json", "graph.graphml", "maltego.csv", "report.html", "kropki.svg", "audit.jsonl"})
MAX_REF = 500
MAX_DOC_BYTES = 50 * 1024 * 1024
_CTRL = re.compile(r"[\x00-\x1f\x7f]")


@dataclass
class Case:
    folder: Path
    graph: Graph
    audit: AuditLog
    purpose: str


def case_purpose(folder: Path) -> str:
    """Cel sprawy z pierwszego wpisu dziennika (wpis 'start', sprawdzony przez verify_audit)."""
    first = (folder / "audit.jsonl").read_text(encoding="utf-8").split("\n", 1)[0]
    return validate_purpose(json.loads(first).get("purpose"))


def open_case(case: str | Path, operator: str | None = None) -> Case:
    folder = Path(case)
    ok, msg = verify_audit(folder / "audit.jsonl")
    if not ok:
        raise GuardrailError(f"dziennik audytu w {folder}: {msg}; zmiany w sprawie wymagają badania z celem w dzienniku")
    return Case(folder, Graph.load(folder / "graph.json"), AuditLog(folder / "audit.jsonl", operator),
                case_purpose(folder))


def save_case(case: Case) -> None:
    g = case.graph
    g.save(case.folder / "graph.json")
    write_atomic(case.folder / "graph.graphml", to_graphml(g))
    write_atomic(case.folder / "maltego.csv", to_maltego_csv(g))
    write_atomic(case.folder / "report.html", render_html(g))
    write_atomic(case.folder / "kropki.svg", render_svg(g))


def audited(case: Case, event: str, fields: dict, action: Callable[[], dict]) -> dict:
    """Wpis 'przed' -> akcja -> wpis 'po' -> zapis plików sprawy (gdy coś się zmieniło).

    Akcja zwraca słownik wyniku z kluczem 'changed' (bool). Wyjątek akcji zostawia wpis 'po' z błędem i jest
    przekazywany dalej; plików sprawy wtedy nie zapisujemy."""
    try:
        case.audit.write(event, phase="przed", **fields)
    except OSError as exc:
        raise GuardrailError(f"nie można zapisać dziennika audytu ({exc}); operacja nie została wykonana") from exc
    try:
        result = action()
    except Exception as exc:
        try:
            case.audit.write(event, phase="po", result="błąd", error=f"{type(exc).__name__}: {str(exc)[:200]}")
        except OSError:
            pass
        raise
    try:
        case.audit.write(event, phase="po", result="zmieniono" if result.get("changed") else "bez zmian",
                         **{k: v for k, v in result.items() if k != "changed"})
    except OSError as exc:
        # Akcja zmieniła wyłącznie graf w pamięci. Bez końcowego wpisu audytu nie utrwalamy jej w plikach sprawy.
        raise GuardrailError(f"nie można zapisać wyniku w dzienniku audytu ({exc}); operacja nie została zapisana") from exc
    if result.get("changed"):
        save_case(case)
    return result


def clean_text(raw: str | None, name: str, max_len: int, required: bool = True, min_words: int = 1) -> str:
    """Tekst operatora: jedna linia bez znaków sterujących, przycięte spacje, limit długości (błąd, nie przycięcie)."""
    text = " ".join(unicodedata.normalize("NFC", str(raw or "")).split())
    if _CTRL.search(text):
        raise ValueError(f"{name}: niedozwolone znaki sterujące")
    if len(text) > max_len:
        raise ValueError(f"{name}: najwyżej {max_len} znaków")
    if required and (not text or len(text.split()) < min_words):
        raise ValueError(f"{name}: pole wymagane" + (f" (min. {min_words} słowa)" if min_words > 1 else ""))
    return text


def _safe_url(raw: str) -> str | None:
    try:
        parts = urlsplit(raw)
    except ValueError:
        return None
    if parts.scheme.lower() not in ("http", "https") or not parts.hostname or "@" in parts.netloc:   # bez danych logowania
        return None
    return raw if not re.search(r"[\s\x00-\x1f\x7f]", raw) else None


def check_reference(raw: str | None, folder: Path) -> dict:
    """Identyfikowalna referencja źródła: publiczny URL albo 'dokument:ŚCIEŻKA' pliku w katalogu sprawy.

    Dokument: ścieżka względna, bez '..' i dowiązań, istniejący zwykły plik wewnątrz sprawy, nie plik techniczny
    sprawy. Zapisujemy ścieżkę, SHA-256 i rozmiar; treść nie trafia do grafu ani dziennika."""
    text = str(raw or "").strip()
    if not text or len(text) > MAX_REF or _CTRL.search(text):
        raise ValueError("źródło jest wymagane: publiczny adres http(s) albo 'dokument:ŚCIEŻKA' pliku w katalogu sprawy")
    if text.lower().startswith(DOC_PREFIX):
        rel = text[len(DOC_PREFIX):].strip().replace("\\", "/")
        parts = [p for p in rel.split("/") if p]
        if not parts or rel.startswith("/") or re.match(r"^[A-Za-z]:", rel) or any(p in (".", "..") for p in parts):
            raise ValueError("dokument: podaj ścieżkę względną wewnątrz katalogu sprawy (bez '..' i dysku)")
        root = folder.resolve()
        path = folder.joinpath(*parts)
        try:
            resolved = path.resolve(strict=True)
            resolved.relative_to(root)
        except (OSError, ValueError):
            raise ValueError("dokument: pliku nie ma w katalogu sprawy") from None
        if path.is_symlink() or not resolved.is_file() or (len(parts) == 1 and parts[0] in CASE_FILES):
            raise ValueError("dokument: to musi być zwykły plik sprawy (nie dowiązanie ani plik techniczny)")
        size = resolved.stat().st_size
        if size > MAX_DOC_BYTES:
            raise ValueError("dokument: plik większy niż 50 MB")
        digest = hashlib.sha256()
        with open(resolved, "rb") as fh:
            for chunk in iter(lambda: fh.read(1 << 16), b""):
                digest.update(chunk)
        return {"kind": "document", "ref": "/".join(parts), "sha256": digest.hexdigest(), "bytes": size}
    url = _safe_url(text)
    if url is None:
        raise ValueError("źródło: tylko publiczny adres http(s) (bez danych logowania) albo 'dokument:ŚCIEŻKA'")
    return {"kind": "url", "ref": url}


def reference_label(ref: dict) -> str:
    if ref.get("kind") == "document":
        return f"dokument sprawy: {ref.get('ref')} (SHA-256 {str(ref.get('sha256', ''))[:16]})"
    return str(ref.get("ref", ""))


def summary(graph: Graph) -> dict:
    """Widok sprawy (dla panelu i `eg sprawa --json`). Przy każdej pozycji osobno: status źródła, pewność powiązania,
    decyzja operatora. Niczego nie liczy od nowa poza odczytem grafu."""
    from . import kandydaci, profile_discovery, relacje, teczka, telefon
    from .correlate import account_confidence, is_profile
    from .normalize import EntityType

    nodes = graph.nodes
    people = graph.nodes_of_type(EntityType.PERSON)
    runs: dict[tuple[str, str], object] = {}
    for r in graph.runs:
        runs[(r.transform, r.node_id)] = r

    def run_status(transform: str, node_id: str) -> dict:
        r = runs.get((transform, node_id))
        if r is None:
            return {"status": "nie sprawdzono", "note": ""}
        return {"status": r.status.value, "note": r.error or r.note, "at": r.timestamp, "stats": r.stats}

    out_people = []
    for p in people:
        names = [nodes[e.dst].value for e in graph.edges.values()
                 if e.src == p.id and e.relation == "candidate_username" and e.dst in nodes]
        out_people.append({"id": p.id, "value": p.value, "sources": p.sources, "first_seen": p.first_seen,
                           "candidate_usernames": names})
    usernames = [{"value": u.value, "candidate": bool(u.attrs.get("candidate")), "sources": u.sources,
                  "scan": run_status("username_scan", u.id)} for u in graph.nodes_of_type(EntityType.USERNAME)]
    phones = []
    for ph in graph.nodes_of_type(EntityType.PHONE):
        ctx = telefon.context(ph)
        if not ctx["log"]:
            ctx["source_status"] = run_status("phone_metadata", ph.id)
        elif any(c.startswith("phone_valid:") for c in ctx["conflicts"]) or "phone_valid" not in ph.attrs:
            ctx["source_status"] = {"status": "UNKNOWN", "note": "sprzeczne albo niepełne wyniki phone-check"}
        else:
            ctx["source_status"] = {
                "status": "FOUND" if ph.attrs["phone_valid"] else "NOT_FOUND",
                "note": "wynik phone-check w sprawie",
            }
        ctx["confidence"] = None
        ctx["decision"] = "nie dotyczy"
        phones.append(ctx)
    out_claims = []
    for c in relacje.claims(graph):
        a, b = nodes.get(c.get("src")), nodes.get(c.get("dst"))
        out_claims.append({
            "id": c["id"], "label": relacje.describe(c), "kind": c.get("kind"), "symmetric": bool(c.get("symmetric")),
            "a": a.value if a else c.get("src"), "b": b.value if b else c.get("dst"),
            "source_status": "twierdzenie operatora ze źródłem", "confidence": c.get("confidence", 0.0),
            "decision": c.get("status"), "decision_evidence": c.get("decision_evidence", ""),
            "decided_at": c.get("decided_at", ""), "created_at": c.get("created_at", ""), "purpose": c.get("purpose", ""),
            "sources": [{"label": reference_label(s.get("source") or {}), "kind": (s.get("source") or {}).get("kind"),
                         "url": (s.get("source") or {}).get("ref") if (s.get("source") or {}).get("kind") == "url" else "",
                         "evidence": s.get("evidence", ""), "excerpt": s.get("excerpt", ""),
                         "added_at": s.get("added_at", "")} for s in c.get("sources") or [] if isinstance(s, dict)]})
    candidates = []
    for prof in nodes.values():
        if not is_profile(prof):
            continue
        via = [nodes[e.src].value for e in graph.edges.values()
               if e.dst == prof.id and e.relation == "has_account" and e.src in nodes]
        decisions = [{"person": p.value, "decision": teczka.decision_of(graph, p, prof)} for p in people
                     if teczka.decision_of(graph, p, prof)]
        assessed = sorted((e for e in graph.edges.values() if e.dst == prof.id and e.relation == kandydaci.RELATION),
                          key=lambda e: e.timestamp)
        a = prof.attrs
        candidates.append({
            "url": prof.value, "site": a.get("site", ""), "display_name": a.get("display_name", ""),
            "website": a.get("website", ""), "links": a.get("links") or [], "via_usernames": via,
            "source_status": "FOUND (username-engine)" if via else ("dodany ręcznie" if a.get("manual") else
                                                                     "wyszukiwanie profili po nazwisku" if a.get("discovery")
                                                                     else "?"),
            "confidence": account_confidence(graph, prof), "decisions": decisions,
            "link_confidence": max((e.confidence for e in graph.edges.values() if e.dst == prof.id
                                    and e.relation == teczka.CONFIRMED), default=0.0),
            "decision": "wymaga potwierdzenia" if not decisions else ", ".join(
                f"{d['person']}: {'potwierdzony' if d['decision'] == teczka.CONFIRMED else 'odrzucony'}" for d in decisions),
            "assessment": assessed[-1].evidence if assessed else "", "first_seen": prof.first_seen,
            "conflicts": prof.conflicts()})
    candidates.sort(key=lambda c: (bool(c["decisions"]), -(c["confidence"] or 0), c["url"]))
    meta = graph.meta
    return {
        "case": {k: meta.get(k, "") for k in ("purpose", "case_ref", "operator", "started", "finished")},
        "people": out_people, "usernames": usernames, "phones": phones, "claims": out_claims,
        "claim_conflicts": relacje.contradictions(graph), "candidates": candidates,
        "rounds": [{k: r.get(k) for k in ("round", "started", "entry", "totals", "stop_reason", "proposals",
                                          "queries", "skipped", "scope")} for r in kandydaci.rounds(graph)],
        "proposals": kandydaci.pending_proposals(graph),
        "limits": {"names": kandydaci.MAX_NAMES, "queries": kandydaci.MAX_QUERIES, "cost": kandydaci.MAX_COST,
                   "seconds": kandydaci.MAX_SECONDS, "rounds": kandydaci.MAX_ROUNDS},
        "relation_kinds": relacje.INPUT_LABELS,
        "discovery": profile_discovery.summary(graph),
    }
