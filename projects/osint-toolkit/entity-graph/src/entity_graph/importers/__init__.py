"""Importery wyników narzędzi siostrzanych: wczytują pliki (OFFLINE) i scalają je w jeden graf.

Format rozpoznaje się po ZAWARTOŚCI (nazwa pliku nie ma znaczenia). Plik nierozpoznany, pusty, binarny albo zbyt duży
jest raportowany jako SKIPPED z powodem; plik uszkodzony jako ERROR; żaden plik nie przerywa pracy.
Statusy rekordów (FOUND/NOT_FOUND/UNKNOWN/ERROR) trafiają do graph.runs: ERROR nigdy nie staje się brakiem danych."""
from __future__ import annotations

import csv
import hashlib
import io
import json
import os
from dataclasses import dataclass, field
from pathlib import Path

from ..model import Graph, RunRecord, Status, utc_now
from . import (
    dns_audit,
    entity_graph_json,
    exif_map,
    hibp,
    meta_search,
    org_intel,
    osint_poland,
    phone_check,
    username_engine,
)
from .base import MAX_FILE_BYTES, ImportCtx, Imported, failed, skipped

MAX_FILES = 2000
SKIP_DIRS = frozenset({".git", ".venv", "venv", "node_modules", "__pycache__", ".pytest_cache"})
FORMATS = ("username-engine", "dns-audit", "phone-check", "hibp-monitor", "exif-map", "osint-poland", "entity-graph",
           "org-intel")


@dataclass
class FileReport:
    file: str
    format: str = ""
    status: str = "SKIPPED"      # IMPORTED | SKIPPED | ERROR
    reason: str = ""
    nodes: int = 0
    edges: int = 0
    sha256: str = ""
    errors: int = 0              # rekordy ze statusem ERROR wewnątrz pliku

    def to_dict(self) -> dict:
        return dict(self.__dict__)


@dataclass
class Collected:
    files: list[Path] = field(default_factory=list)
    problems: list[FileReport] = field(default_factory=list)


def collect(paths: list[str | Path], exclude: tuple[Path, ...] = ()) -> Collected:
    """Rozwija pliki i katalogi (rekurencyjnie, bez ukrytych i katalogów technicznych) do listy plików."""
    out = Collected()
    skip = tuple(p.resolve() for p in exclude)

    def excluded(p: Path) -> bool:
        rp = p.resolve()
        return any(rp == s or s in rp.parents for s in skip)

    for raw in paths:
        p = Path(raw)
        if not p.exists():
            out.problems.append(FileReport(str(raw), status="ERROR", reason="ścieżka nie istnieje"))
        elif p.is_dir():
            for root, dirs, names in os.walk(p):
                dirs[:] = sorted(d for d in dirs if d not in SKIP_DIRS and not d.startswith(".")
                                 and not excluded(Path(root) / d))
                for name in sorted(names):
                    if not name.startswith("."):
                        out.files.append(Path(root) / name)
        elif not excluded(p):
            out.files.append(p)
    seen, unique = set(), []
    for f in out.files:
        key = str(f.resolve())
        if key not in seen:
            seen.add(key)
            unique.append(f)
    if len(unique) > MAX_FILES:
        out.problems.append(FileReport(f"({len(unique) - MAX_FILES} plików)", status="SKIPPED",
                                       reason=f"limit {MAX_FILES} plików na uruchomienie"))
        unique = unique[:MAX_FILES]
    out.files = unique
    return out


def _sniff_csv(text: str) -> tuple[list[str], list[dict]] | None:
    first = text.splitlines()[0] if text.strip() else ""
    delimiter = ";" if first.count(";") > first.count(",") else ","
    try:
        reader = csv.DictReader(io.StringIO(text, newline=""), delimiter=delimiter)
        header = [h for h in (reader.fieldnames or []) if h is not None]
        rows = [r for r in reader]
    except csv.Error:
        return None
    return (header, rows) if len(header) >= 3 else None


def _is_graph(data) -> bool:
    return isinstance(data, dict) and data.get("schema") == 1 and isinstance(data.get("nodes"), list) \
        and isinstance(data.get("edges"), list)


def parse_file(path: Path, now: str, min_confidence: float = 0.0) -> tuple[Imported, str]:
    """-> (wynik, sha256 zawartości). Nie rzuca: każdy problem to Imported z skipped/error."""
    name = path.name
    try:
        size = path.stat().st_size
        if size > MAX_FILE_BYTES:
            return skipped("", f"plik większy niż {MAX_FILE_BYTES // (1024 * 1024)} MB"), ""
        raw = path.read_bytes()
    except OSError as exc:
        return failed("", f"nie można odczytać pliku ({type(exc).__name__})"), ""
    digest = hashlib.sha256(raw).hexdigest()
    try:
        text = raw.decode("utf-8-sig")
    except UnicodeDecodeError:
        return skipped("", "plik binarny albo nie w UTF-8"), digest
    stripped = text.strip()
    if not stripped:
        return skipped("", "pusty plik"), digest
    try:
        return _dispatch(path, name, text, stripped, now, min_confidence), digest
    except Exception as exc:  # noqa: BLE001 - jeden zły plik nie może przerwać łączenia pozostałych
        return failed("", f"błąd importu: {type(exc).__name__}"), digest


def _dispatch(path: Path, name: str, text: str, stripped: str, now: str, min_conf: float) -> Imported:
    def ctx(tool: str) -> ImportCtx:
        return ImportCtx(tool, name, now, min_conf)

    if stripped[0] in "{[":
        try:
            data = json.loads(stripped)
        except json.JSONDecodeError as exc:
            if path.suffix.lower() == ".json":
                return failed("", f"uszkodzony JSON (linia {exc.lineno}, kolumna {exc.colno})")
            return skipped("", "nierozpoznany format (nie jest poprawnym JSON)")
        return _dispatch_json(data, ctx)
    if osint_poland.detect_uldk(stripped):
        return osint_poland.parse_uldk(stripped, ctx(osint_poland.TOOL))
    sniffed = _sniff_csv(text.lstrip("﻿"))
    if sniffed:
        header, rows = sniffed
        if phone_check.detect_csv(header):
            return phone_check.parse(phone_check.rows_from_csv(rows), ctx(phone_check.TOOL))
        if exif_map.detect_csv(header):
            return exif_map.parse(exif_map.rows_from_csv(rows), ctx(exif_map.TOOL))
        if username_engine.detect_csv(header):
            return username_engine.parse(username_engine.from_csv_rows(rows), ctx(username_engine.TOOL))
    return skipped("", "nierozpoznany format pliku (obsługiwane: wyniki narzędzi siostrzanych w JSON/CSV oraz ULDK)")


def _dispatch_json(data, ctx) -> Imported:
    if _is_graph(data):
        return entity_graph_json.parse(data, ctx(entity_graph_json.TOOL))
    if org_intel.kind_of(data):     # przed hibp: eksport org-intel ma "domains" z polem "domain" jak monitor hibp
        return org_intel.parse(data, ctx(org_intel.TOOL))
    if osint_poland.kind_of(data):
        return osint_poland.parse(data, ctx(osint_poland.TOOL))
    if meta_search.detect(data):
        return meta_search.parse(data, ctx(meta_search.TOOL))
    if username_engine.detect_json(data):
        return username_engine.parse(data, ctx(username_engine.TOOL))
    if dns_audit.detect(data) or (isinstance(data, list) and data and all(dns_audit.detect(x) for x in data)):
        return dns_audit.parse(data, ctx(dns_audit.TOOL))
    if hibp.kind_of(data):
        return hibp.parse(data, ctx(hibp.TOOL))
    if phone_check.detect_json(data):
        return phone_check.parse(data if isinstance(data, list) else [data], ctx(phone_check.TOOL))
    if exif_map.detect_json(data):
        return exif_map.parse(data, ctx(exif_map.TOOL))
    keys = ", ".join(sorted(map(str, data))[:8]) if isinstance(data, dict) else f"lista ({len(data)})"
    return skipped("", f"nierozpoznany format JSON (najwyższy poziom: {keys[:120]})")


def merge_into_graph(graph: Graph, imp: Imported, filename: str, now: str) -> tuple[int, int]:
    """Wnosi wynik importu do grafu. -> (liczba węzłów, liczba krawędzi) z pliku."""
    for node in imp.nodes:
        graph.add_node(node, now)
    added = 0
    for edge in imp.edges:
        if graph.add_edge(edge):
            added += 1
    if imp.graph is not None:
        added += _merge_graph(graph, imp, filename, now)
    tool = f"import:{imp.tool}" if imp.tool else "import"
    if not imp.runs:
        status = Status.ERROR if imp.error else Status.UNKNOWN
        graph.runs.append(RunRecord(tool, filename, status, now, note="" if imp.error else f"SKIPPED: {imp.skipped}",
                                    error=imp.error))
    for label, status, text in imp.runs:
        graph.runs.append(RunRecord(tool, label, status, now, note="" if status is Status.ERROR else text,
                                    error=text if status is Status.ERROR else ""))
    return len(imp.nodes) + (len(imp.graph.nodes) if imp.graph else 0), added


def _merge_graph(graph: Graph, imp: Imported, filename: str, now: str) -> int:
    other = imp.graph
    marker = f"import:entity-graph:{filename}"
    for node in other.nodes.values():
        if marker not in node.sources:
            node.sources.append(marker)
        graph.add_node(node, now)
    added = sum(1 for e in other.edges.values() if graph.add_edge(e))
    graph.runs.extend(other.runs)
    graph.meta.setdefault("merged_graphs", []).append(
        {"file": filename, "purpose": str(other.meta.get("purpose", ""))[:200], "started": str(other.meta.get("started", ""))})
    return added


def import_files(graph: Graph, paths: list[str | Path], now: str | None = None, min_confidence: float = 0.0,
                 exclude: tuple[Path, ...] = (), on_file=None) -> list[FileReport]:
    """Importuje pliki do grafu; raport każdego pliku trafia też do graph.meta['imports']."""
    now = now or utc_now()
    found = collect(paths, exclude)
    reports: list[FileReport] = list(found.problems)
    for problem in found.problems:
        graph.runs.append(RunRecord("import", problem.file, Status.ERROR if problem.status == "ERROR" else Status.UNKNOWN,
                                    now, note="" if problem.status == "ERROR" else f"SKIPPED: {problem.reason}",
                                    error=problem.reason if problem.status == "ERROR" else ""))
        if on_file:
            on_file(problem)
    for path in found.files:
        imp, digest = parse_file(path, now, min_confidence)
        n_nodes, n_edges = merge_into_graph(graph, imp, path.name, now)
        report = FileReport(str(path), imp.tool or "", imp.label, imp.reason, n_nodes, n_edges, digest,
                            sum(1 for _, s, _ in imp.runs if s is Status.ERROR))
        reports.append(report)
        if on_file:
            on_file(report)
    graph.meta.setdefault("imports", []).extend(r.to_dict() for r in reports)
    return reports
