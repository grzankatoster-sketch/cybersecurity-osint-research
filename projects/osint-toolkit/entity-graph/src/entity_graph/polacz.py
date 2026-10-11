"""Łączenie kropek: import plików wynikowych narzędzi siostrzanych -> jeden graf -> scalanie identyfikatorów ->
korelacja (same_person) -> powiązania z dowodami. Wszystko OFFLINE; każdy krok trafia do dziennika audytu."""
from __future__ import annotations

from pathlib import Path

from . import links
from .correlate import correlate
from .guardrails import AuditLog
from .importers import FileReport, import_files
from .model import Graph, Status, utc_now


def summarize(reports: list[FileReport]) -> dict:
    out = {"IMPORTED": 0, "SKIPPED": 0, "ERROR": 0}
    for r in reports:
        out[r.status] = out.get(r.status, 0) + 1
    return out


def connect_dots(graph: Graph, paths: list[str | Path], audit: AuditLog, now: str | None = None,
                 min_confidence: float = 0.0, exclude: tuple[Path, ...] = (), progress=None) -> dict:
    now = now or utc_now()

    def on_file(r: FileReport) -> None:
        audit.write("import", file=r.file, format=r.format, status=r.status, reason=r.reason, nodes=r.nodes,
                    edges=r.edges, record_errors=r.errors, sha256=r.sha256)
        if progress:
            progress(f"{r.status:<8} {r.format or '-':<16} {r.file}" + (f"  ({r.reason})" if r.reason else ""))

    reports = import_files(graph, paths, now, min_confidence, exclude, on_file)
    merges = links.merge_identifiers(graph)
    audit.write("merge", merges=len(merges), details=[{"kept": m["kept"], "merged": m["merged"],
                                                      "identifier": m["identifier"]} for m in merges],
                conflicts=len(graph.meta.get("conflicts", [])))
    same_person = correlate(graph, now)
    new_links = links.connect(graph, now)
    summary = summarize(reports)
    statuses = {s.value: sum(1 for r in graph.runs if r.status is s) for s in Status}
    audit.write("end", nodes=len(graph.nodes), edges=len(graph.edges), inputs=summary,
                same_person_links=len(same_person), links=len(new_links), merges=len(merges), statuses=statuses)
    return {"reports": reports, "inputs": summary, "merges": len(merges), "links": len(new_links),
            "same_person": len(same_person), "statuses": statuses}
