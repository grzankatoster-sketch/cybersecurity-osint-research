"""Import własnego grafu entity-graph (graph.json, schema=1): scalanie wcześniejszych badań w jeden graf.

Węzły o tym samym kluczu scalają się z istniejącymi, krawędzie zachowują swoje źródło i pewność (ta sama krawędź z dwóch
grafów dostaje wyższą z dwóch pewności, nigdy sumę), a dziennik uruchomień jest przenoszony ze statusami bez zmian."""
from __future__ import annotations

from ..model import Graph, Status
from .base import ImportCtx, Imported, failed

TOOL = "entity-graph"


def parse(data: dict, ctx: ImportCtx) -> Imported:
    try:
        graph = Graph.from_dict(data)
    except ValueError as exc:
        return failed(TOOL, f"graf entity-graph: {exc}")
    imp = Imported(TOOL, graph=graph)
    imp.runs.append(("graph", Status.FOUND, f"{len(graph.nodes)} węzłów, {len(graph.edges)} krawędzi"))
    return imp
