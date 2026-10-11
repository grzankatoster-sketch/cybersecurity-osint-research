"""Wspólne typy importerów: kontekst (źródło, znacznik czasu, fabryka krawędzi) i wynik importu jednego pliku.

Importery są OFFLINE: czytają pliki wynikowe narzędzi siostrzanych i budują węzły oraz krawędzie. Nigdy nie
podnoszą pewności (krawędź dostaje dokładnie tyle, ile podało źródło) i nigdy nie zamieniają ERROR w brak danych."""
from __future__ import annotations

from dataclasses import dataclass, field

from ..model import Edge, Graph, Node, Status, merge_value, parse_confidence
from ..normalize import EntityType
from ..transforms.base import TransformResult

MAX_FILE_BYTES = 50 * 1024 * 1024


class ImportCtx:
    """Podstawka pod `Context` transformacji: ta sama metoda `edge`, ale źródłem jest plik (import:<narzędzie>:<plik>)."""

    def __init__(self, tool: str, filename: str, now: str, min_confidence: float = 0.0):
        self.tool, self.filename = tool, filename
        self.source = f"import:{tool}:{filename}"
        self._now = now
        self.min_confidence = min_confidence

    def now(self) -> str:
        return self._now

    def edge(self, _transform: str, src: Node, dst: Node, relation: str, confidence: float, evidence: str) -> Edge:
        return Edge(src.id, dst.id, relation, self.source, confidence, evidence, self._now)

    def node(self, etype: EntityType, raw: str, attrs: dict | None = None, region: str = "PL") -> Node:
        return Node.make(etype, raw, attrs, self.source, region)

    def retag(self, nodes: list[Node]) -> None:
        for n in nodes:
            n.sources = [self.source]


@dataclass
class Imported:
    """Wynik importu jednego pliku. `skipped` != "" oznacza: plik pominięty (powód w polu)."""
    tool: str
    nodes: list[Node] = field(default_factory=list)
    edges: list[Edge] = field(default_factory=list)
    runs: list[tuple[str, Status, str]] = field(default_factory=list)   # (etykieta rekordu, status, uwaga/błąd)
    note: str = ""
    skipped: str = ""
    error: str = ""
    graph: Graph | None = None      # tylko import własnego grafu (scalany osobno)

    @property
    def label(self) -> str:
        if self.skipped:
            return "SKIPPED"
        if self.error or (self.runs and all(s is Status.ERROR for _, s, _ in self.runs)):
            return "ERROR"
        return "IMPORTED"

    @property
    def reason(self) -> str:
        if self.skipped:
            return self.skipped
        if self.error:
            return self.error
        errors = [n for _, s, n in self.runs if s is Status.ERROR]
        if errors and self.label == "ERROR":
            return errors[0]
        return self.note


def skipped(tool: str, reason: str) -> Imported:
    return Imported(tool, skipped=reason)


def failed(tool: str, reason: str) -> Imported:
    return Imported(tool, error=reason)


def from_transform(imp: Imported, ctx: ImportCtx, node: Node, res: TransformResult, label: str) -> None:
    """Wnosi wynik transformacji (zbudowany na atrapie kontekstu) do wyniku importu, ze źródłem = plik."""
    for k, v in res.node_attrs.items():
        node.attrs[k] = merge_value(node.attrs[k], v) if k in node.attrs else v
    nodes = [node, *res.nodes]
    ctx.retag(nodes)
    imp.nodes += nodes
    imp.edges += res.edges
    imp.runs.append((label, res.status, res.error or res.note))


def finite_confidence(value) -> float | None:
    """Pewność z pliku jako liczba 0-1 albo None (NaN/inf/bool/tekst/liczba spoza zakresu nie staną się pewnością)."""
    return parse_confidence(value)


def as_bool(value) -> bool | None:
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        low = value.strip().lower()
        if low in ("true", "1", "tak", "yes"):
            return True
        if low in ("false", "0", "nie", "no"):
            return False
    if isinstance(value, int):
        return bool(value)
    return None


def unformula(text):
    """Odwraca neutralizację formuł CSV (apostrof przed = + - @ TAB CR) zrobioną przez narzędzia siostrzane."""
    if isinstance(text, str) and len(text) > 1 and text[0] == "'" and text[1] in "=+-@\t\r":
        return text[1:]
    return text
