"""Model grafu: węzły (encje), krawędzie (z dowodem), rekordy uruchomień transformacji. Zapis JSON.

Obserwacje pól dowodowych (OBSERVED_FIELDS = EVIDENCE_FIELDS profili + PHONE_FIELDS kontekstu numeru): każda wartość
takiego pola jest zapisywana razem ze źródłami, które ją podały (Node.observations). Gdy dwie obserwacje tego samego rekordu różnią się, żadna nie wygrywa: pole znika z
attrs (wartość nieznana), flaga insecure przyjmuje wartość ostrożną (True), a sprzeczność jest widoczna w
Node.conflicts() i w zapisie. Wynik nie zależy od kolejności obserwacji.

Zgodność zapisu: schema=1 bez zmian; klucz "observations" węzła i "observation_model" grafu są dodatkowe. Pola
PHONE_FIELDS doszły w tym samym modelu 1 (rozszerzenie): każdy starszy plik czyta się bez zmian, ale plik z obserwacjami
pól telefonu nie wczyta się w wersji sprzed rozszerzenia (odrzuci nieznane pole zamiast zgadywać). Graf
zapisany przed modelem obserwacji czyta się świadomie (Graph.legacy_observations): wartość pola dowodowego z attrs
traktowana jest jak JEDNA obserwacja wszystkich źródeł węzła, bo nie da się odtworzyć, które źródło ją podało.

Pewność krawędzi (check_confidence): liczba int/float (nie bool), skończona, z zakresu 0-1. Inna wartość (NaN,
nieskończoność, tekst, liczba spoza zakresu) to błąd danych: ValueError, nigdy przycięcie do 1.0."""
from __future__ import annotations

import json
import math
import os
import tempfile
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path

from .normalize import EntityType, fold, normalize, normalize_url

SCHEMA_VERSION = 1
OBSERVATION_MODEL = 1
EVIDENCE_FIELDS = ("entity_kind", "website", "insecure", "display_name", "avatar_hash")
# Kontekst numeru z planu numeracyjnego (phone-check) i z ręcznej weryfikacji operatora: dwa źródła podające różne
# wartości to konflikt (pole nieznane), nie wybór. Operator z planu i operator z ręcznej weryfikacji to OSOBNE pola.
PHONE_FIELDS = ("phone_valid", "phone_possible", "phone_region", "phone_line_type", "phone_plan_region",
                "phone_carrier", "phone_carrier_manual")
OBSERVED_FIELDS = EVIDENCE_FIELDS + PHONE_FIELDS
_BOOL_FIELDS = frozenset({"insecure", "phone_valid", "phone_possible"})
_EMPTY = (None, "", [], {})


class Status(str, Enum):
    FOUND = "FOUND"          # źródło odpowiedziało i dostarczyło dane
    NOT_FOUND = "NOT_FOUND"  # źródło JAWNIE odpowiedziało, że nic nie ma (np. HTTP 404 z API)
    UNKNOWN = "UNKNOWN"      # nie sprawdzono lub nie da się rozstrzygnąć (brak klucza, adres prywatny, tryb offline)
    ERROR = "ERROR"          # błąd sieci, limit, blokada, zły format odpowiedzi. NIGDY nie oznacza braku


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def merge_value(old, new):
    """Scalanie atrybutów: listy sumowane, słowniki scalane, skalar: pierwszy niepusty wygrywa."""
    if isinstance(old, list) and isinstance(new, list):
        return old + [x for x in new if x not in old]
    if isinstance(old, dict) and isinstance(new, dict):
        merged = dict(old)
        for k, v in new.items():
            merged[k] = merge_value(merged[k], v) if k in merged else v
        return merged
    return old if old not in _EMPTY else new


def check_confidence(value) -> float:
    """Kontrakt pewności krawędzi: liczba (int/float, nie bool), skończona, 0-1; zwraca ją zaokrągloną do 0.001."""
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ValueError(f"pewność krawędzi musi być liczbą 0-1, nie {type(value).__name__}")
    x = float(value)
    if not math.isfinite(x) or not 0.0 <= x <= 1.0:
        raise ValueError(f"pewność krawędzi poza zakresem 0-1: {value!r}")
    return round(x, 3)


def parse_confidence(value) -> float | None:
    """Pewność z pliku zewnętrznego (liczba albo tekst liczby; brak = 0) wg kontraktu check_confidence.
    None oznacza wartość nieczytelną: bool, NaN, nieskończoność, liczba spoza 0-1, inny typ."""
    if isinstance(value, str):
        try:
            value = float(value) if value.strip() else 0.0
        except ValueError:
            return None
    try:
        return check_confidence(0.0 if value is None else value)
    except ValueError:
        return None


def _canon(name: str, value) -> str:
    """Klucz porównania obserwacji: te same dane zapisane inaczej nie są sprzecznością."""
    if name in _BOOL_FIELDS:
        return "true" if value else "false"
    text = str(value).strip()
    if name == "website":
        try:
            return normalize_url(text)[0]
        except ValueError:
            return text.lower()
    if name == "display_name":
        return " ".join(fold(text).split())
    if name in PHONE_FIELDS:
        return " ".join(text.split()).casefold()
    return text.lower() if name == "entity_kind" else text


def _check_observations(raw) -> dict[str, list[dict]]:
    """Walidacja klucza "observations" z pliku: {pole: [{"value": tekst|bool, "sources": [tekst]}]}."""
    if not isinstance(raw, dict):
        raise ValueError("observations: oczekiwano obiektu")
    out: dict[str, list[dict]] = {}
    for name, entries in raw.items():
        if name not in OBSERVED_FIELDS or not isinstance(entries, list) or not entries:
            raise ValueError(f"observations: nieznane pole albo pusta lista: {name!r}")
        for e in entries:
            if not isinstance(e, dict) or not isinstance(e.get("value"), bool if name in _BOOL_FIELDS else str) \
                    or e["value"] == "" \
                    or not isinstance(e.get("sources"), list) or not all(isinstance(x, str) for x in e["sources"]):
                raise ValueError(f"observations: nieprawidłowa obserwacja pola {name}")
        out[name] = [{"value": e["value"], "sources": list(e["sources"])} for e in entries]
    return out


@dataclass
class Node:
    type: EntityType
    key: str
    value: str
    attrs: dict = field(default_factory=dict)
    sources: list[str] = field(default_factory=list)
    first_seen: str = ""
    observations: dict = field(default_factory=dict)   # pole dowodowe -> [{"value", "sources"}] (po scaleniu)

    @property
    def id(self) -> str:
        return f"{self.type.value}:{self.key}"

    @classmethod
    def make(cls, etype: EntityType, raw: str, attrs: dict | None = None, source: str = "seed",
             region: str = "PL") -> "Node":
        key, display = normalize(etype, raw, region)
        return cls(etype, key, display, dict(attrs or {}), [source])

    def observed(self) -> dict[str, list[dict]]:
        """Obserwacje pól dowodowych. Węzeł nigdy nie scalany (albo z grafu sprzed modelu obserwacji): wartość
        z attrs to jedna obserwacja wszystkich źródeł węzła."""
        out = {k: [dict(e, sources=list(e["sources"])) for e in v] for k, v in self.observations.items()}
        for name in OBSERVED_FIELDS:
            value = self.attrs.get(name)
            if name == "insecure" and value not in _EMPTY:
                value = bool(value)        # ostrożnie: każda niepusta wartość inna niż False to brak weryfikacji TLS
            if value in _EMPTY:
                continue
            entries = out.setdefault(name, [])
            if not any(_canon(name, e["value"]) == _canon(name, value) for e in entries):
                entries.append({"value": value, "sources": list(self.sources)})
        return out

    def merge(self, other: "Node") -> None:
        mine, theirs = self.observed(), other.observed()
        for k, v in other.attrs.items():
            if k in OBSERVED_FIELDS:
                continue
            self.attrs[k] = merge_value(self.attrs[k], v) if k in self.attrs else v
        self.sources += [s for s in other.sources if s not in self.sources]
        for name in OBSERVED_FIELDS:
            by_key: dict[str, dict] = {}
            for e in mine.get(name, []) + theirs.get(name, []):
                slot = by_key.setdefault(_canon(name, e["value"]), {"value": e["value"], "sources": []})
                slot["value"] = min(slot["value"], e["value"], key=str)   # zapis niezależny od kolejności
                slot["sources"] += [x for x in e["sources"] if x not in slot["sources"]]
            if by_key:
                self.observations[name] = [by_key[k] for k in sorted(by_key)]
        self.apply_observations()

    def apply_observations(self) -> None:
        """attrs z obserwacji: jedna wartość = ta wartość; sprzeczne = pole nieznane (insecure: True)."""
        for name, entries in self.observations.items():
            if len(entries) == 1:
                self.attrs[name] = entries[0]["value"]
            elif name == "insecure":
                self.attrs[name] = True
            else:
                self.attrs.pop(name, None)

    def conflicts(self) -> list[str]:
        """Opisy sprzecznych obserwacji: 'pole: wartość [źródła] / wartość [źródła]' (kolejność stała)."""
        out = []
        for name in OBSERVED_FIELDS:
            entries = self.observations.get(name) or []
            if len(entries) > 1:
                out.append(f"{name}: " + " / ".join(f"{str(e['value'])[:60]} [{', '.join(sorted(e['sources']))}]"
                                                     for e in entries))
        return out

    def to_dict(self) -> dict:
        out = {"id": self.id, "type": self.type.value, "value": self.value, "attrs": self.attrs,
               "sources": self.sources, "first_seen": self.first_seen}
        if self.observations:
            out["observations"] = self.observations
        return out


@dataclass
class Edge:
    src: str                 # id węzła
    dst: str
    relation: str
    source: str              # transformacja/źródło danych
    confidence: float        # 0-1; dla ustaleń bez dowodu 0
    evidence: str
    timestamp: str = ""
    evidence_ref: list[str] = field(default_factory=list)   # refy plików w skarbcu dowodów (vault)

    def __post_init__(self) -> None:
        self.confidence = check_confidence(self.confidence)

    @property
    def key(self) -> tuple[str, str, str, str]:
        return (self.src, self.dst, self.relation, self.source)

    def to_dict(self) -> dict:
        out = {"src": self.src, "dst": self.dst, "relation": self.relation, "source": self.source,
               "confidence": self.confidence, "evidence": self.evidence, "timestamp": self.timestamp}
        if self.evidence_ref:
            out["evidence_ref"] = list(self.evidence_ref)
        return out


@dataclass
class RunRecord:
    transform: str
    node_id: str
    status: Status
    timestamp: str
    note: str = ""
    error: str = ""
    stats: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {"transform": self.transform, "node": self.node_id, "status": self.status.value,
                "timestamp": self.timestamp, "note": self.note, "error": self.error, "stats": self.stats}


class Graph:
    def __init__(self, meta: dict | None = None):
        self.meta: dict = dict(meta or {})
        self.nodes: dict[str, Node] = {}
        self.edges: dict[tuple, Edge] = {}
        self.runs: list[RunRecord] = []
        self.legacy_observations = False   # odczytany graf sprzed modelu obserwacji (patrz docstring modułu)

    # --- węzły ---
    def add_node(self, node: Node, now: str | None = None) -> Node:
        """Dodaje węzeł albo scala z istniejącym o tym samym kluczu. Zwraca węzeł kanoniczny."""
        existing = self.nodes.get(node.id)
        if existing:
            existing.merge(node)
            return existing
        node.first_seen = node.first_seen or now or utc_now()
        self.nodes[node.id] = node
        return node

    def merge_into(self, keep_id: str, drop_id: str) -> None:
        """Scala węzeł drop w keep (ta sama encja): atrybuty, źródła i krawędzie przechodzą na keep."""
        if keep_id == drop_id or drop_id not in self.nodes or keep_id not in self.nodes:
            return
        self.nodes[keep_id].merge(self.nodes.pop(drop_id))
        moved: dict[tuple, Edge] = {}
        for edge in self.edges.values():
            if edge.src == drop_id:
                edge.src = keep_id
            if edge.dst == drop_id:
                edge.dst = keep_id
            if edge.src == edge.dst:
                continue
            existing = moved.get(edge.key)
            moved[edge.key] = _merge_edges(existing, edge) if existing else edge
        self.edges = moved

    def rename(self, old_id: str, new_key: str, new_value: str) -> None:
        """Zmienia klucz węzła (po ponownej normalizacji); krawędzie są przepinane. Kolizje: merge_into."""
        node = self.nodes.pop(old_id)
        node.key, node.value = new_key, new_value
        self.nodes[node.id] = node
        renamed: dict[tuple, Edge] = {}
        for edge in self.edges.values():
            if edge.src == old_id:
                edge.src = node.id
            if edge.dst == old_id:
                edge.dst = node.id
            renamed[edge.key] = edge
        self.edges = renamed

    # --- krawędzie ---
    def add_edge(self, edge: Edge) -> Edge | None:
        if edge.src not in self.nodes or edge.dst not in self.nodes or edge.src == edge.dst:
            return None
        edge.timestamp = edge.timestamp or utc_now()
        existing = self.edges.get(edge.key)
        if existing:
            self.edges[edge.key] = _merge_edges(existing, edge)
        else:
            self.edges[edge.key] = edge
        return self.edges[edge.key]

    def edges_of(self, node_id: str) -> list[Edge]:
        return [e for e in self.edges.values() if node_id in (e.src, e.dst)]

    def nodes_of_type(self, etype: EntityType) -> list[Node]:
        return [n for n in self.nodes.values() if n.type is etype]

    # --- serializacja ---
    def to_dict(self) -> dict:
        return {
            "schema": SCHEMA_VERSION,
            "observation_model": OBSERVATION_MODEL,
            "meta": self.meta,
            "nodes": [n.to_dict() for n in self.nodes.values()],
            "edges": [e.to_dict() for e in self.edges.values()],
            "runs": [r.to_dict() for r in self.runs],
        }

    @classmethod
    def from_dict(cls, data: dict) -> "Graph":
        if not isinstance(data, dict) or data.get("schema") != SCHEMA_VERSION:
            raise ValueError("nieznany format grafu (oczekiwano schema=1)")
        model = data.get("observation_model")
        if model is not None and (type(model) is not int or model != OBSERVATION_MODEL):
            raise ValueError(f"nieznany model obserwacji: {model!r} (obsługiwany: {OBSERVATION_MODEL})")
        g = cls(data.get("meta"))
        g.legacy_observations = model is None
        try:
            for n in data.get("nodes", []):
                etype = EntityType(n["type"])
                key = n["id"].split(":", 1)[1]
                node = Node(etype, key, str(n["value"]), dict(n.get("attrs") or {}),
                            list(n.get("sources") or []), str(n.get("first_seen", "")))
                if "observations" in n:
                    if model is None:
                        raise ValueError("obserwacje węzła w pliku bez observation_model")
                    node.observations = _check_observations(n["observations"])
                    node.apply_observations()
                g.nodes[n["id"]] = node
            for e in data.get("edges", []):
                if e["src"] not in g.nodes or e["dst"] not in g.nodes:
                    raise ValueError(f"krawędź wskazuje nieistniejący węzeł: {e['src']} -> {e['dst']}")
                try:
                    edge = Edge(e["src"], e["dst"], str(e["relation"]), str(e["source"]), e["confidence"],
                                str(e.get("evidence", "")), str(e.get("timestamp", "")),
                                [str(x) for x in e.get("evidence_ref") or []])
                except ValueError as exc:
                    raise ValueError(f"krawędź {e['src']} -> {e['dst']}: {exc}") from exc
                g.edges[edge.key] = edge
            for r in data.get("runs", []):
                g.runs.append(RunRecord(r["transform"], r["node"], Status(r["status"]), str(r["timestamp"]),
                                        str(r.get("note", "")), str(r.get("error", "")), dict(r.get("stats") or {})))
        except (KeyError, TypeError, IndexError) as exc:
            raise ValueError(f"uszkodzony plik grafu: {exc!r}") from exc
        return g

    def save(self, path: str | Path) -> None:
        # allow_nan=False: NaN/Infinity to nie JSON; taki zapis ma się nie udać zamiast dać nieczytelny plik
        write_atomic(path, json.dumps(self.to_dict(), ensure_ascii=False, indent=1, allow_nan=False))

    @classmethod
    def load(cls, path: str | Path) -> "Graph":
        try:
            return cls.from_dict(json.loads(Path(path).read_text(encoding="utf-8")))
        except json.JSONDecodeError as exc:
            raise ValueError(f"plik grafu nie jest poprawnym JSON: {exc}") from exc


def _merge_edges(a: Edge, b: Edge) -> Edge:
    """Ta sama krawędź z dwóch źródeł: wyższa pewność, dowody sumowane (bez duplikatów)."""
    evidence = a.evidence
    if b.evidence and b.evidence not in evidence:
        evidence = f"{evidence} | {b.evidence}" if evidence else b.evidence
    refs = a.evidence_ref + [r for r in b.evidence_ref if r not in a.evidence_ref]
    return Edge(a.src, a.dst, a.relation, a.source, max(a.confidence, b.confidence), evidence,
                min(filter(None, (a.timestamp, b.timestamp)), default=""), refs)


def write_atomic(path: str | Path, content: str) -> None:
    """Zapis przez plik tymczasowy w tym samym katalogu + os.replace: brak ucietych plikow."""
    target = Path(path)
    fd, tmp = tempfile.mkstemp(dir=target.parent, prefix=f".{target.name}.", suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as fh:
            fh.write(content)
        os.replace(tmp, target)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise
