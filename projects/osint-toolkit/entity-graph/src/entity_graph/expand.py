"""Rozszerzanie rekordów sterowane dowodami: zebranie kandydatów -> porównanie -> uzasadniona decyzja -> kolejna
ograniczona runda -> raport.

Wejście: identyfikator tekstowy (domyślnie nazwa użytkownika) i opcjonalne atrybuty startowe (profile wskazane przez
operatora, strona www, e-mail, nazwa wyświetlana, typ encji). Atrybuty startowe i wskazane profile to KOTWICA.

Zasady (ocena w evidence.py):
  * Każdy kandydat w każdej rundzie jest porównywany z kotwicą, nie z poprzednikiem. A-B i B-C nie potwierdza A-C:
    dowód przez pośrednika trafia do raportu jako łańcuch i co najwyżej kieruje do przeglądu.
  * Dalsze zapytania wykonuje się tylko z kandydatów z decyzją "rozwin" (mocny dowód kontroli po stronie kotwicy,
    brak sprzeczności, wiarygodne źródło), tylko przez skonfigurowane adaptery (transformacje z rejestru) i tylko
    przy włączonej automatycznej kontynuacji. Bez niej runda 1 kończy się listą propozycji.
  * Kandydat zawsze pozostaje hipotezą (krawędź candidate_match z pewnością 0); potwierdza człowiek (eg potwierdz).
  * Limity: rundy, zapytania, czas, koszt, kandydaci na rundę, propozycje na kandydata. Deduplikacja identyfikatorów
    i kandydatów (cykle). Zatrzymanie: should_stop() przed każdym zapytaniem albo Ctrl+C.
  * Ocena jest powiązana z obserwacjami, z których pochodzi (skrót "basis": kandydat i kotwice). Deduplikacja pomija
    tylko kandydata bez nowych obserwacji; nowe obserwacje (np. sprzeczny typ encji z innego zapytania) wymuszają
    ponowną ocenę, także w kolejnej rundzie. Przed każdym zaplanowanym zapytaniem sprawdza się kandydata, z którego
    ono wynika: jeśli po nowych obserwacjach nie ma już decyzji "rozwin", zapytanie jest wstrzymane (report["held"]).
    Wcześniejsza ocena zostaje w raporcie swojej rundy i w polu "previous" nowej.
  * ERROR / UNKNOWN adaptera to "nie rozstrzygnięto", nigdy "rekordu nie ma".
"""
from __future__ import annotations

import hashlib
import math
import time
from dataclasses import asdict, dataclass, field
from typing import Callable

from .correlate import correlate, is_profile, record_from_node
from .engine import apply_result, run_transform
from .evidence import Decision, Record, assess, handle_from_url, url_key
from .guardrails import AuditLog
from .model import Edge, Graph, Node, RunRecord, Status
from .normalize import EntityType
from .transforms import REGISTRY, Context, Transform

RELATION = "candidate_match"
SOURCE = "expand"
ADAPTER_COST = {"username_scan": 5.0}   # jednostki umowne; pozostałe adaptery: 1.0
DEFAULT_COST = 1.0
UNRESOLVED = "nie rozstrzygnięto: błąd lub brak dostępu do źródła nie oznacza braku rekordu"
HELD = ("wstrzymane: kandydat, z którego wynika to zapytanie, po nowych obserwacjach nie ma już decyzji \"rozwin\" "
        "(ponowna ocena w raporcie)")


@dataclass
class Scope:
    adapters: tuple[str, ...] = ("username_scan",)
    auto_continue: bool = False
    max_rounds: int = 2
    max_queries: int = 10
    max_seconds: float = 1800.0
    max_cost: float = 50.0
    max_candidates: int = 50       # ocenianych kandydatów na rundę
    max_followups: int = 5         # nowych identyfikatorów z jednego rozwiniętego kandydata
    offline: bool = False

    def validate(self, registry: dict[str, Transform], seed_type: EntityType | None = None) -> None:
        unknown = [a for a in self.adapters if a not in registry]
        if unknown:
            raise ValueError("nieznane adaptery: " + ", ".join(unknown))
        if not self.adapters:
            raise ValueError("podaj co najmniej jeden adapter")
        if seed_type is not None and not any(seed_type in registry[a].inputs for a in self.adapters):
            raise ValueError("wybrane adaptery nie obsługują typu identyfikatora: " + seed_type.value)
        if len(set(self.adapters)) != len(self.adapters):
            raise ValueError("adaptery nie mogą się powtarzać")
        if any(type(v) is not int for v in (self.max_rounds, self.max_queries, self.max_candidates, self.max_followups)):
            raise ValueError("liczby rund, wywołań i kandydatów muszą być całkowite")
        if any(type(v) not in (int, float) or not math.isfinite(v) for v in (self.max_seconds, self.max_cost)):
            raise ValueError("limity czasu i kosztu muszą być skończonymi liczbami")
        if min(self.max_rounds, self.max_queries, self.max_candidates) < 1 or self.max_followups < 0 \
                or self.max_seconds <= 0 or self.max_cost <= 0:
            raise ValueError("limity muszą być dodatnie")


@dataclass
class Seed:
    identifier: str
    id_type: EntityType = EntityType.USERNAME
    profiles: tuple[str, ...] = ()       # adresy profili, o których operator wie, że należą do podmiotu
    website: str = ""
    emails: tuple[str, ...] = ()
    display_name: str = ""
    entity_kind: str = ""                # person | organization | ""

    def record(self) -> Record:
        return Record(url="", site="dane początkowe", display_name=self.display_name, website=self.website,
                      aliases=tuple(self.profiles), emails=tuple(e.strip().lower() for e in self.emails),
                      entity_kind=self.entity_kind, provenance="operator", anchor=True)

    def to_report(self) -> dict:
        return {"identifier": self.identifier, "type": self.id_type.value, "profiles": list(self.profiles),
                "website": self.website, "emails": list(self.emails), "display_name": self.display_name,
                "entity_kind": self.entity_kind}


@dataclass
class _Budget:
    scope: Scope
    clock: Callable[[], float]
    should_stop: Callable[[], bool]
    started: float = 0.0
    queries: int = 0
    cost: float = 0.0
    stop_reason: str = ""

    def allow(self, adapter: str) -> bool:
        if self.stop_reason:
            return False
        s, price = self.scope, ADAPTER_COST.get(adapter, DEFAULT_COST)
        if self.should_stop():
            self.stop_reason = "zatrzymane na żądanie użytkownika"
        elif self.queries >= s.max_queries:
            self.stop_reason = f"limit zapytań ({s.max_queries})"
        elif self.clock() - self.started >= s.max_seconds:
            self.stop_reason = f"limit czasu ({s.max_seconds:g} s)"
        elif self.cost + price > s.max_cost:
            self.stop_reason = f"limit kosztu ({s.max_cost:g} jednostek; zapytanie {adapter} kosztuje {price:g})"
        return not self.stop_reason

    def spend(self, adapter: str) -> None:
        self.queries += 1
        self.cost += ADAPTER_COST.get(adapter, DEFAULT_COST)


def followup_identifiers(node: Node, id_type: EntityType = EntityType.USERNAME) -> list[str]:
    """Nowe identyfikatory z rozwiniętego kandydata: nazwy kont z linków jego profilu (bez strony www: to domena)."""
    if id_type is not EntityType.USERNAME:
        return []
    out = []
    for raw in node.attrs.get("links") or []:
        handle = handle_from_url(str(raw))
        if handle and handle not in out:
            out.append(handle)
    return out


def _query(graph: Graph, t: Transform, node: Node, ctx: Context, audit: AuditLog, scope: Scope,
           rnd: int, origin: str) -> tuple[dict, list[Node]]:
    result = run_transform(t, node, ctx, scope.offline)
    old_id = node.id
    # A failed/unknown response may carry partial data; it must not become an anchor or authorize another round.
    pivots = []
    if result.status is Status.FOUND:
        node, pivots = apply_result(graph, node, result)
    graph.runs.append(RunRecord(t.name, old_id, result.status, ctx.now(), result.note, result.error, result.stats))
    audit.write("transform", transform=t.name, node=old_id, status=result.status.value, error=result.error,
                note=result.note, nodes_added=len(result.nodes), edges_added=len(result.edges), round=rnd)
    entry = {"identifier": node.value, "adapter": t.name, "status": result.status.value, "origin": origin,
             "note": result.error or result.note}
    if result.status in (Status.ERROR, Status.UNKNOWN):
        entry["interpretation"] = UNRESOLVED
    profiles = [target for _, target in pivots if is_profile(target)]
    return entry, profiles


def _basis(anchors: list[Record], record: Record) -> str:
    """Skrót obserwacji, z których pochodzi ocena (kandydat i kotwice). Inna wartość = nowe obserwacje = ponowna ocena."""
    return hashlib.sha256(repr((tuple(anchors), record)).encode("utf-8")).hexdigest()[:16]


def expand(graph: Graph, seed: Seed, ctx: Context, audit: AuditLog, scope: Scope,
           registry: dict[str, Transform] | None = None, clock: Callable[[], float] = time.monotonic,
           should_stop: Callable[[], bool] = lambda: False,
           progress: Callable[[str], None] | None = None) -> dict:
    """Prowadzi rundy i zwraca raport (zapisany też w graph.meta["expansion"])."""
    registry = registry if registry is not None else REGISTRY
    scope.validate(registry, seed.id_type)
    adapters = [registry[a] for a in scope.adapters]
    budget = _Budget(scope, clock, should_stop, started=clock())
    seed_node = graph.add_node(Node.make(seed.id_type, seed.identifier, source="seed"))
    anchor_keys = {k for k in (url_key(p) for p in seed.profiles) if k}
    seed_record = seed.record()
    report: dict = {"seed": seed.to_report(), "scope": asdict(scope), "rounds": [], "pending": [], "held": [],
                    "stop_reason": "", "anchors_found": [], "anchors_missing": []}
    queried: set[str] = set()                    # id węzłów-identyfikatorów już odpytanych
    assessed: dict[str, dict] = {}               # id profilu -> ostatnia ocena (z podstawą "basis")
    expanded: list[str] = []                     # id profili z aktualną decyzją "rozwin"
    held: set[str] = set()                       # id profili, którym ponowna ocena odebrała "rozwin"
    # (identyfikator, opis pochodzenia, id kandydata, z którego wynika zapytanie: None dla danych początkowych)
    frontier: list[tuple[str, str, str | None]] = [(seed_node.id, "dane początkowe", None)]
    say = progress or (lambda _m: None)

    def pending(items) -> list[dict]:
        out = []
        for n, o, origin_pid in items:
            if n in graph.nodes:
                row = {"identifier": graph.nodes[n].value, "origin": o}
                if origin_pid in held:
                    row["held"] = HELD
                out.append(row)
        return out

    def current_anchors() -> list[Record]:
        anchors = [seed_record]
        for key in sorted(anchor_keys):
            anchor_node = graph.nodes.get(f"{EntityType.URL.value}:{key}")
            if anchor_node is not None:
                anchors.append(record_from_node(graph, anchor_node, anchor=True))
                if key not in report["anchors_found"]:
                    report["anchors_found"].append(key)
        return anchors

    def intermediates_for(pid: str) -> list[Record]:
        return [record_from_node(graph, graph.nodes[p]) for p in expanded if p in graph.nodes and p != pid]

    def evaluate(pid: str, rnd: int, rd: dict, anchors: list[Record], intermediates: list[Record]) -> dict:
        """Ocena kandydata powiązana z obserwacjami (basis). Wcześniejsza ocena zostaje w raporcie swojej rundy."""
        cand = graph.nodes[pid]
        record = record_from_node(graph, cand)
        a = assess(anchors, record, intermediates)
        row = {"profile": cand.value, "site": cand.attrs.get("site", ""), **a.to_dict(), "round": rnd,
               "basis": _basis(anchors, record), "sources": list(cand.sources)}
        prev = assessed.get(pid)
        note = ""
        if prev is not None:
            row["reassessed"] = True
            row["previous"] = {k: prev[k] for k in ("round", "decision", "level", "basis")}
            note = f" (ponowna ocena po nowych obserwacjach; wcześniej: {prev['decision']} w rundzie {prev['round']})"
        assessed[pid] = row
        rd["candidates"].append(row)
        graph.add_edge(Edge(seed_node.id, cand.id, RELATION, SOURCE, 0.0,
                            f"runda {rnd}: decyzja {a.decision.value}{note}, dowody {a.level.label}: "
                            + "; ".join(a.reasons) + ". Kandydat to hipoteza, nie potwierdzenie", ctx.now()))
        audit.write("expansion_decision", round=rnd, profile=cand.id, decision=a.decision.value,
                    level=a.level.label, reasons=a.reasons, basis=row["basis"], reassessed=prev is not None)
        if a.decision is Decision.EXPAND:
            held.discard(pid)
            if pid not in expanded:
                expanded.append(pid)
        elif pid in expanded:
            expanded.remove(pid)
            held.add(pid)
        return row

    def origin_allows(origin_pid: str | None, rnd: int, rd: dict) -> bool:
        """Zapytanie zaplanowane z kandydata wolno wykonać tylko, jeśli jego ocena nadal brzmi "rozwin" dla
        obecnych obserwacji. Nowe obserwacje od czasu planowania = ponowna ocena teraz, przed zapytaniem."""
        if origin_pid is None:
            return True
        row, cand = assessed.get(origin_pid), graph.nodes.get(origin_pid)
        if row is None or cand is None:
            return False
        anchors = current_anchors()
        if _basis(anchors, record_from_node(graph, cand)) != row["basis"]:
            row = evaluate(origin_pid, rnd, rd, anchors, intermediates_for(origin_pid))
        return row["decision"] == Decision.EXPAND.value

    try:
        for rnd in range(1, scope.max_rounds + 1):
            if not frontier:
                report["stop_reason"] = "brak nowych identyfikatorów do zbadania"
                break
            if rnd > 1 and not scope.auto_continue:
                report["pending"] = pending(frontier)
                report["stop_reason"] = "automatyczna kontynuacja wyłączona: propozycje czekają na decyzję operatora"
                break
            rd: dict = {"round": rnd, "queries": [], "candidates": [], "followups": [], "skipped": []}
            report["rounds"].append(rd)
            found: list[str] = []
            for i, (node_id, origin, origin_pid) in enumerate(frontier):
                node = graph.nodes.get(node_id)
                if node is None:
                    continue
                if not origin_allows(origin_pid, rnd, rd):
                    entry = {"identifier": node.value, "origin": origin, "why": HELD}
                    rd["skipped"].append(entry)
                    report["held"].append({**entry, "round": rnd})
                    continue
                queried.add(node_id)
                for t in adapters:
                    if node.type not in t.inputs:
                        continue
                    if not budget.allow(t.name):
                        rd["skipped"].append({"identifier": node.value, "adapter": t.name, "why": budget.stop_reason})
                        report["pending"] += pending(frontier[i:])
                        break
                    budget.spend(t.name)
                    entry, profiles = _query(graph, t, node, ctx, audit, scope, rnd, origin)
                    rd["queries"].append(entry)
                    found += [p.id for p in profiles]
                    say(f"runda {rnd}: {entry['status']:<9} {t.name} {node.value}")
                if budget.stop_reason:
                    break

            anchors = current_anchors()
            intermediates = [record_from_node(graph, graph.nodes[p]) for p in expanded if p in graph.nodes]
            next_frontier: list[tuple[str, str, str | None]] = []
            evaluated = 0
            found_now = set(found)
            # Także kandydaci ocenieni wcześniej, a nieznalezieni teraz: nowa obserwacja mogła dojść innym zapytaniem.
            for pid in dict.fromkeys(found + list(assessed)):
                cand = graph.nodes.get(pid)
                if cand is None:
                    continue
                if cand.key in anchor_keys:
                    if pid in found_now:
                        rd["candidates"].append({"profile": cand.value, "role": "kotwica",
                                                 "reasons": ["profil wskazany przez operatora w danych początkowych"]})
                    continue
                prev = assessed.get(pid)
                if prev is not None:
                    if _basis(anchors, record_from_node(graph, cand)) == prev["basis"]:
                        if pid in found_now:
                            rd["skipped"].append({"profile": cand.value,
                                                  "why": "już oceniony wcześniej (duplikat lub cykl), bez nowych obserwacji"})
                        continue
                    # nowe obserwacje: ponowna ocena zawsze, poza limitem kandydatów (sprzeczności się nie pomija)
                elif evaluated >= scope.max_candidates:
                    rd["skipped"].append({"profile": cand.value, "why": f"limit kandydatów na rundę ({scope.max_candidates})"})
                    continue
                else:
                    evaluated += 1
                row = evaluate(pid, rnd, rd, anchors, [r for r in intermediates if r.url != cand.key])
                if row["decision"] != Decision.EXPAND.value:
                    continue
                for handle in followup_identifiers(cand, seed.id_type)[:scope.max_followups]:
                    try:
                        nxt = graph.add_node(Node.make(seed.id_type, handle, source=SOURCE))
                    except ValueError:
                        continue
                    if nxt.id in queried or any(nxt.id == n for n, _, _ in next_frontier):
                        if prev is None:
                            rd["followups"].append({"identifier": nxt.value, "from": cand.value,
                                                    "status": "pominięty: już zbadany lub zaplanowany (cykl)"})
                        continue
                    next_frontier.append((nxt.id, cand.value, pid))
                    rd["followups"].append({"identifier": nxt.value, "from": cand.value, "status": "zaplanowany"})
            if budget.stop_reason:
                report["stop_reason"] = budget.stop_reason
                report["pending"] += pending(next_frontier)
                break
            frontier = next_frontier
        else:
            if frontier:
                report["stop_reason"] = f"limit rund ({scope.max_rounds})"
                report["pending"] = pending(frontier)
            else:
                report["stop_reason"] = "brak nowych identyfikatorów do zbadania"
    except KeyboardInterrupt:
        report["stop_reason"] = "przerwane przez użytkownika (Ctrl+C)"

    report["anchors_missing"] = sorted(anchor_keys - set(report["anchors_found"]))
    report["totals"] = {
        "queries": budget.queries, "cost": budget.cost, "seconds": round(clock() - budget.started, 1),
        "decisions": {d.value: sum(1 for r in assessed.values() if r["decision"] == d.value) for d in Decision},
        "unresolved_queries": sum(1 for r in report["rounds"] for q in r["queries"] if "interpretation" in q),
        "reassessed": sum(1 for r in report["rounds"] for c in r["candidates"] if c.get("reassessed")),
        "held": len(report["held"]),
    }
    graph.meta["expansion"] = report
    links = correlate(graph)
    audit.write("end", nodes=len(graph.nodes), edges=len(graph.edges), runs=budget.queries,
                same_person_links=len(links), stop_reason=report["stop_reason"], decisions=report["totals"]["decisions"])
    return report
