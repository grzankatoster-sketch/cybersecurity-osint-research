"""Kandydaci publicznych profili dla rekordu Person albo Username w sprawie: JEDNA jawnie uruchomiona runda.

Punkt wejścia: osoba (jej kandydaci nazw użytkownika z person_candidates) albo nazwa użytkownika obecna w sprawie.
Każda nazwa to jedno wywołanie username_scan (username-engine) w budżecie z expand.Scope: zapytania, czas, koszt.
Trafienia FOUND to kandydaci do ręcznego przeglądu (krawędź candidate_match z pewnością 0); NOT_FOUND / UNKNOWN /
ERROR zostają ze swoim znaczeniem w graph.runs i w raporcie rundy, nigdy jako ocena osoby.

Ocena (evidence.assess, ta sama co w `eg rozszerz`) opisuje wyłącznie techniczne dopasowanie profilu do danych
początkowych: sama nazwa użytkownika, imię i nazwisko, awatar albo serwis to co najwyżej "do przeglądu". Profil
łączy z osobą tylko człowiek (`eg potwierdz`), a potwierdzenie niczego nie skanuje. Kolejne nazwy z mocno
uzasadnionych kandydatów trafiają do raportu jako propozycje: następna runda to osobne, jawne polecenie z limitem.
Dla serwisów bez automatycznego sprawdzania powstają wyłącznie linki do ręcznego otwarcia.
"""
from __future__ import annotations

import time
from dataclasses import asdict
from typing import Callable
from urllib.parse import quote, quote_plus

from . import teczka
from .correlate import correlate, is_profile, record_from_node
from .evidence import Decision, Record, assess
from .expand import Scope, _Budget, _query, followup_identifiers
from .guardrails import AuditLog
from .model import Edge, Graph, Node, utc_now
from .normalize import EntityType
from .transforms import REGISTRY, Context, Transform
from .transforms.person import ENGINES, generate_usernames

META_KEY = "profile_rounds"
RELATION = "candidate_match"
SOURCE = "kandydaci"
ADAPTER = "username_scan"
MAX_NAMES = 12
MAX_QUERIES = 10
MAX_COST = 50.0
MAX_SECONDS = 1800.0
MAX_ROUNDS = 10
KEEP_ROUNDS = 20
DECISION_PL = {"rozwin": "mocne dopasowanie techniczne: propozycja kolejnej rundy",
               "przeglad": "wymaga przeglądu przez operatora", "zatrzymaj": "brak dowodu dopasowania"}
# serwisy, których username-engine nie sprawdza automatycznie (wymagałyby logowania lub podszywania się)
MANUAL_PROFILES = (
    ("Facebook", "https://www.facebook.com/{}"),
    ("Instagram", "https://www.instagram.com/{}/"),
    ("Threads", "https://www.threads.net/@{}"),
    ("LinkedIn", "https://www.linkedin.com/in/{}"),
)


def manual_links(username: str) -> list[dict]:
    """Linki do RĘCZNEGO otwarcia przez operatora (nic nie jest pobierane)."""
    links = [{"engine": site, "label": "profil do ręcznego sprawdzenia", "query": username,
              "url": tpl.format(quote(username, safe=""))} for site, tpl in MANUAL_PROFILES]
    q = f'"{username}"'
    links += [{"engine": e, "label": "fraza dokładna", "query": q, "url": base + quote_plus(q)} for e, base in ENGINES.items()]
    return links


def rounds(graph: Graph) -> list[dict]:
    raw = graph.meta.get(META_KEY)
    return [r for r in raw if isinstance(r, dict)] if isinstance(raw, list) else []


def pending_proposals(graph: Graph) -> list[str]:
    seen = []
    for r in rounds(graph):
        for p in r.get("proposals") or []:
            if isinstance(p, dict) and p.get("identifier") and p["identifier"] not in seen:
                seen.append(p["identifier"])
    return seen


def check_scope(scope: Scope, names: int) -> None:
    """Twarde limity backendu (niezależnie od formularza)."""
    if scope.auto_continue or scope.max_rounds != 1:
        raise ValueError("w sprawie runda kandydatów jest zawsze jedna; kolejna to osobne, jawne polecenie")
    if not 1 <= names <= MAX_NAMES:
        raise ValueError(f"liczba nazw w rundzie: 1-{MAX_NAMES}")
    if type(scope.max_queries) is not int or not 1 <= scope.max_queries <= MAX_QUERIES:
        raise ValueError(f"limit zapytań: 1-{MAX_QUERIES}")
    if type(scope.max_cost) not in (int, float) or not 0 < scope.max_cost <= MAX_COST:
        raise ValueError(f"limit kosztu: do {MAX_COST:g} jednostek")
    if type(scope.max_seconds) not in (int, float) or not 0 < scope.max_seconds <= MAX_SECONDS:
        raise ValueError(f"limit czasu: do {MAX_SECONDS:g} s")


def plan_names(graph: Graph, entry: Node, names: list[str] | None, max_names: int) -> list[Node]:
    """Nazwy do sprawdzenia. Osoba: jej kandydaci nazw (brak = wygenerowanie ze wzorców, pewność 0). Nazwa
    użytkownika: ona sama. Jawnie podane nazwy muszą należeć do osoby albo pochodzić z propozycji wcześniejszej rundy."""
    if entry.type is EntityType.USERNAME:
        return [entry]
    if entry.type is not EntityType.PERSON:
        raise ValueError("punkt wejścia: osoba albo nazwa użytkownika")
    own = [graph.nodes[e.dst] for e in graph.edges.values()
           if e.src == entry.id and e.relation == "candidate_username" and e.dst in graph.nodes]
    if not own:
        for user, label in generate_usernames(entry.value, MAX_NAMES):
            u = graph.add_node(Node.make(EntityType.USERNAME, user, {"candidate": True}, "person_candidates"))
            graph.add_edge(Edge(entry.id, u.id, "candidate_username", "person_candidates", 0.0,
                                f"wygenerowano ze wzorca: {label}. HIPOTEZA bez dowodu, wymaga weryfikacji"))
            own.append(u)
    if names:
        wanted = [Node.make(EntityType.USERNAME, n).id for n in names]
        allowed = {u.id for u in own}
        bad = [n for n, i in zip(names, wanted) if i not in allowed]
        if bad:
            raise ValueError("nazwy spoza kandydatów tej osoby: " + ", ".join(bad))
        own = [graph.nodes[i] for i in dict.fromkeys(wanted)]
    return own[:max_names]


def resolve_entry(graph: Graph, person: str = "", username: str = "") -> Node:
    if bool(person) == bool(username):
        raise ValueError("podaj dokładnie jedno: osobę albo nazwę użytkownika")
    if person:
        return teczka.find_person(graph, person)
    node_id = Node.make(EntityType.USERNAME, username).id
    if node_id in graph.nodes:
        return graph.nodes[node_id]
    if username in pending_proposals(graph):
        return graph.add_node(Node.make(EntityType.USERNAME, username, source=SOURCE))
    raise ValueError(f"nazwy '{username}' nie ma w sprawie ani w propozycjach wcześniejszych rund")


def _anchors(graph: Graph, entry: Node) -> list[Record]:
    """Dane początkowe: osoba = imię i nazwisko (sygnał tylko kopiowalny) + typ 'person' + profile już potwierdzone."""
    if entry.type is not EntityType.PERSON:
        return [Record(url="", site="dane początkowe", provenance="operator", anchor=True)]
    out = [Record(url="", site="dane początkowe", display_name=entry.value, entity_kind="person",
                  provenance="operator", anchor=True)]
    for node, _ in teczka.dossier(graph, entry)["confirmed"]:
        out.append(record_from_node(graph, node, anchor=True))
    return out


def run_round(graph: Graph, entry: Node, names: list[Node], ctx: Context, audit: AuditLog, scope: Scope,
              registry: dict[str, Transform] | None = None, clock: Callable[[], float] = time.monotonic,
              should_stop: Callable[[], bool] = lambda: False, now: str | None = None,
              max_rounds: int = 3) -> dict:
    """Jedna runda: username_scan dla każdej nazwy (w budżecie), ocena trafień, propozycje bez wykonania."""
    registry = registry if registry is not None else REGISTRY
    check_scope(scope, len(names))
    scope.validate(registry, EntityType.USERNAME)
    if not 1 <= max_rounds <= MAX_ROUNDS:
        raise ValueError(f"limit rund sprawy: 1-{MAX_ROUNDS}")
    done = rounds(graph)
    number = max((int(r.get("round", 0)) for r in done), default=0) + 1
    if number > max_rounds:
        raise ValueError(f"osiągnięto limit rund sprawy ({max_rounds}); zwiększ go jawnie, jeśli cel na to pozwala")
    t = registry[ADAPTER]
    budget = _Budget(scope, clock, should_stop, started=clock())
    now = now or utc_now()
    report = {"round": number, "started": now, "entry": {"type": entry.type.value, "value": entry.value},
              "scope": asdict(scope), "queries": [], "candidates": [], "proposals": [], "skipped": [],
              "stop_reason": ""}
    found: list[str] = []
    for i, node in enumerate(names):
        node.attrs["manual_review_links"] = manual_links(node.value)
        if not budget.allow(t.name):
            report["skipped"] += [{"identifier": n.value, "why": budget.stop_reason} for n in names[i:]]
            break
        budget.spend(t.name)
        entry_row, profiles = _query(graph, t, node, ctx, audit, scope, number, f"{entry.type.value}: {entry.value}")
        report["queries"].append(entry_row)
        found += [p.id for p in profiles if p.id not in found]
    anchors = _anchors(graph, entry)
    for pid in found:
        cand = graph.nodes.get(pid)
        if cand is None or not is_profile(cand):
            continue
        a = assess(anchors, record_from_node(graph, cand))
        row = {"profile": cand.value, "site": cand.attrs.get("site", ""), **a.to_dict()}
        report["candidates"].append(row)
        graph.add_edge(Edge(entry.id, cand.id, RELATION, SOURCE, 0.0,
                            f"runda {number}: {DECISION_PL.get(a.decision.value, a.decision.value)}, dowody "
                            f"{a.level.label}: " + "; ".join(a.reasons)
                            + ". Kandydat profilu to hipoteza; łączy go z osobą tylko decyzja operatora", now))
        audit.write("profile_candidate", round=number, profile=cand.id, decision=a.decision.value,
                    level=a.level.label)
        if a.decision is Decision.EXPAND:
            fresh = [h for h in followup_identifiers(cand) if Node.make(EntityType.USERNAME, h).id not in graph.nodes]
            for handle in fresh[:scope.max_followups]:   # nazwy już obecne w sprawie operator uruchamia sam
                report["proposals"].append({"identifier": handle, "from": cand.value})
    report["stop_reason"] = budget.stop_reason or "runda zakończona; kolejna wymaga osobnego polecenia"
    report["totals"] = {"queries": budget.queries, "cost": budget.cost, "seconds": round(clock() - budget.started, 1),
                        "statuses": {s: sum(1 for q in report["queries"] if q["status"] == s)
                                     for s in ("FOUND", "NOT_FOUND", "UNKNOWN", "ERROR")}}
    graph.meta[META_KEY] = (done + [report])[-KEEP_ROUNDS:]
    correlate(graph, now)
    return report
