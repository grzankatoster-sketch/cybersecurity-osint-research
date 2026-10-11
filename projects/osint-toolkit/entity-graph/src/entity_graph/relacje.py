"""Twierdzenia o relacjach między osobami: operator ZAPISUJE informację dostarczoną z zewnątrz (dokument sprawy albo
publiczny adres), np. "A jest rodzicem B". Narzędzie relacji nie odkrywa i nie wnioskuje: nie ma reguły, która
utworzy twierdzenie ze wspólnego nazwiska, adresu, numeru, zdjęcia, znajomych ani podobieństwa profili.

Zasady:
  * typ z zamkniętej listy (rodzic, dziecko, rodzeństwo, małżonek/partner, inna z opisem), źródło z identyfikowalną
    referencją, dowód (min. 2 słowa) i cel sprawy są wymagane; nowe twierdzenie = kandydat, pewność 0
  * kierunek zachowany tam, gdzie ma znaczenie: "A dziecko B" zapisuje się jako "B rodzic A" (jedna postać kanoniczna);
    relacje symetryczne mają stałą kolejność osób, więc to samo twierdzenie nie daje dwóch przeciwnych krawędzi
  * potwierdzenie (osobne uzasadnienie) = ocena człowieka z pewnością 0.9 jak w teczce, nie dowód pokrewieństwa;
    odrzucenie = pewność 0; zmiana decyzji usuwa krawędź poprzedniego stanu (dane pochodne). Operacje są idempotentne
  * szczegóły twierdzeń w graph.meta["relation_claims"]; krawędzie Person-Person są przeliczane z nich od zera
    (sync_edges), źródło krawędzi "relacje:<id>"
  * dodanie ani potwierdzenie nie uruchamia żadnego badania drugiej osoby
"""
from __future__ import annotations

import hashlib

from .model import Edge, Graph, Node, utc_now
from .normalize import EntityType
from .teczka import CONFIRM_CONFIDENCE, validate_evidence

META_KEY = "relation_claims"
SOURCE_PREFIX = "relacje:"
PENDING, CONFIRMED, REJECTED = "oczekuje", "potwierdzone", "odrzucone"
STATUS_RELATION = {PENDING: "claim", CONFIRMED: "confirmed", REJECTED: "rejected"}
# wejście operatora -> (relacja kanoniczna, czy zamienić kolejność osób, symetryczna)
INPUT_KINDS = {
    "rodzic": ("parent_of", False, False),
    "dziecko": ("parent_of", True, False),
    "rodzenstwo": ("sibling", False, True),
    "partner": ("partner", False, True),
    "inna": ("other", False, False),
}
KIND_LABELS = {
    "parent_of": "rodzic -> dziecko",
    "sibling": "rodzeństwo",
    "partner": "małżonek lub partner",
    "other": "inna relacja",
}
INPUT_LABELS = {"rodzic": "jest rodzicem osoby", "dziecko": "jest dzieckiem osoby", "rodzenstwo": "rodzeństwo",
                "partner": "małżonek lub partner", "inna": "inna relacja (opis wymagany)"}
MAX_EVIDENCE = 500
MAX_EXCERPT = 300
MAX_OPIS = 80
MAX_SOURCES = 5
MAX_HISTORY = 20


def claims(graph: Graph) -> list[dict]:
    raw = graph.meta.get(META_KEY)
    return [c for c in raw if isinstance(c, dict) and c.get("id")] if isinstance(raw, list) else []


def find_claim(graph: Graph, claim_id: str) -> dict:
    for c in claims(graph):
        if c["id"] == claim_id:
            return c
    raise ValueError(f"w sprawie nie ma twierdzenia o relacji '{claim_id}'")


def _bounded(text: str, name: str, max_len: int) -> str:
    if len(text) > max_len:
        raise ValueError(f"{name}: najwyżej {max_len} znaków")
    return text


def describe(claim: dict) -> str:
    label = KIND_LABELS.get(claim.get("kind"), "?")
    return f"{label}: {claim.get('opis')}" if claim.get("kind") == "other" else label


def add_claim(graph: Graph, a: Node, b: Node, kind: str, source: dict, evidence: str, purpose: str,
              excerpt: str = "", opis: str = "", operator: str = "", now: str | None = None) -> tuple[dict, bool]:
    """Zapisuje twierdzenie (status: oczekuje, pewność 0). -> (twierdzenie, czy coś się zmieniło)."""
    if kind not in INPUT_KINDS:
        raise ValueError(f"nieznany typ relacji: {kind} (dozwolone: {', '.join(INPUT_KINDS)})")
    if a.type is not EntityType.PERSON or b.type is not EntityType.PERSON:
        raise ValueError("twierdzenie o relacji łączy wyłącznie dwa rekordy Person")
    if a.id == b.id:
        raise ValueError("twierdzenie o relacji wymaga dwóch różnych osób")
    if not purpose:
        raise ValueError("twierdzenie wymaga celu sprawy")
    if not isinstance(source, dict) or source.get("kind") not in ("url", "document") or not source.get("ref"):
        raise ValueError("twierdzenie wymaga źródła z identyfikowalną referencją")
    evidence = _bounded(validate_evidence(evidence), "dowód", MAX_EVIDENCE)
    excerpt = _bounded(" ".join(str(excerpt or "").split()), "fragment", MAX_EXCERPT)
    opis = _bounded(" ".join(str(opis or "").split()), "opis", MAX_OPIS)
    canon, swap, symmetric = INPUT_KINDS[kind]
    if canon == "other" and len(opis) < 3:
        raise ValueError("relacja 'inna' wymaga krótkiego opisu (min. 3 znaki)")
    if canon != "other":
        opis = ""
    src, dst = (b, a) if swap else (a, b)
    if symmetric and src.id > dst.id:
        src, dst = dst, src
    claim_id = "r-" + hashlib.sha256(f"{canon}|{src.id}|{dst.id}|{opis.casefold()}".encode("utf-8")).hexdigest()[:10]
    now = now or utc_now()
    entry = {"source": source, "evidence": evidence, "excerpt": excerpt, "added_at": now, "operator": operator}
    existing = next((c for c in claims(graph) if c["id"] == claim_id), None)
    if existing is not None:
        known = [s.get("source") for s in existing.get("sources") or []]
        if source in known:
            return existing, False                     # to samo twierdzenie z tego samego źródła: bez zmian
        if len(known) >= MAX_SOURCES:
            raise ValueError(f"twierdzenie {claim_id} ma już {MAX_SOURCES} źródeł")
        existing.setdefault("sources", []).append(entry)
        sync_edges(graph)
        return existing, True
    claim = {"id": claim_id, "kind": canon, "input_kind": kind, "opis": opis, "src": src.id, "dst": dst.id,
             "symmetric": symmetric, "purpose": purpose, "created_at": now, "operator": operator,
             "status": PENDING, "confidence": 0.0, "decision_evidence": "", "decided_at": "", "decided_by": "",
             "sources": [entry], "history": []}
    graph.meta.setdefault(META_KEY, []).append(claim)
    sync_edges(graph)
    return claim, True


def decide(graph: Graph, claim_id: str, decision: str, evidence: str, operator: str = "",
           now: str | None = None) -> tuple[dict, bool]:
    """Potwierdza albo odrzuca twierdzenie (osobne uzasadnienie). Ta sama decyzja z tym samym uzasadnieniem = bez zmian."""
    if decision not in (CONFIRMED, REJECTED):
        raise ValueError(f"nieznana decyzja: {decision}")
    claim = find_claim(graph, claim_id)
    evidence = _bounded(validate_evidence(evidence), "uzasadnienie", MAX_EVIDENCE)
    if any(evidence.casefold() == str(s.get("evidence", "")).casefold() for s in claim.get("sources") or []):
        raise ValueError("uzasadnienie decyzji musi być osobne: nie powtarzaj dowodu z twierdzenia, "
                         "napisz, co sprawdziłeś")
    if claim.get("status") == decision and claim.get("decision_evidence") == evidence:
        return claim, False
    now = now or utc_now()
    claim["history"] = (claim.get("history") or [])[-(MAX_HISTORY - 1):] + [
        {"status": decision, "evidence": evidence, "at": now, "operator": operator}]
    claim.update(status=decision, confidence=CONFIRM_CONFIDENCE if decision == CONFIRMED else 0.0,
                 decision_evidence=evidence, decided_at=now, decided_by=operator)
    sync_edges(graph)
    return claim, True


def _edge_evidence(claim: dict, graph: Graph) -> str:
    a, b = graph.nodes.get(claim["src"]), graph.nodes.get(claim["dst"])
    names = f"{a.value if a else claim['src']} / {b.value if b else claim['dst']}"
    refs = "; ".join(f"źródło {s['source'].get('kind')}: {s['source'].get('ref')}"
                     for s in claim.get("sources") or [] if isinstance(s.get("source"), dict))
    head = {PENDING: "TWIERDZENIE OPERATORA, wymaga potwierdzenia",
            CONFIRMED: f"POTWIERDZONE przez operatora: {claim.get('decision_evidence')}",
            REJECTED: f"ODRZUCONE przez operatora: {claim.get('decision_evidence')}"}[claim.get("status", PENDING)]
    return (f"[{claim['id']}] {describe(claim)} ({names}). {head}. {refs}. "
            "Ocena człowieka na podstawie dostarczonego źródła, nie dowód pokrewieństwa ani tożsamości")


def sync_edges(graph: Graph) -> list[Edge]:
    """Krawędzie twierdzeń przeliczane od zera z graph.meta (idempotentne): stan poprzedni znika (dane pochodne)."""
    for key in [k for k, e in graph.edges.items() if e.source.startswith(SOURCE_PREFIX)]:
        del graph.edges[key]
    out = []
    for c in claims(graph):
        if c.get("src") not in graph.nodes or c.get("dst") not in graph.nodes:
            continue
        status = c.get("status") if c.get("status") in STATUS_RELATION else PENDING
        conf = CONFIRM_CONFIDENCE if status == CONFIRMED else 0.0
        edge = graph.add_edge(Edge(c["src"], c["dst"], f"{STATUS_RELATION[status]}_{c.get('kind')}",
                                   SOURCE_PREFIX + c["id"], conf, _edge_evidence(c, graph),
                                   c.get("decided_at") or c.get("created_at") or ""))
        if edge:
            out.append(edge)
    return out


def contradictions(graph: Graph) -> list[str]:
    """Pary osób z kilkoma nieodrzuconymi twierdzeniami różnego rodzaju lub kierunku: do wyjaśnienia przez operatora."""
    by_pair: dict[tuple, list[dict]] = {}
    for c in claims(graph):
        if c.get("status") != REJECTED:
            by_pair.setdefault(tuple(sorted((c["src"], c["dst"]))), []).append(c)
    out = []
    for pair, items in sorted(by_pair.items()):
        shapes = {(c["kind"], c["src"] if not c.get("symmetric") else "", c.get("opis", "")) for c in items}
        if len(shapes) > 1:
            names = " / ".join(graph.nodes[x].value if x in graph.nodes else x for x in pair)
            out.append(f"{names}: " + "; ".join(f"{c['id']} {describe(c)} ({c['status']})" for c in items))
    return out


def add_person(graph: Graph, name: str, now: str | None = None) -> tuple[Node, bool]:
    """Osoba dopisana jawnie przez operatora (np. druga strona twierdzenia), której nie było w grafie."""
    node = Node.make(EntityType.PERSON, name, source="operator")
    if node.id in graph.nodes:
        return graph.nodes[node.id], False
    return graph.add_node(node, now), True
