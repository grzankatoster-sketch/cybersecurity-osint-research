"""Teczka osoby: operator potwierdza lub odrzuca znalezione profile, a dane z potwierdzonych łączą się z osobą.

Tak pracuje analityk w Maltego: narzędzie podsuwa kandydatów (profile znalezione z nazw użytkownika
wygenerowanych z imienia i nazwiska albo powiązane z już potwierdzonym profilem), a DECYZJĘ "to ta osoba"
podejmuje człowiek, z dowodem zapisanym w dzienniku audytu. Nic nie jest wysyłane do sieci.

Zasady:
  * potwierdzenie = krawędź Person -> profil `confirmed_profile` (źródło `operator`, pewność 0.9: ocena
    człowieka, nie dowód tożsamości); odrzucenie = `rejected_profile` (pewność 0); każde z dowodem
  * dane z potwierdzonego profilu (nazwa użytkownika, e-mail, domena, inne węzły niebędące profilami) łączą się
    z osobą krawędzią `via_confirmed_profile` (źródło `teczka`), pewność = min(0.9, pewność krawędzi profilu)
  * własna strona www profilu (0.6) i linki do domen spoza platform (0.5) stają się węzłami Domain osoby
  * inne PROFILE powiązane z potwierdzonym (same_person) nigdy nie są dołączane same: wracają jako kandydaci
  * odrzucony profil nie przekazuje niczego; przeliczenie (`propagate`) jest idempotentne
"""
from __future__ import annotations

from dataclasses import dataclass, field

from .correlate import _host, _is_platform, account_confidence, is_profile
from .model import Edge, Graph, Node, utc_now
from .normalize import EntityType

CONFIRMED = "confirmed_profile"
REJECTED = "rejected_profile"
DERIVED = "via_confirmed_profile"
OPERATOR = "operator"
SOURCE = "teczka"
CONFIRM_CONFIDENCE = 0.9
WEBSITE_CONFIDENCE = 0.6
LINK_CONFIDENCE = 0.5
REVIEW_RELATIONS = (CONFIRMED, REJECTED)


@dataclass
class Candidate:
    node: Node
    confidence: float | None
    reasons: list[str] = field(default_factory=list)
    decision: str = ""          # "", CONFIRMED albo REJECTED


def validate_evidence(text: str | None) -> str:
    text = " ".join((text or "").split())
    if len(text) < 10 or len(text.split()) < 2:
        raise ValueError("dowód jest wymagany: napisz, dlaczego to ta osoba (min. 2 słowa, 10 znaków)")
    return text


def find_person(graph: Graph, name: str) -> Node:
    node_id = Node.make(EntityType.PERSON, name).id
    if node_id not in graph.nodes:
        people = ", ".join(n.value for n in graph.nodes_of_type(EntityType.PERSON)) or "brak"
        raise ValueError(f"w grafie nie ma osoby '{name}' (osoby w grafie: {people})")
    return graph.nodes[node_id]


def decision_of(graph: Graph, person: Node, profile: Node) -> str:
    for rel in REVIEW_RELATIONS:
        if (person.id, profile.id, rel, OPERATOR) in graph.edges:
            return rel
    return ""


def candidates(graph: Graph, person: Node) -> list[Candidate]:
    """Profile do przeglądu dla osoby: znalezione z jej kandydatów nazw i powiązane z potwierdzonymi profilami."""
    found: dict[str, Candidate] = {}

    def add(node: Node, reason: str) -> None:
        cand = found.setdefault(node.id, Candidate(node, account_confidence(graph, node),
                                                   decision=decision_of(graph, person, node)))
        if reason not in cand.reasons:
            cand.reasons.append(reason)

    usernames = {e.dst for e in graph.edges.values() if e.src == person.id and e.relation == "candidate_username"}
    for e in graph.edges.values():
        if e.src in usernames and e.relation == "has_account" and e.dst in graph.nodes and is_profile(graph.nodes[e.dst]):
            add(graph.nodes[e.dst], f"konto nazwy '{graph.nodes[e.src].value}' (z imienia i nazwiska, {e.confidence:.2f})")
        if e.src == person.id and e.relation in REVIEW_RELATIONS:
            add(graph.nodes[e.dst], "oceniony wcześniej")
        if e.src == person.id and e.relation == "candidate_match" and e.dst in graph.nodes and is_profile(graph.nodes[e.dst]):
            add(graph.nodes[e.dst], f"kandydat ({e.source}): {e.evidence[:160]}")
    confirmed = {c for c, cand in found.items() if cand.decision == CONFIRMED}
    for e in graph.edges.values():
        if e.relation != "same_person":
            continue
        for a, b in ((e.src, e.dst), (e.dst, e.src)):
            if a in confirmed and b in graph.nodes and is_profile(graph.nodes[b]):
                add(graph.nodes[b], f"ta sama osoba co potwierdzony {graph.nodes[a].value} ({e.confidence:.2f}): {e.evidence}")
    order = {"": 0, CONFIRMED: 1, REJECTED: 2}
    return sorted(found.values(), key=lambda c: (order[c.decision], -(c.confidence or 0), c.node.id))


def decide(graph: Graph, person: Node, profile: Node, decision: str, evidence: str, now: str | None = None) -> Edge:
    """Zapisuje decyzję operatora (zastępuje poprzednią dla tej pary)."""
    if decision not in REVIEW_RELATIONS:
        raise ValueError(f"nieznana decyzja: {decision}")
    if not is_profile(profile):
        raise ValueError(f"{profile.value} nie jest profilem (węzeł URL z kind=profile)")
    evidence = validate_evidence(evidence)
    for rel in REVIEW_RELATIONS:
        graph.edges.pop((person.id, profile.id, rel, OPERATOR), None)
    conf = CONFIRM_CONFIDENCE if decision == CONFIRMED else 0.0
    label = "POTWIERDZONE przez operatora" if decision == CONFIRMED else "ODRZUCONE przez operatora"
    return graph.add_edge(Edge(person.id, profile.id, decision, OPERATOR, conf,
                               f"{label}: {evidence}. Ocena człowieka, nie dowód tożsamości", now or utc_now()))


def add_manual_profile(graph: Graph, url: str, now: str | None = None) -> Node:
    """Profil znaleziony ręcznie (np. z linków dorków), którego nie było w grafie."""
    node = Node.make(EntityType.URL, url, {"kind": "profile", "manual": True}, OPERATOR)
    if node.id in graph.nodes and not is_profile(graph.nodes[node.id]):
        graph.nodes[node.id].attrs["kind"] = "profile"
    return graph.add_node(node, now)


def propagate(graph: Graph, person: Node, now: str | None = None) -> list[Edge]:
    """Przelicza krawędzie via_confirmed_profile osoby od zera (idempotentne)."""
    now = now or utc_now()
    for key in [k for k, e in graph.edges.items() if e.source == SOURCE and e.src == person.id]:
        del graph.edges[key]
    confirmed = [graph.nodes[e.dst] for e in list(graph.edges.values())
                 if e.src == person.id and e.relation == CONFIRMED and e.dst in graph.nodes]
    created: list[Edge] = []
    for prof in confirmed:
        for e in list(graph.edges.values()):
            if prof.id not in (e.src, e.dst) or e.source in (OPERATOR, SOURCE):
                continue
            other = graph.nodes.get(e.dst if e.src == prof.id else e.src)
            if other is None or other.id == person.id or is_profile(other) or other.type is EntityType.PERSON:
                continue
            edge = graph.add_edge(Edge(person.id, other.id, DERIVED, SOURCE, min(CONFIRM_CONFIDENCE, e.confidence),
                                       f"przez potwierdzony profil {prof.value}: {e.relation} ({e.source}): {e.evidence}",
                                       now))
            if edge:
                created.append(edge)
        created += _profile_domains(graph, person, prof, now)
    # domeny dodane wyłącznie przez teczkę, które straciły powiązania (np. po odrzuceniu profilu)
    linked = {x for e in graph.edges.values() for x in (e.src, e.dst)}
    for node_id in [i for i, n in graph.nodes.items() if n.sources == [SOURCE] and i not in linked]:
        del graph.nodes[node_id]
    return created


def _profile_domains(graph: Graph, person: Node, prof: Node, now: str) -> list[Edge]:
    """Własna strona www (0.6) i linki do domen spoza platform (0.5) z potwierdzonego profilu -> domena osoby."""
    cap = min(CONFIRM_CONFIDENCE, account_confidence(graph, prof) or CONFIRM_CONFIDENCE)
    sources = [(prof.attrs.get("website"), WEBSITE_CONFIDENCE, "strona www")]
    sources += [(link, LINK_CONFIDENCE, "link") for link in prof.attrs.get("links") or []]
    created = []
    for raw, conf, label in sources:
        host = _host(str(raw or ""))
        if not host or _is_platform(host):
            continue
        try:
            dom = graph.add_node(Node.make(EntityType.DOMAIN, host, source=SOURCE), now)
        except ValueError:
            continue                                   # np. adres IP albo niepoprawna nazwa
        edge = graph.add_edge(Edge(person.id, dom.id, DERIVED, SOURCE, min(cap, conf),
                                   f"przez potwierdzony profil {prof.value}: {label} w profilu: {raw}", now))
        if edge:
            created.append(edge)
    return created


def dossier(graph: Graph, person: Node) -> dict:
    """Podsumowanie teczki: potwierdzone/odrzucone profile i dane dołączone przez potwierdzone profile."""
    out = {"confirmed": [], "rejected": [], "data": []}
    for e in sorted(graph.edges.values(), key=lambda x: (-x.confidence, x.dst)):
        if e.src != person.id or e.dst not in graph.nodes:
            continue
        if e.relation == CONFIRMED:
            out["confirmed"].append((graph.nodes[e.dst], e))
        elif e.relation == REJECTED:
            out["rejected"].append((graph.nodes[e.dst], e))
        elif e.relation == DERIVED:
            out["data"].append((graph.nodes[e.dst], e))
    return out
