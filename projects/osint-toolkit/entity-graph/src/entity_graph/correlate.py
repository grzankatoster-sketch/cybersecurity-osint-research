"""Korelacja: scalanie węzłów tej samej encji i powiązania "ta sama osoba" wyłącznie z jawnych sygnałów.

Scalanie dotyczy identyfikatorów, które po normalizacji są identyczne (domena, URL bez śledzenia i www, e-mail,
nazwa użytkownika bez wielkości liter, telefon E.164). Węzłów OSÓB nie scala się nigdy: tylko łączy krawędzią
same_person z dowodem.

Sygnały i ich wagi pochodzą ze wspólnego modułu evidence.py (ta sama reguła co w rozszerzaniu rekordów):
  * wzajemne linki w profilach (0.85); link w jedną stronę (0.7, pole kopiowalne: twierdzenie jednej strony)
  * ten sam adres e-mail powiązany z oboma profilami (0.8)
  * ta sama własna strona www (domena spoza listy platform) w obu profilach (0.6, pole kopiowalne)
  * ta sama nazwa wyświetlana ORAZ ten sam skrót awatara, na różnych serwisach (0.75, pola kopiowalne)
Krawędź powstaje tylko przy sygnale co najmniej umiarkowanym: sama nazwa, sam awatar albo podobne bio nie wystarczą.
Pola kopiowalne liczą się jako jedna zależna grupa (najsilniejsze, nie wyżej niż COPYABLE_CAP). Sprzeczność twarda
(np. osoba / organizacja) ogranicza wagę do CONFLICT_CAP. Wynik nigdy nie przekracza MAX_SCORE ani pewności
najsłabszego z dwóch kont. Waga porządkuje tropy; to nie jest prawdopodobieństwo."""
from __future__ import annotations

from datetime import datetime, timezone

from .evidence import (MAX_WEIGHT, PLATFORM_HOSTS, Level, Record, Signal, compare, host_of, is_platform,  # noqa: F401
                       level_of, url_key, weight)
from .model import Edge, Graph, Node, utc_now
from .normalize import EntityType, normalize
from .transforms.email import gravatar_hashes

MAX_SCORE = MAX_WEIGHT
RELATION = "same_person"
SOURCE = "correlate"
STALE_AFTER_DAYS = 365
STALE_FACTOR = 0.5
ACCOUNT_RELATIONS = ("has_account", "has_gravatar")
EMAIL_RELATIONS = ("has_gravatar", "avatar_matches_email", "uses_email")
_host = host_of          # dawne nazwy używane przez links.py i teczka.py
_is_platform = is_platform


def combine(scores: list[float]) -> float:
    rest = 1.0
    for s in scores:
        rest *= 1 - s
    return 1 - rest


def is_profile(node: Node) -> bool:
    return node.type is EntityType.URL and node.attrs.get("kind") in ("profile", "gravatar")


def account_confidence(graph: Graph, node: Node) -> float | None:
    """Najwyższa pewność krawędzi, która wprowadziła to konto do grafu (dowód istnienia konta)."""
    values = [e.confidence for e in graph.edges.values() if e.dst == node.id and e.relation in ACCOUNT_RELATIONS]
    return max(values) if values else None


def _emails_of(graph: Graph, node: Node) -> set[str]:
    out = set()
    for e in graph.edges.values():
        if e.relation not in EMAIL_RELATIONS or node.id not in (e.src, e.dst):
            continue
        other = e.dst if e.src == node.id else e.src
        if other.startswith(EntityType.EMAIL.value + ":"):
            out.add(other.split(":", 1)[1])
    return out


def record_from_node(graph: Graph, node: Node, anchor: bool = False) -> Record:
    """Węzeł profilu -> rekord do porównania (te same pola dla korelacji i rozszerzania)."""
    a = node.attrs
    return Record(
        url=node.key, site=str(a.get("site") or ""), display_name=str(a.get("display_name") or ""),
        avatar_hash=str(a.get("avatar_hash") or ""), website=str(a.get("website") or ""),
        links=tuple(str(x) for x in a.get("links") or []), emails=tuple(sorted(_emails_of(graph, node))),
        bio_fingerprint=tuple(a.get("bio_fingerprint") or ()), entity_kind=str(a.get("entity_kind") or ""),
        provenance=",".join(node.sources), reliability=account_confidence(graph, node),
        insecure=bool(a.get("insecure")), anchor=anchor, conflicts=tuple(node.conflicts()))


def _pair(graph: Graph, a: Node, b: Node):
    return compare(record_from_node(graph, a), record_from_node(graph, b))


def signals_between(graph: Graph, a: Node, b: Node) -> list[Signal]:
    """Sygnały co najmniej umiarkowane (te tworzą krawędź same_person)."""
    return [s for s in _pair(graph, a, b)[0] if s.level >= Level.MODERATE]


def _parse_time(value: str) -> datetime | None:
    try:
        moment = datetime.fromisoformat(str(value).strip())
    except (ValueError, TypeError):
        return None
    return moment if moment.tzinfo else moment.replace(tzinfo=timezone.utc)


def evidence_age_days(graph: Graph, node: Node, now: str) -> float | None:
    """Wiek (w dniach) najświeższego dowodu konta; None, gdy brak czytelnego znacznika czasu."""
    current = _parse_time(now)
    if current is None:
        return None
    moments = [_parse_time(e.timestamp) for e in graph.edges.values()
               if e.dst == node.id and e.relation in ACCOUNT_RELATIONS]
    moments = [m for m in moments if m is not None]
    if not moments:
        return None
    return max(0.0, (current - max(moments)).total_seconds() / 86400)


def _is_stale(graph: Graph, node: Node, now: str) -> bool:
    age = evidence_age_days(graph, node, now)
    return age is not None and age > STALE_AFTER_DAYS


def score_pair(graph: Graph, a: Node, b: Node, signals: list[Signal], now: str | None = None) -> float:
    contradictions = _pair(graph, a, b)[1]
    score = weight(signals, contradictions, (account_confidence(graph, a), account_confidence(graph, b)))
    if now is not None and (_is_stale(graph, a, now) or _is_stale(graph, b, now)):
        score = min(score, score * STALE_FACTOR)
    return score


def attach_gravatar_emails(graph: Graph, now: str | None = None) -> int:
    """Jeśli awatar profilu to Gravatar adresu e-mail znanego w grafie, dodaje krawędź profil -> e-mail."""
    added = 0
    for email in graph.nodes_of_type(EntityType.EMAIL):
        hashes = set(gravatar_hashes(email.key).values())
        for prof in graph.nodes_of_type(EntityType.URL):
            if prof.attrs.get("kind") == "profile" and prof.attrs.get("avatar_hash") in hashes:
                edge = Edge(prof.id, email.id, "avatar_matches_email", SOURCE, 0.85,
                            "awatar profilu to Gravatar tego adresu (skrót adresu w URL awatara)", now or utc_now())
                if graph.add_edge(edge):
                    added += 1
    return added


def merge_duplicates(graph: Graph) -> int:
    """Ponowna normalizacja kluczy (np. po ręcznej edycji lub imporcie) i scalenie kolizji. -> liczba scaleń."""
    merged = 0
    for node in list(graph.nodes.values()):
        try:
            key, display = normalize(node.type, node.value)
        except ValueError:
            continue
        if key == node.key:
            continue
        new_id = f"{node.type.value}:{key}"
        if new_id in graph.nodes:
            graph.merge_into(new_id, node.id)
            merged += 1
        else:
            graph.rename(node.id, key, display)
    return merged


def correlate(graph: Graph, now: str | None = None) -> list[Edge]:
    """Dodaje krawędzie same_person między profilami z co najmniej jednym jawnym sygnałem. Idempotentne."""
    now = now or utc_now()
    merge_duplicates(graph)
    attach_gravatar_emails(graph, now)
    profiles = sorted((n for n in graph.nodes.values() if is_profile(n)), key=lambda n: n.id)
    created: list[Edge] = []
    for i, a in enumerate(profiles):
        for b in profiles[i + 1:]:
            signals = signals_between(graph, a, b)
            if not signals:
                continue
            contradictions = _pair(graph, a, b)[1]
            score = score_pair(graph, a, b, signals, now)
            evidence = "; ".join(f"[{s.kind} {s.score:.2f}] {s.detail}" for s in signals)
            for acc in (a, b):
                if _is_stale(graph, acc, now):
                    age = int(evidence_age_days(graph, acc, now))
                    evidence += (f"; [stale] dowód nieaktualny: konto {acc.attrs.get('site') or acc.key} "
                                 f"sprawdzone {age} dni temu")
            notes = [f"dowody: {level_of(signals).label}"]
            if all(s.copyable for s in signals):
                notes.append("tylko pola, które da się skopiować: możliwa kopia")
            notes += [("SPRZECZNOŚĆ: " if c.hard else "rozbieżność: ") + c.detail for c in contradictions]
            graph.edges.pop((a.id, b.id, RELATION, SOURCE), None)
            edge = graph.add_edge(Edge(a.id, b.id, RELATION, SOURCE, score,
                                       f"{evidence}. {'; '.join(notes)}. Waga ograniczona do {score:.2f}: "
                                       "trop, nie dowód tożsamości", now))
            if edge:
                created.append(edge)
    return created
