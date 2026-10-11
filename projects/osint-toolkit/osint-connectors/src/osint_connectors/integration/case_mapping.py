"""Mapowanie Finding -> rekord przebiegu (run) sprawy entity-graph.

entity-graph ma własny enum ``Status`` o identycznych NAZWACH
(FOUND/NOT_FOUND/UNKNOWN/ERROR) i tych samych semantykach, co tutejszy — różnią
się tylko wielkością liter w wartościach (`"found"` vs `"FOUND"`). Dlatego
mostkujemy przez ``Status.name`` (= "FOUND"), co daje dokładnie wartość oczekiwaną
przez entity-graph.

Wynik to ZSERIALIZOWANY słownik w kształcie ``entity_graph.model.RunRecord.to_dict()``
(klucze: transform, node, status jako tekst, timestamp, note, error, stats) — NIE są to
argumenty konstruktora. ``RunRecord(**mapped)`` NIE zadziała: konstruktor ma ``node_id``
(nie ``node``) i enum ``Status`` (nie tekst). Poprawne wpięcie: dołączyć do listy
``runs`` słownika grafu i odtworzyć przez ``Graph.from_dict`` albo zbudować
``RunRecord(transform=r["transform"], node_id=r["node"], status=Status(r["status"]), ...)``.

Granica odpowiedzialności za dane: hashowany (HMAC z solą) jest WYŁĄCZNIE identyfikator
celu → ``stats.subject_ref``. Pola ``note`` (z ``evidence``) i ``stats.extra.*`` są
przepisywane DOSŁOWNIE z :class:`Finding`; HMAC ich nie zabezpiecza. To konektor
odpowiada, by nie wkładać tam surowych danych osobowych. ``node_id`` (zwykle jawny
e-mail) i tak należy do grafu sprawy — ten moduł go nie hashuje.
"""
from __future__ import annotations

from typing import Iterable, List, Mapping, Optional

from ..model import Finding, Status

#: Klucze rekordu run oczekiwane przez entity-graph (model.py: RunRecord.to_dict).
ENTITY_GRAPH_RUN_KEYS = ("transform", "node", "status", "timestamp", "note", "error", "stats")

#: Nazwy statusów, które muszą się zgadzać po obu stronach (asercja kontraktu).
EXPECTED_STATUS_NAMES = ("FOUND", "NOT_FOUND", "UNKNOWN", "ERROR")


def _status_name(status: Status) -> str:
    # .name mostkuje lower->UPPER; wartość == wartość enuma entity-graph.
    return status.name


def finding_to_run(
    finding: Finding,
    node_id: str,
    *,
    extra_stats: Optional[Mapping[str, object]] = None,
) -> dict:
    """Zamień jeden :class:`Finding` na rekord run zgodny z entity-graph.

    ``node_id`` to identyfikator węzła w grafie sprawy (np. ``"email:..."``),
    dostarczony przez wołającego. ``error`` wypełniamy tylko dla ERROR/UNKNOWN.
    """
    if not isinstance(node_id, str) or not node_id.strip():
        raise ValueError("node_id jest wymagany (identyfikator węzła w grafie sprawy)")

    stats = {
        "source": finding.source.value,
        "confidence": round(finding.confidence, 4),
        "subject_ref": finding.subject_ref,
    }
    for k, v in dict(finding.extra or {}).items():
        stats[f"extra.{k}"] = v
    if extra_stats:
        stats.update(dict(extra_stats))

    error = ""
    if finding.status in (Status.ERROR, Status.UNKNOWN) and finding.error_kind:
        error = finding.error_kind

    return {
        "transform": finding.connector,
        "node": node_id,
        "status": _status_name(finding.status),
        "timestamp": finding.checked_at.astimezone().isoformat(),
        "note": finding.evidence or "",
        "error": error,
        "stats": stats,
    }


def findings_to_runs(findings: Iterable[Finding], node_id: str) -> List[dict]:
    """Zmapuj wiele Finding (dla jednego węzła) na listę rekordów run.

    Deterministycznie posortowane po nazwie transformu (= konektora).
    """
    runs = [finding_to_run(f, node_id) for f in findings]
    return sorted(runs, key=lambda r: r["transform"])
