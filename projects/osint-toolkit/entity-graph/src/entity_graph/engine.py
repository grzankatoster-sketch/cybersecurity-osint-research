"""Silnik badania: uruchamia transformacje na zalążkach i (do limitu głębokości) na odkrytych węzłach.

Zasady: wyjątek w transformacji = ERROR tego uruchomienia (nigdy brak danych); każde uruchomienie trafia do
dziennika audytu i do grafu (graph.runs); twarde limity węzłów i uruchomień chronią przed lawiną."""
from __future__ import annotations

from collections import deque
from dataclasses import dataclass, field
from typing import Callable

from . import __version__
from .correlate import correlate
from .guardrails import AuditLog
from .model import Graph, Node, RunRecord, Status, merge_value
from .normalize import EntityType
from .transforms import REGISTRY, Context, Transform, TransformResult

# Po których relacjach badanie przechodzi dalej (głębokość > 0). Hosty NS/MX, rejestrator, organizacje i konta
# NIE są rozwijane: to cudza infrastruktura lub profile. Subdomeny i kandydaci tylko na jawną prośbę.
PIVOT_RELATIONS = frozenset({"resolves_to", "mailbox_at", "hosted_on"})


@dataclass
class Options:
    depth: int = 1
    max_nodes: int = 500
    max_runs: int = 200
    only: frozenset[str] = frozenset()
    skip: frozenset[str] = frozenset()
    expand_subdomains: bool = False
    expand_candidates: bool = False
    offline: bool = False

    def to_audit(self) -> dict:
        return {"depth": self.depth, "max_nodes": self.max_nodes, "max_runs": self.max_runs,
                "only": sorted(self.only), "skip": sorted(self.skip), "expand_subdomains": self.expand_subdomains,
                "expand_candidates": self.expand_candidates, "offline": self.offline}


def select_transforms(node: Node, opts: Options, registry: dict[str, Transform]) -> list[Transform]:
    out = []
    for t in registry.values():
        if node.type not in t.inputs or t.name in opts.skip or (opts.only and t.name not in opts.only):
            continue
        out.append(t)
    return out


def _should_pivot(edge_relation: str, target: Node, opts: Options) -> bool:
    if target.attrs.get("candidate"):
        return opts.expand_candidates
    if target.attrs.get("generic_mail_provider"):
        return False
    if edge_relation == "has_subdomain":
        return opts.expand_subdomains
    return edge_relation in PIVOT_RELATIONS


def run_transform(t: Transform, node: Node, ctx: Context, offline: bool) -> TransformResult:
    if offline and t.network:
        return TransformResult.failed(Status.UNKNOWN, "tryb offline: transformacja sieciowa pominięta")
    try:
        result = t.run(node, ctx)
    except Exception as exc:  # noqa: BLE001 - jedna transformacja nie może przerwać badania ani udawać braku danych
        return TransformResult.failed(Status.ERROR, f"wyjątek: {type(exc).__name__}")
    if result.status is Status.ERROR and not result.error:
        result.error = "nieznany błąd"
    return result


def apply_result(graph: Graph, node: Node, result: TransformResult) -> tuple[Node, list[tuple[str, Node]]]:
    """Wnosi wynik do grafu. -> (węzeł kanoniczny wejścia, [(relacja, nowy/istniejący węzeł docelowy)])."""
    node.attrs = _merged(node.attrs, result.node_attrs)
    targets: dict[str, Node] = {}
    for n in result.nodes:
        targets[n.id] = graph.add_node(n)
    for e in result.edges:
        if e.src == node.id or e.src in graph.nodes:
            graph.add_edge(e)
    pivots = [(e.relation, targets[e.dst]) for e in result.edges if e.dst in targets]
    if result.canonical is not None:
        canon = graph.add_node(result.canonical)
        graph.merge_into(canon.id, node.id)
        node = canon
    return node, pivots


def _link_evidence(result: TransformResult, refs: list[str]) -> None:
    """Dowiązuje refy skarbca do krawędzi, nowych węzłów i (gdy dostał atrybuty) węzła wejściowego."""
    if not refs:
        return
    for e in result.edges:
        e.evidence_ref = merge_value(list(e.evidence_ref), list(refs))
    for n in result.nodes:
        n.attrs["evidence_ref"] = merge_value(n.attrs.get("evidence_ref", []), list(refs))
    if result.node_attrs:
        result.node_attrs["evidence_ref"] = merge_value(result.node_attrs.get("evidence_ref", []), list(refs))


def _merged(attrs: dict, extra: dict) -> dict:
    out = dict(attrs)
    for k, v in extra.items():
        out[k] = merge_value(out[k], v) if k in out else v
    return out


def investigate(
    graph: Graph,
    seeds: list[Node],
    ctx: Context,
    audit: AuditLog,
    opts: Options,
    registry: dict[str, Transform] | None = None,
    progress: Callable[[str], None] | None = None,
) -> Graph:
    registry = registry if registry is not None else REGISTRY
    queue: deque[tuple[str, int]] = deque()
    queued: set[str] = set()
    done: set[tuple[str, str]] = set()
    runs = 0
    truncated = ""
    for s in seeds:
        n = graph.add_node(s)
        if n.id not in queued:
            queue.append((n.id, 0))
            queued.add(n.id)

    while queue:
        node_id, depth = queue.popleft()
        for t in select_transforms(graph.nodes[node_id], opts, registry):
            node = graph.nodes.get(node_id)
            if node is None:   # węzeł został scalony z kanonicznym w trakcie
                break
            if (t.name, node.id) in done:
                continue
            if runs >= opts.max_runs:
                truncated = f"osiągnięto limit uruchomień ({opts.max_runs})"
                break
            done.add((t.name, node.id))
            runs += 1
            vault = getattr(ctx, "vault", None)
            if vault is not None:
                vault.begin(t.name, node.id)
            result = run_transform(t, node, ctx, opts.offline)
            evidence: dict = {}
            if vault is not None:
                refs = vault.take()
                _link_evidence(result, [r["ref"] for r in refs])
                evidence["evidence"] = [{"ref": r["ref"], "url": r["url"], "status": r["status"],
                                         "sha256": r["sha256"]} for r in refs]
            old_id = node.id
            node, pivots = apply_result(graph, node, result)
            node_id = node.id
            done.add((t.name, node.id))
            record = RunRecord(t.name, old_id, result.status, ctx.now(), result.note, result.error, result.stats)
            graph.runs.append(record)
            audit.write("transform", transform=t.name, node=old_id, status=result.status.value,
                        error=result.error, note=result.note, nodes_added=len(result.nodes),
                        edges_added=len(result.edges), **evidence)
            if progress:
                progress(f"{result.status.value:<9} {t.name:<18} {old_id}"
                         + (f"  ({result.error or result.note})" if result.error or result.note else ""))
            if depth < opts.depth:
                for relation, target in pivots:
                    if (target.id not in queued and _should_pivot(relation, target, opts)
                            and len(graph.nodes) < opts.max_nodes):
                        queue.append((target.id, depth + 1))
                        queued.add(target.id)
        if truncated:
            break
    if len(graph.nodes) >= opts.max_nodes:
        truncated = truncated or f"osiągnięto limit węzłów ({opts.max_nodes})"
    if truncated:
        graph.meta["truncated"] = truncated
        audit.write("limit", detail=truncated)
    links = correlate(graph, ctx.now())
    audit.write("end", nodes=len(graph.nodes), edges=len(graph.edges), runs=runs, same_person_links=len(links),
                statuses={s.value: sum(1 for r in graph.runs if r.status is s) for s in Status})
    return graph


def new_graph(purpose: str, operator: str, case_ref: str, inputs: list[dict], options: dict, started: str) -> Graph:
    return Graph({"tool": f"entity-graph {__version__}", "purpose": purpose, "operator": operator,
                  "case_ref": case_ref, "started": started, "inputs": inputs, "options": options})
