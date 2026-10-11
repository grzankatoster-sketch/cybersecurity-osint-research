"""Kropki: rysunek grafu jako statyczny SVG (węzeł = kropka w kolorze typu, krawędź = linia wg pewności).

Bez JavaScriptu i zewnętrznych zasobów; wszystkie teksty z cudzych źródeł escapowane. Układ siłowy
(Fruchterman-Reingold) jest deterministyczny: ten sam graf daje ten sam rysunek.
"""
from __future__ import annotations

import hashlib
import html
import math
from collections import Counter

from .export import xml_safe
from .model import Graph
from .normalize import LABELS_PL, EntityType

COLORS = {
    EntityType.PERSON: "#d1495b", EntityType.USERNAME: "#edae49", EntityType.EMAIL: "#00798c",
    EntityType.DOMAIN: "#30638e", EntityType.IP: "#6a4c93", EntityType.PHONE: "#2a9d8f",
    EntityType.ORGANIZATION: "#8d5524", EntityType.URL: "#7a7a7a", EntityType.PHOTO: "#e76f51",
    EntityType.PARCEL: "#588157",
}
SIZE = 1000.0
MARGIN = 60.0
LEGEND_W = 230.0
LABEL_MAX = 28
CONFIRMED = "confirmed_profile"
RELATION_PREFIX = "relacje:"           # twierdzenia o relacjach osób (relacje.py)
RELATION_COLOR = "#7b3fa0"


def _is_claim(e) -> bool:
    return e.source.startswith(RELATION_PREFIX)


def _seed_xy(node_id: str) -> tuple[float, float]:
    """Pozycja startowa ze skrótu id (deterministyczna, niezależna od kolejności węzłów)."""
    h = hashlib.sha256(node_id.encode("utf-8")).digest()
    return int.from_bytes(h[:4], "big") / 2**32 * SIZE, int.from_bytes(h[4:8], "big") / 2**32 * SIZE


def layout(ids: list[str], pairs: list[tuple[str, str]], iterations: int = 200) -> dict[str, tuple[float, float]]:
    """Fruchterman-Reingold z grawitacją do środka (rozłączne składowe nie odlatują)."""
    if not ids:
        return {}
    if len(ids) == 1:
        return {ids[0]: (SIZE / 2, SIZE / 2)}
    pos = {i: list(_seed_xy(i)) for i in ids}
    k = math.sqrt(SIZE * SIZE / len(ids))
    temp = SIZE / 10
    for step in range(iterations):
        disp = {i: [0.0, 0.0] for i in ids}
        for a_idx, a in enumerate(ids):
            pa = pos[a]
            for b in ids[a_idx + 1:]:
                pb = pos[b]
                dx, dy = pa[0] - pb[0], pa[1] - pb[1]
                d2 = dx * dx + dy * dy or 0.01
                f = k * k / d2
                disp[a][0] += dx * f; disp[a][1] += dy * f
                disp[b][0] -= dx * f; disp[b][1] -= dy * f
        for a, b in pairs:
            pa, pb = pos[a], pos[b]
            dx, dy = pa[0] - pb[0], pa[1] - pb[1]
            d = math.hypot(dx, dy) or 0.01
            f = d / k
            disp[a][0] -= dx * f; disp[a][1] -= dy * f
            disp[b][0] += dx * f; disp[b][1] += dy * f
        for i in ids:
            p = pos[i]
            disp[i][0] += (SIZE / 2 - p[0]) * 0.02 * k / 10
            disp[i][1] += (SIZE / 2 - p[1]) * 0.02 * k / 10
            dx, dy = disp[i]
            d = math.hypot(dx, dy) or 0.01
            p[0] += dx / d * min(d, temp)
            p[1] += dy / d * min(d, temp)
        temp = max(SIZE / 10 * (1 - (step + 1) / iterations), 1.0)
    # dopasowanie do kwadratu [MARGIN, SIZE - MARGIN]
    xs, ys = [p[0] for p in pos.values()], [p[1] for p in pos.values()]
    span = max(max(xs) - min(xs), max(ys) - min(ys)) or 1.0
    scale = (SIZE - 2 * MARGIN) / span
    ox = MARGIN + ((SIZE - 2 * MARGIN) - (max(xs) - min(xs)) * scale) / 2
    oy = MARGIN + ((SIZE - 2 * MARGIN) - (max(ys) - min(ys)) * scale) / 2
    return {i: (ox + (p[0] - min(xs)) * scale, oy + (p[1] - min(ys)) * scale) for i, p in pos.items()}


def _esc(text: object) -> str:
    return html.escape(xml_safe(text), quote=True)


def _short(text: str) -> str:
    return text if len(text) <= LABEL_MAX else text[: LABEL_MAX - 1] + "…"


def select(graph: Graph, max_nodes: int, min_confidence: float) -> tuple[list[str], list, int]:
    """Węzły do narysowania (najbardziej połączone, gdy za dużo) i krawędzie między nimi."""
    edges = [e for e in graph.edges.values() if not e.relation.startswith("rejected_")
             and e.confidence >= min_confidence and e.src in graph.nodes and e.dst in graph.nodes and e.src != e.dst]
    degree = Counter()
    for e in edges:
        degree[e.src] += 1
        degree[e.dst] += 1
    ids = sorted(graph.nodes, key=lambda i: (-degree[i], i))
    cut = max(len(ids) - max_nodes, 0)
    keep = set(ids[:max_nodes])
    return sorted(keep), [e for e in edges if e.src in keep and e.dst in keep], cut


def render_svg(graph: Graph, max_nodes: int = 200, min_confidence: float = 0.0, iterations: int = 200) -> str:
    if max_nodes < 1:
        raise ValueError("--max-nodes musi być >= 1")
    ids, edges, cut = select(graph, max_nodes, min_confidence)
    pairs = sorted({tuple(sorted((e.src, e.dst))) for e in edges})
    pos = layout(ids, pairs, iterations)
    degree = Counter(x for p in pairs for x in p)

    w, h = SIZE + LEGEND_W, SIZE
    out = [f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {w:.0f} {h:.0f}" width="{w:.0f}" height="{h:.0f}" '
           'font-family="Segoe UI, Arial, sans-serif" font-size="11">',
           f'<rect width="{w:.0f}" height="{h:.0f}" fill="#ffffff"/>',
           '<g stroke="#555555" stroke-linecap="round">']
    best: dict[tuple[str, str], object] = {}
    for e in edges:
        key = tuple(sorted((e.src, e.dst)))
        rank = (e.relation == CONFIRMED or _is_claim(e), e.confidence)
        if key not in best or rank > (best[key].relation == CONFIRMED or _is_claim(best[key]), best[key].confidence):
            best[key] = e
    for (a, b), e in sorted(best.items()):
        (x1, y1), (x2, y2) = pos[a], pos[b]
        style = ' stroke-dasharray="4 4"' if e.confidence == 0 else ""
        if e.relation == CONFIRMED:
            style += ' stroke="#1b9e45"'
        elif _is_claim(e):
            style += f' stroke="{RELATION_COLOR}"'
        direction = f"{graph.nodes[e.src].value} -> {graph.nodes[e.dst].value}: " if _is_claim(e) else ""
        out.append(f'<line x1="{x1:.1f}" y1="{y1:.1f}" x2="{x2:.1f}" y2="{y2:.1f}" '
                   f'stroke-width="{0.6 + 2.4 * e.confidence:.2f}" stroke-opacity="{0.25 + 0.6 * e.confidence:.2f}"{style}>'
                   f'<title>{_esc(direction)}{_esc(e.relation)} ({e.confidence:.2f}): {_esc(e.evidence)}</title></line>')
    out.append("</g>")

    out.append('<g stroke="#ffffff" stroke-width="1.5">')
    for i in ids:
        node = graph.nodes[i]
        x, y = pos[i]
        r = 5 + min(degree[i], 20) * 0.6
        out.append(f'<circle cx="{x:.1f}" cy="{y:.1f}" r="{r:.1f}" fill="{COLORS.get(node.type, "#999999")}">'
                   f'<title>{_esc(LABELS_PL.get(node.type, node.type.value))}: {_esc(node.value)}</title></circle>')
        out.append(f'<text x="{x + r + 3:.1f}" y="{y + 4:.1f}" stroke="none" fill="#222222">{_esc(_short(node.value))}</text>')
    out.append("</g>")

    lx = SIZE + 10
    counts = Counter(graph.nodes[i].type for i in ids)
    out.append(f'<text x="{lx:.0f}" y="40" font-size="14" font-weight="bold">Kropki: {len(ids)} węzłów, {len(best)} połączeń</text>')
    y = 70
    for etype in EntityType:
        if counts[etype]:
            out.append(f'<circle cx="{lx + 8:.0f}" cy="{y - 4}" r="6" fill="{COLORS[etype]}"/>'
                       f'<text x="{lx + 22:.0f}" y="{y}">{_esc(LABELS_PL.get(etype, etype.value))} ({counts[etype]})</text>')
            y += 20
    notes = ["grubość linii = pewność", "linia przerywana = hipoteza (0)", "zielona linia = profil potwierdzony",
             "fioletowa = twierdzenie o relacji", "(przerywana: wymaga potwierdzenia)", "najedź na kropkę: wartość"]
    if min_confidence > 0:
        notes.append(f"pominięto krawędzie < {min_confidence:g}")
    if cut:
        notes.append(f"pominięto {cut} najsłabiej połączonych węzłów")
    for note in notes:
        y += 18
        out.append(f'<text x="{lx:.0f}" y="{y}" fill="#555555">{_esc(note)}</text>')
    out.append("</svg>")
    return "\n".join(out) + "\n"
