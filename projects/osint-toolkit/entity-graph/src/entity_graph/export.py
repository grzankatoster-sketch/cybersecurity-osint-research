"""Eksport grafu: GraphML (Gephi, yEd; format standardowy) i statyczny raport HTML (bez JS, wszystko escapowane)."""
from __future__ import annotations

import csv
import html
import io
import json
import re
import xml.etree.ElementTree as ET
from collections import Counter
from urllib.parse import urlsplit

from . import __version__
from .guardrails import EXCLUDED_CAPABILITIES
from .model import Edge, Graph, Node, Status
from .normalize import LABELS_PL, EntityType
from . import relacje, teczka, telefon

GRAPHML_NS = "http://graphml.graphdrawing.org/xmlns"
_XML_BAD = re.compile("[^\u0009\u000a\u000d -퟿-�\U00010000-\U0010ffff]")


def xml_safe(text: object) -> str:
    """Usuwa znaki niedozwolone w XML 1.0 (np. sterujące z cudzych danych), inaczej plik się nie otworzy."""
    return _XML_BAD.sub("", str(text))


# ------------------------------------------------------------------ GraphML

def to_graphml(graph: Graph) -> str:
    ET.register_namespace("", GRAPHML_NS)
    root = ET.Element(f"{{{GRAPHML_NS}}}graphml")
    keys = [
        ("n_label", "node", "label", "string"), ("n_type", "node", "type", "string"),
        ("n_value", "node", "value", "string"), ("n_sources", "node", "sources", "string"),
        ("n_first_seen", "node", "first_seen", "string"), ("n_attrs", "node", "attrs", "string"),
        ("e_relation", "edge", "relation", "string"), ("e_source", "edge", "source", "string"),
        ("e_confidence", "edge", "confidence", "double"), ("e_evidence", "edge", "evidence", "string"),
        ("e_timestamp", "edge", "timestamp", "string"), ("e_label", "edge", "label", "string"),
        ("e_evidence_ref", "edge", "evidence_ref", "string"),
    ]
    for kid, target, name, typ in keys:
        ET.SubElement(root, f"{{{GRAPHML_NS}}}key", {"id": kid, "for": target, "attr.name": name, "attr.type": typ})
    g = ET.SubElement(root, f"{{{GRAPHML_NS}}}graph", {"id": "G", "edgedefault": "directed"})
    ids = {nid: f"n{i}" for i, nid in enumerate(graph.nodes)}

    def data(parent, key: str, value: object) -> None:
        ET.SubElement(parent, f"{{{GRAPHML_NS}}}data", {"key": key}).text = xml_safe(value)

    for node in graph.nodes.values():
        el = ET.SubElement(g, f"{{{GRAPHML_NS}}}node", {"id": ids[node.id]})
        data(el, "n_label", node.value)
        data(el, "n_type", node.type.value)
        data(el, "n_value", node.value)
        data(el, "n_sources", ", ".join(node.sources))
        data(el, "n_first_seen", node.first_seen)
        data(el, "n_attrs", json.dumps(node.attrs, ensure_ascii=False, sort_keys=True))
    for i, edge in enumerate(graph.edges.values()):
        el = ET.SubElement(g, f"{{{GRAPHML_NS}}}edge", {"id": f"e{i}", "source": ids[edge.src], "target": ids[edge.dst]})
        data(el, "e_relation", edge.relation)
        data(el, "e_label", edge.relation)
        data(el, "e_source", edge.source)
        data(el, "e_confidence", f"{edge.confidence:.3f}")
        data(el, "e_evidence", edge.evidence)
        data(el, "e_timestamp", edge.timestamp)
        if edge.evidence_ref:
            data(el, "e_evidence_ref", ",".join(edge.evidence_ref))
    ET.indent(root)
    return '<?xml version="1.0" encoding="UTF-8"?>\n' + ET.tostring(root, encoding="unicode") + "\n"


# ------------------------------------------------------------------ Maltego (CSV do "Import Graph from Table")
#
# Decyzje formatu (testy: tests/test_maltego_export.py):
# - Nagłówek zgodny wstecz: pierwsze 9 kolumn bez zmian (kolejność i nazwy), nowe kolumny DOPISANE na końcu.
# - UTF-8 bez BOM (BOM trafiłby do nazwy pierwszej kolumny; Maltego czyta UTF-8, Excel: Dane -> Z tekstu, UTF-8).
# - Wiersze kończy "\r\n" (RFC 4180), zawsze; wartości nigdy nie zawierają CR/LF ani innych znaków sterujących
#   (zamieniane na spację), więc jedna encja = jedna fizyczna linia. Przecinki i cudzysłowy cytuje csv.writer.
# - Węzły typu Email NIE są eksportowane (ani jako wiersze, ani jako końce krawędzi): zamaskowana wartość zlałaby w
#   Maltego różne adresy w jedną encję i zafałszowała powiązania. Adres e-mail w KAŻDEJ innej komórce -> "[e-mail ukryty]".
# - Komórka z sekretem (JWT, Bearer, klucz prywatny, bcrypt, e-mail:hasło, hasło w URL, password=...) -> cała komórka
#   zastąpiona znacznikiem "[usunięto: sekret]". Surowych rekordów wycieków graf nie przechowuje, a filtr działa na
#   każdej komórce niezależnie od typu węzła.

# Typy encji Maltego dla typow entity-graph; reszta jako maltego.Phrase (operator mapuje kolumny przy imporcie).
MALTEGO_TYPES = {
    "person": "maltego.Person", "username": "maltego.Alias", "email": "maltego.EmailAddress",
    "domain": "maltego.Domain", "ip": "maltego.IPv4Address", "phone": "maltego.PhoneNumber",
    "organization": "maltego.Organization", "url": "maltego.URL", "photo": "maltego.Image",
    "parcel": "maltego.Location",
}
_CSV_CTRL = re.compile("[\x00-\x1f\x7f-\x9f\u2028\u2029]")
_CSV_INVISIBLE = re.compile("[\u00ad\u200b-\u200f\u202a-\u202e\u2060-\u2064\ufeff]")   # nie dzielą wzorców sekretów
_CSV_NUMBER = re.compile(r"[+-]?[0-9][0-9 ()./-]*")   # numer/liczba: arkusz nie wykona z tego funkcji
MALTEGO_HEADER = ("source_type", "source_value", "relation", "target_type", "target_value", "confidence",
                  "evidence", "source", "timestamp_utc",
                  "source_id", "target_id", "derivation", "evidence_hash", "evidence_ref")
MALTEGO_EMAIL_MASK = "[e-mail ukryty]"
MALTEGO_SECRET_MARK = "[usunięto: sekret]"
_MALTEGO_EMAIL = re.compile(r"[\w.%+-]+@[\w-]+(?:\.[\w-]+)+")
_MALTEGO_SECRET = re.compile("|".join((
    r"eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.",                    # JWT
    r"\bBearer\s+[A-Za-z0-9._~+/=-]{20,}",                        # token Bearer
    r"-----BEGIN [A-Z ]*PRIVATE KEY-----",                        # klucz prywatny
    r"\$2[aby]\$[0-9]{2}\$",                                      # hash bcrypt
    r"(?<![A-Za-z0-9])[\w.+-]+@[\w-]+(?:\.[\w-]+)+[:;|](?!\d+(?:/|$))\S{3,}",   # e-mail:haslo
    r"://[^/\s:@]+:[^/\s@]+@",                                    # haslo w URL (user:haslo@host)
    r"\b(?:password|passwd|pwd|token|secret|api[_-]?key)\s*[=:]\s*\S{6,}",   # pole=wartosc
)), re.IGNORECASE)   # id wezlow bywa zapisane malymi literami
_ORG_INTEL_PREFIX = "org-intel:"            # = importers.org_intel.SOURCE_PREFIX (bez importu, by uniknąć cyklu)
_EVIDENCE_DERIVATION = re.compile(r"(direct|inferred);")
_EVIDENCE_HASH = re.compile(r"\bevidence_hash=([0-9a-f]{12,64})(?![0-9a-f])")
_SHA256 = re.compile(r"[0-9a-f]{64}")


def _csv_cell(value: object) -> str:
    """Komorka CSV bezpieczna dla arkuszy: bez znakow sterujacych, formula poprzedzona apostrofem. '=' i '@'
    zawsze; '+'/'-' tylko gdy to nie sama liczba lub numer (np. '+48 603 123 456' zostaje wartoscia encji)."""
    text = _CSV_CTRL.sub(" ", xml_safe(value))
    first = text.lstrip()[:1]
    if first in ("=", "@") or (first in ("+", "-") and not _CSV_NUMBER.fullmatch(text.strip())):
        return "'" + text
    return text


def _maltego_cell(value: object) -> str:
    """Komorka eksportu Maltego: sekret -> cala komorka "[usunieto: sekret]", e-mail -> "[e-mail ukryty]", potem
    ochrona przed formulami (_csv_cell)."""
    text = _CSV_INVISIBLE.sub("", _CSV_CTRL.sub(" ", xml_safe(value)))
    if _MALTEGO_SECRET.search(text):
        return MALTEGO_SECRET_MARK
    return _csv_cell(_MALTEGO_EMAIL.sub(MALTEGO_EMAIL_MASK, text))


def _maltego_edge_provenance(edge: Edge, a: Node, b: Node) -> tuple[str, str]:
    """(derivation, evidence_hash) wylacznie z tego, co jest w grafie: z tekstu dowodu krawedzi zapisanego przez
    importer org-intel ('direct|inferred; ...; evidence_hash=<12 znakow>') oraz z provenance wezlow (to samo zrodlo,
    skrot jest poczatkiem pelnego sha256; derivation we wpisie provenance moze sie roznic od krawedzi). Brak danych = puste pola; nic nie jest zgadywane."""
    derivation = evidence_hash = ""
    org_intel = edge.source.startswith(_ORG_INTEL_PREFIX)
    if org_intel:
        m = _EVIDENCE_DERIVATION.match(edge.evidence)
        derivation = m.group(1) if m else ""
    m = _EVIDENCE_HASH.search(edge.evidence)
    if m:
        evidence_hash = m.group(1)
        if org_intel and len(evidence_hash) < 64:
            key = edge.source[len(_ORG_INTEL_PREFIX):]
            for node in (a, b):
                for entry in node.attrs.get("provenance") or []:
                    if not isinstance(entry, dict):
                        continue
                    full = str(entry.get("evidence_hash") or "")
                    if (entry.get("source_url_normalized") == key and _SHA256.fullmatch(full)
                            and full.startswith(evidence_hash)):
                        return derivation, full
    return derivation, evidence_hash


def to_maltego_csv(graph: Graph) -> str:
    """Krawedzie grafu jako tabela par encji. Import w Maltego: Import -> Import Graph from Table; kolumny
    *_type wskazuja typ encji, relacja, pewnosc, zrodlo i proweniencja (derivation, evidence_hash, evidence_ref)
    zostaja jako wlasciwosci. Wezly bez krawedzi (takze po pominieciu krawedzi do wezlow Email): osobne wiersze.
    Wezly typu Email nie sa eksportowane. Wynik: UTF-8, wiersze konczone "\\r\\n", deterministyczny."""
    rows: list[tuple] = []
    linked: set[str] = set()
    for edge in graph.edges.values():
        a, b = graph.nodes.get(edge.src), graph.nodes.get(edge.dst)
        if a is None or b is None or EntityType.EMAIL in (a.type, b.type):
            continue
        linked.update((a.id, b.id))
        derivation, evidence_hash = _maltego_edge_provenance(edge, a, b)
        rows.append((MALTEGO_TYPES.get(a.type.value, "maltego.Phrase"), a.value, edge.relation,
                     MALTEGO_TYPES.get(b.type.value, "maltego.Phrase"), b.value, f"{edge.confidence:.3f}",
                     edge.evidence, edge.source, edge.timestamp, a.id, b.id, derivation, evidence_hash,
                     " ".join(edge.evidence_ref)))
    for node in graph.nodes.values():
        if node.id not in linked and node.type is not EntityType.EMAIL:
            rows.append((MALTEGO_TYPES.get(node.type.value, "maltego.Phrase"), node.value, "", "", "", "", "",
                         ", ".join(node.sources), node.first_seen, node.id, "", "", "", ""))
    buf = io.StringIO()
    writer = csv.writer(buf, lineterminator="\r\n")
    writer.writerow(MALTEGO_HEADER)
    for row in rows:
        writer.writerow([_maltego_cell(c) for c in row])
    return buf.getvalue()


# ------------------------------------------------------------------ HTML

esc = lambda s: html.escape(str(s), quote=True)  # noqa: E731
MAX_EDGE_ROWS = 3000
MAX_ATTR_CHARS = 400

CSS = """
:root{--bg:#fff;--fg:#1b1f24;--muted:#57606a;--line:#d0d7de;--accent:#0b5cad;--warn:#fff4d6;--bad:#8a1f11}
@media (prefers-color-scheme:dark){:root{--bg:#14181d;--fg:#e6edf3;--muted:#9aa4af;--line:#30363d;--accent:#58a6ff;--warn:#3a2f12;--bad:#ff8b7a}}
body{margin:0;background:var(--bg);color:var(--fg);font:15px/1.5 system-ui,Segoe UI,sans-serif}
main{max-width:1200px;margin:0 auto;padding:16px}
h1{font-size:1.5rem}h2{font-size:1.15rem;margin-top:2rem;border-bottom:1px solid var(--line);padding-bottom:4px}
table{border-collapse:collapse;width:100%;font-size:.9rem}th,td{border:1px solid var(--line);padding:4px 8px;text-align:left;vertical-align:top;overflow-wrap:anywhere}
th{background:rgba(127,127,127,.12)}a{color:var(--accent)}code{font-size:.85em}
.notice{background:var(--warn);border:1px solid var(--line);padding:8px 12px}.muted{color:var(--muted)}
.st{font-weight:600}.st-ERROR{color:var(--bad)}.conf{font-variant-numeric:tabular-nums}
.scroll{overflow-x:auto}
"""


def _safe_href(url: str) -> str | None:
    try:
        parts = urlsplit(url)
    except ValueError:
        return None
    if parts.scheme.lower() in ("http", "https") and parts.netloc and not re.search(r"[\s\x00-\x1f]", url):
        return url
    return None


def _link(url: str, text: str | None = None) -> str:
    href = _safe_href(url)
    label = esc(text if text is not None else url)
    return f'<a href="{esc(href)}" rel="noopener noreferrer nofollow">{label}</a>' if href else label


def _node_cell(node: Node | None, fallback: str) -> str:
    if node is None:
        return esc(fallback)
    text = f"{node.value}"
    return _link(node.value, text) if node.type is EntityType.URL else esc(text)


def _attrs_cell(node: Node) -> str:
    shown = {k: v for k, v in node.attrs.items() if k != "manual_review_links"}
    if node.conflicts():
        shown["sprzeczne_obserwacje"] = node.conflicts()
    text = json.dumps(shown, ensure_ascii=False, sort_keys=True) if shown else ""
    if len(text) > MAX_ATTR_CHARS:
        text = text[:MAX_ATTR_CHARS] + " ..."
    return f"<code>{esc(text)}</code>" if text else ""


def _table(headers: list[str], rows: list[list[str]]) -> str:
    head = "".join(f'<th scope="col">{esc(h)}</th>' for h in headers)
    body = "".join("<tr>" + "".join(f"<td>{c}</td>" for c in row) + "</tr>" for row in rows)
    return f'<div class="scroll"><table><thead><tr>{head}</tr></thead><tbody>{body}</tbody></table></div>'


def _edge_row(graph: Graph, e: Edge) -> list[str]:
    return [_node_cell(graph.nodes.get(e.src), e.src), esc(e.relation), _node_cell(graph.nodes.get(e.dst), e.dst),
            f'<span class="conf">{e.confidence:.2f}</span>', esc(e.source), esc(e.timestamp),
            esc(e.evidence) + (f' <span class="muted">[{esc(", ".join(e.evidence_ref))}]</span>' if e.evidence_ref else "")]


def _vault_section(graph: Graph) -> list[str]:
    """Skarbiec dowodów: surowe odpowiedzi źródeł (plik, skrót SHA-256, czas, status). URL jako tekst, bez linku."""
    vault = graph.meta.get("evidence_vault")
    if not isinstance(vault, dict):
        return []
    entries = [e for e in vault.get("entries") or [] if isinstance(e, dict)]
    out = ["<h2>Skarbiec dowodów</h2>",
           f'<p class="muted">Surowe odpowiedzi źródeł w katalogu {esc(vault.get("dir", "evidence"))}/ '
           f"({esc(vault.get('count', len(entries)))}). Skróty SHA-256 są w dzienniku audytu; spójność sprawdza "
           "'eg evidence-verify KATALOG'. Błąd lub limit źródła to dowód próby, nie brak danych.</p>"]
    if not entries:
        out.append('<p class="muted">Brak zapisanych odpowiedzi.</p>')
        return out
    out.append(_table(["Ref", "Czas", "Status HTTP / błąd", "URL", "SHA-256", "Transformacja / węzeł"], [
        [esc(e.get("ref", "")), esc(e.get("fetched_at", "")),
         esc(e.get("status") if e.get("status") is not None else (e.get("error") or "-")),
         f"<code>{esc(e.get('url', ''))}</code>", f"<code>{esc(str(e.get('sha256') or '')[:16])}</code>",
         esc(f"{e.get('transform', '')} / {e.get('node', '')}")] for e in entries[:MAX_EDGE_ROWS]]))
    return out


LINK_SOURCE = "links"


def _source_files(graph: Graph, e: Edge) -> str:
    """Pliki wejściowe (import:<narzędzie>:<plik>), z których pochodzą oba końce krawędzi."""
    found: list[str] = []
    for nid in (e.src, e.dst):
        node = graph.nodes.get(nid)
        for src in (node.sources if node else []):
            if src.startswith("import:"):
                _, tool, name = (src.split(":", 2) + ["", ""])[:3]
                label = f"{name} ({tool})"
                if label not in found:
                    found.append(label)
    return ", ".join(found)


def _links_section(graph: Graph) -> list[str]:
    """Sekcja "Powiązania między źródłami": wejścia (z liczbą SKIPPED/ERROR), scalenia i powiązania wg pewności."""
    imports = graph.meta.get("imports")
    links = sorted((e for e in graph.edges.values() if e.source == LINK_SOURCE), key=lambda x: (-x.confidence, x.relation, x.src))
    if imports is None and not links:
        return []
    imports = imports or []
    counts = Counter(i.get("status", "") for i in imports)
    out = ["<h2>Powiązania między źródłami</h2>",
           '<p class="muted">Łączenie kropek: scalone węzły o tym samym identyfikatorze oraz powiązania z jawnych sygnałów. '
           "Każde powiązanie ma dowód; pewność nie przekracza 0.90. To tropy, nie dowody tożsamości.</p>"]
    if imports:
        out.append(f'<p><strong>Wejścia:</strong> IMPORTED={counts.get("IMPORTED", 0)}, SKIPPED={counts.get("SKIPPED", 0)}, '
                   f'<span class="{"st st-ERROR" if counts.get("ERROR") else ""}">ERROR={counts.get("ERROR", 0)}</span></p>')
        out.append(_table(["Plik", "Format", "Status", "Węzły", "Krawędzie", "Błędy rekordów", "Powód"], [
            [esc(i.get("file", "")), esc(i.get("format") or "-"),
             f'<span class="st st-{esc(i.get("status", ""))}">{esc(i.get("status", ""))}</span>', esc(i.get("nodes", 0)),
             esc(i.get("edges", 0)), esc(i.get("errors", 0)), esc(i.get("reason", ""))] for i in imports]))
    merges = graph.meta.get("merges") or []
    if merges:
        out.append(f"<h3>Scalone węzły ({len(merges)})</h3>")
        out.append(_table(["Zachowany węzeł", "Scalone", "Identyfikator", "Źródła"], [
            [esc(m.get("kept", "")), esc(", ".join(m.get("merged", []))), esc(m.get("identifier", "")),
             esc(", ".join(m.get("sources", [])))] for m in merges]))
    conflicts = graph.meta.get("conflicts") or []
    if conflicts:
        out.append(f"<h3>Konflikty identyfikatorów (nie scalono) ({len(conflicts)})</h3>")
        out.append(_table(["Węzły", "Powód"], [[esc(", ".join(c.get("nodes", []))), esc(c.get("reason", ""))] for c in conflicts]))
    out.append(f"<h3>Powiązania ({len(links)})</h3>")
    out.append(_table(["Od", "Relacja", "Do", "Pewność", "Dowód", "Pliki źródłowe"], [
        [_node_cell(graph.nodes.get(e.src), e.src), esc(e.relation), _node_cell(graph.nodes.get(e.dst), e.dst),
         f'<span class="conf">{e.confidence:.2f}</span>', esc(e.evidence), esc(_source_files(graph, e))]
        for e in links[:MAX_EDGE_ROWS]]) if links else '<p class="muted">Brak powiązań spełniających kryteria.</p>')
    return out


DECISION_PL = {"rozwin": "rozwiń (dalsze zapytania)", "przeglad": "do przeglądu", "zatrzymaj": "zatrzymaj"}


def _expansion_section(graph: Graph) -> list[str]:
    """Rundy rozszerzania: co zapytano, jaka decyzja i dlaczego gałąź rozwinięto albo zatrzymano."""
    rep = graph.meta.get("expansion")
    if not isinstance(rep, dict):
        return []
    seed = rep.get("seed") or {}
    scope = rep.get("scope") or {}
    totals = rep.get("totals") or {}
    out = ["<h2>Rozszerzanie rekordów: rundy i decyzje</h2>",
           '<p class="notice"><strong>Kandydat to hipoteza.</strong> Ocena to poziom dowodów (brak, słabe, umiarkowane, '
           "mocne), nie procent pewności. Każdy kandydat jest porównany z danymi początkowymi, nie z poprzednikiem: "
           "powiązanie A-B i B-C nie potwierdza A-C. Błąd lub brak dostępu do źródła nie oznacza braku rekordu.</p>",
           _table(["Pole", "Wartość"], [
               ["Identyfikator", esc(f"{seed.get('type')}: {seed.get('identifier')}")],
               ["Dane początkowe", esc("; ".join(f"{k}: {v}" for k, v in seed.items()
                                                 if k not in ("identifier", "type") and v)) or "brak"],
               ["Profile kotwicy znalezione / nieznalezione", esc(", ".join(rep.get("anchors_found") or []) or "-")
                + " / " + esc(", ".join(rep.get("anchors_missing") or []) or "-")],
               ["Zakres", esc(f"adaptery: {', '.join(scope.get('adapters') or [])}; automatyczna kontynuacja: "
                              f"{'tak' if scope.get('auto_continue') else 'nie'}; rundy {scope.get('max_rounds')}, "
                              f"zapytania {scope.get('max_queries')}, czas {scope.get('max_seconds')} s, "
                              f"koszt {scope.get('max_cost')}")],
               ["Wykorzystano", esc(f"zapytania {totals.get('queries')}, koszt {totals.get('cost')}, "
                                    f"czas {totals.get('seconds')} s, nierozstrzygnięte zapytania "
                                    f"{totals.get('unresolved_queries')}")],
               ["Dlaczego przebieg się zakończył", esc(rep.get("stop_reason") or "-")],
           ])]
    for rd in rep.get("rounds") or []:
        out.append(f"<h3>Runda {esc(rd.get('round'))}</h3>")
        out.append(_table(["Status", "Adapter", "Identyfikator", "Skąd", "Uwagi"], [
            [f'<span class="st st-{esc(q.get("status"))}">{esc(q.get("status"))}</span>', esc(q.get("adapter")),
             esc(q.get("identifier")), esc(q.get("origin")),
             esc("; ".join(x for x in (q.get("note"), q.get("interpretation")) if x))]
            for q in rd.get("queries") or []]))
        rows = []
        for c in rd.get("candidates") or []:
            decision = c.get("decision") or c.get("role", "")
            details = list(c.get("reasons") or [])
            prev = c.get("previous")
            if isinstance(prev, dict):
                details.insert(0, f"ponowna ocena po nowych obserwacjach; wcześniej: "
                                  f"{DECISION_PL.get(prev.get('decision'), prev.get('decision'))} (runda {prev.get('round')})")
            details += [f"[{s.get('level')}, {s.get('group')}] {s.get('detail')}" for s in c.get("signals") or []]
            details += [f"[sprzeczność{', twarda' if x.get('hard') else ''}] {x.get('detail')}"
                        for x in c.get("contradictions") or []]
            rows.append([esc(DECISION_PL.get(decision, decision)), esc(c.get("level", "-")),
                         _link(c.get("profile", "")), "<br>".join(esc(d) for d in details)])
        if rows:
            out.append(_table(["Decyzja", "Dowody", "Kandydat", "Uzasadnienie"], rows))
        extra = [[esc(f.get("identifier")), esc(f.get("from")), esc(f.get("status"))] for f in rd.get("followups") or []]
        if extra:
            out.append(_table(["Kolejny identyfikator", "Z kandydata", "Status"], extra))
        skipped = [[esc(x.get("profile") or x.get("identifier")), esc(x.get("why"))] for x in rd.get("skipped") or []]
        if skipped:
            out.append(_table(["Pominięto", "Dlaczego"], skipped))
    held = rep.get("held") or []
    if held:
        out.append("<h3>Wstrzymane rozwinięcia (kandydat stracił decyzję \"rozwiń\" po nowych obserwacjach)</h3>")
        out.append(_table(["Identyfikator", "Z kandydata", "Runda"],
                          [[esc(x.get("identifier")), esc(x.get("origin")), esc(x.get("round"))] for x in held]))
    pending = rep.get("pending") or []
    if pending:
        out.append("<h3>Niewykonane propozycje (czekają na decyzję lub większy limit)</h3>")
        out.append(_table(["Identyfikator", "Z kandydata", "Uwagi"],
                          [[esc(x.get("identifier")), esc(x.get("origin")), esc(x.get("held", ""))] for x in pending]))
    return out


def _source_cell(ref: dict) -> str:
    if ref.get("kind") == "url":
        return _link(str(ref.get("ref", "")))
    return esc(f"dokument sprawy: {ref.get('ref', '')} (SHA-256 {str(ref.get('sha256', ''))[:16]}, "
               f"{ref.get('bytes', '?')} B)")


def _claims_section(graph: Graph) -> list[str]:
    """Twierdzenia o relacjach: kto, jaka relacja, status, pewność, źródła i decyzja operatora."""
    items = relacje.claims(graph)
    if not items:
        return []
    out = ["<h2>Twierdzenia o relacjach (wprowadzone przez operatora)</h2>",
           '<p class="notice"><strong>Twierdzenie o relacji to zapis informacji ze wskazanego źródła, nie ustalenie '
           "narzędzia.</strong> Narzędzie nie szuka relacji: wspólne nazwisko, adres, numer, zdjęcie ani podobne profile "
           "nie tworzą twierdzeń. Status \"oczekuje\" znaczy: wymaga potwierdzenia. Potwierdzenie to ocena człowieka "
           "(pewność 0.90) z osobnym uzasadnieniem, nie dowód pokrewieństwa ani tożsamości.</p>"]
    rows = []
    for c in items:
        a, b = graph.nodes.get(c.get("src")), graph.nodes.get(c.get("dst"))
        sources = "<br>".join(
            _source_cell(s.get("source") or {}) + "<br>" + esc(f"dowód: {s.get('evidence', '')}")
            + (f"<br>{esc('fragment: ' + str(s.get('excerpt')))}" if s.get("excerpt") else "")
            + f' <span class="muted">({esc(s.get("added_at", ""))})</span>'
            for s in c.get("sources") or [] if isinstance(s, dict))
        decision = esc(c.get("status", ""))
        if c.get("decision_evidence"):
            decision += "<br>" + esc(f"{c['decision_evidence']} ({c.get('decided_at', '')}, {c.get('decided_by', '')})")
        rows.append([esc(c.get("id", "")), _node_cell(a, str(c.get("src"))), esc(relacje.describe(c)),
                     _node_cell(b, str(c.get("dst"))), decision,
                     f'<span class="conf">{float(c.get("confidence") or 0):.2f}</span>', sources,
                     esc(c.get("purpose", "")), esc(c.get("created_at", ""))])
    out.append(_table(["Id", "Osoba A", "Relacja (A wobec B)", "Osoba B", "Decyzja operatora", "Pewność",
                       "Źródła i dowód", "Cel sprawy", "Zapisano"], rows))
    conflicts = relacje.contradictions(graph)
    if conflicts:
        out.append("<h3>Sprzeczne twierdzenia do wyjaśnienia</h3><ul>"
                   + "".join(f"<li>{esc(x)}</li>" for x in conflicts) + "</ul>")
    return out


def _phones_section(graph: Graph) -> list[str]:
    """Kontekst numerów z planu numeracyjnego: pola, konflikty obserwacji, źródła i czas obserwacji."""
    phones = [n for n in graph.nodes_of_type(EntityType.PHONE) if any(k.startswith("phone_") for k in n.attrs)]
    if not phones:
        return []
    out = ["<h2>Kontekst numerów telefonu (plan numeracyjny)</h2>",
           '<p class="notice">Region planu numeracyjnego to obszar, któremu przydzielono pulę numerów, a nie miejsce '
           "urządzenia ani osoby. Dla numeru komórkowego to tylko kraj planu; kierunkowy numeru stacjonarnego też nie "
           "mówi, gdzie jest urządzenie. Operator z planu to pierwotny przydział (numer mógł zostać przeniesiony). "
           "Numer nie jest wiązany z osobą.</p>"]
    for n in phones:
        ctx = telefon.context(n)
        out.append(f"<h3>{esc(n.value)}</h3>")
        rows = [[esc(f["label"]), esc(f["value"])] for f in ctx["fields"]]
        if ctx["manual_check_url"]:
            rows.append([esc("ręczna weryfikacja aktualnego operatora (otwierasz sam)"), _link(ctx["manual_check_url"])])
        rows.append([esc("powiązanie z osobą"), esc(ctx["linked_person"])])
        out.append(_table(["Pole", "Wartość"], rows))
        if ctx["conflicts"]:
            out.append("<p><strong>Konflikt obserwacji (pole nieznane, nie rozstrzygamy):</strong></p><ul>"
                       + "".join(f"<li>{esc(c)}</li>" for c in ctx["conflicts"]) + "</ul>")
        if ctx["log"]:
            out.append(_table(["Rodzaj", "Źródło obserwacji", "Czas obserwacji", "Data weryfikacji", "Referencja"], [
                [esc("plan numeracji (phone-check)" if x.get("kind") == "plan" else "ręczna weryfikacja"),
                 esc(x.get("source", "")), esc(x.get("observed_at", "")), esc(x.get("verified_on", "") or "-"),
                 _source_cell(x["reference"]) if isinstance(x.get("reference"), dict) else "-"] for x in ctx["log"]]))
    return out


def _profile_rounds_section(graph: Graph) -> list[str]:
    """Rundy kandydatów profili w sprawie (eg kandydaci): zapytania ze statusami, kandydaci z oceną, propozycje."""
    rounds = [r for r in graph.meta.get("profile_rounds") or [] if isinstance(r, dict)]
    if not rounds:
        return []
    out = ["<h2>Kandydaci profili: rundy (wymagają potwierdzenia)</h2>",
           '<p class="notice">Kandydat profilu to hipoteza. Ocena opisuje wyłącznie techniczne dopasowanie profilu do '
           "danych początkowych; sama nazwa użytkownika, imię i nazwisko, awatar albo serwis nie łączą profilu z osobą. "
           "NOT_FOUND, UNKNOWN i ERROR mówią o źródle, nie o osobie. Profil łączy z osobą tylko decyzja operatora; "
           "propozycje kolejnej rundy nie zostały wykonane.</p>"]
    for r in rounds:
        entry, totals, scope = r.get("entry") or {}, r.get("totals") or {}, r.get("scope") or {}
        out.append(f"<h3>Runda {esc(r.get('round'))}: {esc(entry.get('type'))} {esc(entry.get('value'))} "
                   f'<span class="muted">({esc(r.get("started", ""))})</span></h3>')
        out.append(_table(["Budżet", "Wykorzystano", "Koniec"], [[
            esc(f"zapytania {scope.get('max_queries')}, koszt {scope.get('max_cost')}, czas {scope.get('max_seconds')} s"),
            esc(f"zapytania {totals.get('queries')}, koszt {totals.get('cost')}, czas {totals.get('seconds')} s"),
            esc(r.get("stop_reason", ""))]]))
        out.append(_table(["Status źródła", "Nazwa", "Uwagi"], [
            [f'<span class="st st-{esc(q.get("status"))}">{esc(q.get("status"))}</span>', esc(q.get("identifier")),
             esc("; ".join(x for x in (q.get("note"), q.get("interpretation")) if x))]
            for q in r.get("queries") or []] + [
            [esc("pominięto"), esc(s.get("identifier")), esc(s.get("why"))] for s in r.get("skipped") or []]))
        cands = r.get("candidates") or []
        if cands:
            out.append(_table(["Ocena dopasowania", "Dowody", "Kandydat", "Uzasadnienie"], [
                [esc(DECISION_PL.get(c.get("decision"), c.get("decision"))), esc(c.get("level", "-")),
                 _link(str(c.get("profile", ""))), "<br>".join(esc(x) for x in c.get("reasons") or [])] for c in cands]))
        props = r.get("proposals") or []
        if props:
            out.append(_table(["Propozycja kolejnej rundy (niewykonana)", "Z kandydata"],
                              [[esc(p.get("identifier")), esc(p.get("from"))] for p in props]))
    return out


def _discovery_section(graph: Graph) -> list[str]:
    """Wyszukiwanie profili po nazwisku (eg szukaj-profili / material-profilu): przebiegi i karty kandydatów."""
    from .profile_discovery import summary
    view = summary(graph)
    if not view["items"] and not view["runs"]:
        return []
    out = ["<h2>Wyszukiwanie profili po nazwisku (kandydaci wymagają decyzji)</h2>",
           '<p class="notice">Źródło automatyczne: Brave Search API (fragmenty wyników, nie odczyt profili). Wynik '
           "wyszukiwarki i nazwa serwisu nie dowodzą, że adres jest kontem tej osoby; zgodność nazwy niczego nie "
           "potwierdza. Zero wyników zapytania nie oznacza braku kont. Materiał operatora to tekst przez niego "
           "dostarczony, nie zweryfikowana kopia strony. Profil łączy z osobą wyłącznie decyzja operatora.</p>"]
    if view.get("error"):
        out.append(f"<p>{esc(view['error'])}</p>")
    for r in view["runs"]:
        t = r.get("totals") or {}
        out.append(f"<h3>Przebieg {esc(r.get('number'))}: {esc(r.get('person'))} "
                   f'<span class="muted">({esc(r.get("started", ""))}; {esc(r.get("channel", ""))})</span></h3>')
        out.append(_table(["Budżet", "Wykorzystano", "Koniec"], [[
            esc(", ".join(f"{k} {v}" for k, v in (r.get("limits") or {}).items())),
            esc(f"wywołania {t.get('calls')}, kandydaci {t.get('candidates_seen')}, odrzucone adresy "
                f"{t.get('discarded')}, czas {t.get('seconds')} s"),
            esc(r.get("stop_reason", "") + (" (wynik częściowy)" if r.get("partial") else ""))]]))
        out.append(_table(["Status źródła", "Zapytanie", "Przyczyna", "Wyniki / przyjęte / wywołania"], [
            [f'<span class="st st-{esc(q.get("status"))}">{esc(q.get("status"))}</span>', esc(q.get("query")),
             esc(q.get("reason")), esc(f"{q.get('results')} / {q.get('accepted')} / {q.get('attempts')}")]
            for q in r.get("queries") or []] + [
            [esc("pominięto"), esc(q.get("query")), esc(q.get("why")), "-"] for q in r.get("skipped") or []]))
    rows = []
    for c in view["items"]:
        obs = "<br>".join(
            f"{esc(o.get('kind_label'))}: {esc(o.get('acquired_at'))}"
            + (f" · zapytanie {esc(o.get('query'))}" if o.get("query") else "")
            + (f"<br><q>{esc(o.get('excerpt'))}</q> <span class=\"muted\">(fragment zapisany przed R5A)</span>"
               if o.get("excerpt") else "")
            + "".join(f"<br>pominięto {esc(s.get('what'))} ({esc(s.get('count'))}): {esc(s.get('why'))}"
                      for s in o.get("skipped") or [])
            for o in c["observations"])
        found = "<br>".join(f"{esc(f.get('kind'))}: {esc(f.get('value'))} <q>{esc(f.get('evidence'))}</q> "
                            f'<span class="muted">({esc(f.get("method"))}, {esc(f.get("observed_at"))})</span>'
                            for o in c["observations"] for f in o.get("findings") or [])
        rows.append([esc(c.get("person")), _link(str(c.get("url") or "")),
                     esc(f"{c.get('platform')} / {c.get('url_class')}"),
                     obs or "-", found or esc(c.get("analysis_status")), esc(c.get("assessment")),
                     esc(c.get("decision"))])
    if rows:
        out.append('<p class="muted">Tekst materiału nie jest zapisywany: karta pokazuje pochodzenie, skrót i ustalenia '
                   "z dosłownym dowodem. Ocena i decyzja dotyczą osoby z pierwszej kolumny.</p>")
        out.append(_table(["Osoba", "Adres", "Serwis / klasa adresu", "Pochodzenie",
                           "Ustalenia z dowodem", "Ocena dopasowania", "Decyzja operatora"], rows))
    return out


def render_html(graph: Graph) -> str:
    meta = graph.meta
    by_type = Counter(n.type for n in graph.nodes.values())
    by_status = Counter(r.status for r in graph.runs)
    out = [
        '<!doctype html><html lang="pl"><head><meta charset="utf-8">',
        '<meta name="viewport" content="width=device-width,initial-scale=1">',
        '<meta http-equiv="Content-Security-Policy" content="default-src \'none\'; style-src \'unsafe-inline\'">',
        '<meta name="referrer" content="no-referrer"><title>Raport entity-graph</title>',
        f"<style>{CSS}</style></head><body><main>",
        "<h1>Raport badania entity-graph</h1>",
        f'<p class="muted">narzędzie entity-graph {esc(__version__)}; raport statyczny, bez skryptów</p>',
        "<h2>Cel i zakres badania</h2>",
        _table(["Pole", "Wartość"], [
            ["Cel (purpose)", esc(meta.get("purpose", ""))], ["Operator", esc(meta.get("operator", ""))],
            ["Sygnatura sprawy", esc(meta.get("case_ref", "")) or "-"], ["Start", esc(meta.get("started", ""))],
            ["Wejścia", esc("; ".join(f"{i.get('type')}: {i.get('value')}" for i in meta.get("inputs", [])))],
            ["Ograniczenia przebiegu", esc(meta.get("truncated", "")) or "brak"],
        ]),
        '<p class="notice"><strong>Trafienie to trop, nie dowód.</strong> Ta sama nazwa lub awatar nie oznacza tej samej '
        "osoby. Pewność krawędzi (0-1) nigdy nie przekracza dowodu opisanego w jej uzasadnieniu. "
        "Dane osobowe: przechowuj tylko tak długo i w takim zakresie, jak wymaga cel badania.</p>",
        "<h2>Podsumowanie</h2>",
        _table(["Rodzaj", "Liczba"], [[esc(LABELS_PL[t]), str(by_type.get(t, 0))] for t in EntityType]
               + [["Krawędzie", str(len(graph.edges))]]
               + [[f"Uruchomienia: {s.value}", str(by_status.get(s, 0))] for s in Status]),
        "<h2>Uruchomienia transformacji</h2>",
        '<p class="muted">NOT_FOUND = źródło jawnie odpowiedziało, że nic nie ma. UNKNOWN = nie sprawdzono lub nie '
        "da się rozstrzygnąć. ERROR = błąd, blokada lub limit (nie oznacza braku danych).</p>",
        _table(["Status", "Transformacja", "Węzeł", "Czas", "Uwagi"], [
            [f'<span class="st st-{r.status.value}">{r.status.value}</span>', esc(r.transform), esc(r.node_id),
             esc(r.timestamp), esc(r.error or r.note)] for r in graph.runs]),
    ]
    out += _links_section(graph)
    out += _expansion_section(graph)
    out += _vault_section(graph)
    out += _claims_section(graph)
    out += _phones_section(graph)
    out += _profile_rounds_section(graph)
    out += _discovery_section(graph)
    same = [e for e in graph.edges.values() if e.relation == "same_person"]
    out.append('<h2>Powiązania "ta sama osoba" (tylko z jawnych sygnałów)</h2>')
    out.append(_table(["Profil A", "Profil B", "Pewność", "Dowody"], [
        [_node_cell(graph.nodes.get(e.src), e.src), _node_cell(graph.nodes.get(e.dst), e.dst),
         f'<span class="conf">{e.confidence:.2f}</span>', esc(e.evidence)] for e in sorted(
            same, key=lambda x: -x.confidence)]) if same else '<p class="muted">Brak powiązań spełniających kryteria.</p>')
    for person in graph.nodes_of_type(EntityType.PERSON):
        d = teczka.dossier(graph, person)
        if not (d["confirmed"] or d["rejected"]):
            continue
        out.append(f"<h2>Teczka osoby: {esc(person.value)}</h2>")
        out.append('<p class="notice">Profile potwierdził lub odrzucił operator (ocena człowieka z dowodem w dzienniku '
                   "audytu). Dane poniżej są połączone z osobą wyłącznie przez potwierdzone profile.</p>")
        out.append(_table(["Decyzja", "Profil", "Uzasadnienie"], [
            [esc("potwierdzony" if e.relation == teczka.CONFIRMED else "odrzucony"), _node_cell(n, n.value),
             esc(e.evidence)] for n, e in d["confirmed"] + d["rejected"]]))
        if d["data"]:
            out.append(_table(["Rodzaj", "Wartość", "Pewność", "Skąd"], [
                [esc(LABELS_PL[n.type]), _node_cell(n, n.value), f'<span class="conf">{e.confidence:.2f}</span>',
                 esc(e.evidence)] for n, e in d["data"]]))
    reviews = [(n, link) for n in graph.nodes.values() for link in n.attrs.get("manual_review_links") or []
               if isinstance(link, dict)]
    if reviews:
        out.append("<h2>Linki do ręcznego przeglądu (nic nie zostało wysłane)</h2>")
        out.append(_table(["Rekord", "Wyszukiwarka / serwis", "Rodzaj", "Zapytanie"], [
            [esc(n.value), esc(link.get("engine", "")), esc(link.get("label", "")),
             _link(str(link.get("url", "")), str(link.get("query", "")))] for n, link in reviews]))
    out.append("<h2>Węzły</h2>")
    for etype in EntityType:
        nodes = graph.nodes_of_type(etype)
        if not nodes:
            continue
        out.append(f"<h3>{esc(LABELS_PL[etype])} ({len(nodes)})</h3>")
        out.append(_table(["Wartość", "Źródła", "Atrybuty"], [
            [_node_cell(n, n.value), esc(", ".join(n.sources)), _attrs_cell(n)] for n in nodes]))
    edges = sorted(graph.edges.values(), key=lambda e: (-e.confidence, e.relation, e.src))
    out.append(f"<h2>Krawędzie ({len(edges)})</h2>")
    out.append(_table(["Od", "Relacja", "Do", "Pewność", "Źródło", "Czas", "Dowód"],
                      [_edge_row(graph, e) for e in edges[:MAX_EDGE_ROWS]]))
    if len(edges) > MAX_EDGE_ROWS:
        out.append(f'<p class="muted">Pokazano {MAX_EDGE_ROWS} z {len(edges)} krawędzi; pełne dane w graph.json.</p>')
    out.append("<h2>Czego narzędzie nie robi</h2><ul>" + "".join(f"<li>{esc(x)}</li>" for x in EXCLUDED_CAPABILITIES) + "</ul>")
    out.append("</main></body></html>")
    return "\n".join(out)
