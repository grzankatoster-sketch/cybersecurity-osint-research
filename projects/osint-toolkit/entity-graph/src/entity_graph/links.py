"""Łączenie kropek między źródłami: scalanie węzłów o tym samym identyfikatorze i powiązania z jawnych sygnałów.

Każda krawędź ma tekst dowodu, a pewność wynika z siły dowodu i NIGDY nie przekracza MAX_CONFIDENCE (0.9) ani pewności
konta, z którego sygnał pochodzi. Powiązanie to trop, nie dowód tożsamości.

Scalanie (merge_identifiers): firmy o tym samym NIP, KRS albo REGON (9 cyfr = pierwsze 9 cyfr REGON-u 14-cyfrowego) oraz
wycieki o tej samej nazwie. Konflikt identyfikatorów (różne NIP albo KRS w jednej grupie) NIE scala: jest zapisany w
graph.meta["conflicts"]. Pozostałe identyfikatory (e-mail, domena IDNA, telefon E.164, nazwa użytkownika, URL) scalają się
już przy tworzeniu węzła, bo mają ten sam klucz po normalizacji.

Reguły powiązań (connect):
  * e-mail <-> domena z adresu (mailbox_at), gdy domena jest w grafie
  * e-mail <-> organizacja, gdy domena adresu = strona www organizacji (np. z KRS)
  * dwie domeny na tym samym IP (shares_ip), z tym samym NS (shares_nameserver) albo w tym samym ASN (shares_asn)
  * profil (konto) wskazuje w linkach/bio domenę obecną w grafie (links_to_domain)
  * ten sam rachunek bankowy (IBAN) u dwóch różnych organizacji (shares_bank_account)
Szeroko współdzielone zasoby (wspólny hosting, duży dostawca DNS) osłabiają dowód: powyżej MAX_FANOUT nie łączymy."""
from __future__ import annotations

from collections import defaultdict
from itertools import combinations

from .correlate import PLATFORM_HOSTS, _host, account_confidence, is_profile
from .identifiers import normalize_iban, normalize_krs, normalize_nip, normalize_regon, regon_core
from .model import Edge, Graph, Node, utc_now
from .normalize import EntityType
from .transforms.base import GENERIC_MAIL_PROVIDERS

SOURCE = "links"
MAX_CONFIDENCE = 0.9
MAX_FANOUT = 25
INFRA_KINDS = frozenset({"ns_host", "mx_host"})



# ------------------------------------------------------------------ scalanie po identyfikatorach

def _org_idents(node: Node) -> dict[str, str]:
    a = node.attrs
    out = {}
    if normalize_nip(a.get("nip")):
        out["nip"] = normalize_nip(a.get("nip"))
    if regon_core(normalize_regon(a.get("regon"))):
        out["regon"] = regon_core(normalize_regon(a.get("regon")))
    if normalize_krs(a.get("krs")):
        out["krs"] = normalize_krs(a.get("krs"))
    return out


def _is_breach(node: Node) -> bool:
    return node.type is EntityType.ORGANIZATION and node.attrs.get("kind") == "breach"


def merge_identifiers(graph: Graph) -> list[dict]:
    """Scala firmy (NIP/KRS/REGON) i wycieki (nazwa) pochodzące z różnych źródeł. -> lista opisów scaleń (też w meta)."""
    parent: dict[str, str] = {}

    def find(x: str) -> str:
        parent.setdefault(x, x)
        while parent[x] != x:
            parent[x] = parent[parent[x]]
            x = parent[x]
        return x

    def union(a: str, b: str) -> None:
        parent[find(a)] = find(b)

    idents: dict[str, dict[str, str]] = {}
    for node in graph.nodes_of_type(EntityType.ORGANIZATION):
        if _is_breach(node):
            bn = str(node.attrs.get("breach_name") or "").strip().casefold()
            keys = {"breach": bn} if bn else {}
        else:
            keys = _org_idents(node)
        if not keys:
            continue
        idents[node.id] = keys
        find(node.id)
        for kind, value in keys.items():
            union(node.id, f"{kind}:{value}")

    groups: dict[str, list[str]] = defaultdict(list)
    for nid in idents:
        groups[find(nid)].append(nid)
    merges: list[dict] = []
    conflicts = graph.meta.setdefault("conflicts", [])
    for members in groups.values():
        if len(members) < 2:
            continue
        clash = [k for k in ("nip", "krs") if len({idents[m][k] for m in members if k in idents[m]}) > 1]
        if clash:
            conflicts.append({"nodes": sorted(members), "reason": "różne wartości " + ", ".join(clash).upper()
                              + " w grupie węzłów o wspólnym innym identyfikatorze: nie scalono"})
            continue
        members.sort(key=lambda m: (-len(idents[m]), m))
        keep, rest = members[0], members[1:]
        shared = sorted({f"{k.upper()} {v}" for m in members for k, v in idents[m].items()
                         if sum(1 for x in members if idents[x].get(k) == v) > 1})
        sources = sorted({s for m in members for s in graph.nodes[m].sources})
        aliases = [graph.nodes[m].value for m in rest]
        for drop in rest:
            graph.merge_into(keep, drop)
        node = graph.nodes[keep]
        if aliases and not _is_breach(node):
            node.attrs["aliases"] = list(dict.fromkeys([*node.attrs.get("aliases", []), *aliases]))[:20]
        merges.append({"kept": keep, "merged": sorted(rest), "identifier": ", ".join(shared) or "wspólny identyfikator",
                       "sources": sources,
                       "evidence": f"ten sam identyfikator ({', '.join(shared)}) w {len(sources)} źródłach"})
    if not conflicts:
        graph.meta.pop("conflicts", None)
    graph.meta["merges"] = [*graph.meta.get("merges", []), *merges]
    return merges


# ------------------------------------------------------------------ reguły powiązań

def _edge(graph: Graph, a: Node, b: Node, relation: str, conf: float, evidence: str, now: str,
          out: list[Edge], undirected: bool = False, limit: float = MAX_CONFIDENCE) -> None:
    """`limit` > MAX_CONFIDENCE tylko dla faktu wynikającego wprost ze składni (adres e-mail zawiera domenę)."""
    if undirected and a.id > b.id:
        a, b = b, a
    e = graph.add_edge(Edge(a.id, b.id, relation, SOURCE, round(max(0.0, min(limit, conf)), 3), evidence, now))
    if e:
        out.append(e)


def _website_domains(graph: Graph) -> dict[str, list[tuple[Node, float, str]]]:
    """domena -> [(organizacja, pewność deklaracji strony, skąd)] z krawędzi has_website i atrybutu website."""
    out: dict[str, list[tuple[Node, float, str]]] = defaultdict(list)
    for e in graph.edges.values():
        if e.relation != "has_website":
            continue
        org, dom = graph.nodes.get(e.src), graph.nodes.get(e.dst)
        if org and dom and org.type is EntityType.ORGANIZATION and dom.type is EntityType.DOMAIN:
            out[dom.key].append((org, e.confidence, e.source))
    for org in graph.nodes_of_type(EntityType.ORGANIZATION):
        site = org.attrs.get("website")
        host = _host(site) if isinstance(site, str) and site else None
        if host and all(o.id != org.id for o, _, _ in out[host]):
            out[host].append((org, 0.6, "atrybut website"))
    return out


def link_emails(graph: Graph, now: str) -> list[Edge]:
    out: list[Edge] = []
    sites = _website_domains(graph)
    for email in graph.nodes_of_type(EntityType.EMAIL):
        host = email.key.rsplit("@", 1)[1]
        if host in GENERIC_MAIL_PROVIDERS:
            continue
        dom = graph.nodes.get(f"{EntityType.DOMAIN.value}:{host}")
        if dom is not None:
            _edge(graph, email, dom, "mailbox_at", 1.0, "adres e-mail zawiera tę domenę (domena występuje w grafie)", now, out,
                  limit=1.0)
        for site_host, orgs in sites.items():
            exact = host == site_host
            if not (exact or host.endswith("." + site_host)):
                continue
            for org, site_conf, origin in orgs:
                conf = site_conf * (0.85 if exact else 0.6)
                what = "jest taka sama jak domena strony www" if exact else "jest subdomeną domeny strony www"
                _edge(graph, email, org, "email_matches_org_domain", conf,
                      f"domena adresu {email.value} ({host}) {what} organizacji {org.value} "
                      f"({site_host}; deklaracja: {origin}, pewność {site_conf:.2f}). Wspólna domena nie dowodzi, "
                      "że skrzynka należy do tej organizacji ani do konkretnej osoby", now, out)
    return out


def _domain_nodes(graph: Graph, ids: set[str]) -> list[Node]:
    return sorted((graph.nodes[i] for i in ids if i in graph.nodes), key=lambda n: n.id)


def link_infrastructure(graph: Graph, now: str) -> list[Edge]:
    out: list[Edge] = []
    by_ip: dict[str, set[str]] = defaultdict(set)
    by_ns: dict[str, set[str]] = defaultdict(set)
    ns_of: dict[str, set[str]] = defaultdict(set)
    ips_of: dict[str, set[str]] = defaultdict(set)
    for e in graph.edges.values():
        src, dst = graph.nodes.get(e.src), graph.nodes.get(e.dst)
        if src is None or dst is None or src.type is not EntityType.DOMAIN:
            continue
        if e.relation == "resolves_to" and dst.type is EntityType.IP:
            by_ip[dst.id].add(src.id)
            ips_of[src.id].add(dst.id)
        elif e.relation == "nameserver" and dst.type is EntityType.DOMAIN:
            by_ns[dst.id].add(src.id)
            ns_of[src.id].add(dst.id)
    ip_pairs: set[tuple[str, str]] = set()
    for ip_id, ids in by_ip.items():
        if not 2 <= len(ids) <= MAX_FANOUT:
            continue
        for a, b in combinations(_domain_nodes(graph, ids), 2):
            ip_pairs.add((a.id, b.id))
            _edge(graph, a, b, "shares_ip", 0.5 - 0.02 * (len(ids) - 2),
                  f"obie domeny rozwiązują się na ten sam adres IP {graph.nodes[ip_id].value} ({len(ids)} domen w grafie "
                  "na tym adresie). Wspólny hosting nie dowodzi wspólnego właściciela", now, out, undirected=True)
    seen_ns: set[tuple[str, str]] = set()
    for ns_id, ids in by_ns.items():
        if not 2 <= len(ids) <= MAX_FANOUT:
            continue
        for a, b in combinations(_domain_nodes(graph, ids), 2):
            if (a.id, b.id) in seen_ns:
                continue
            seen_ns.add((a.id, b.id))
            shared = ns_of[a.id] & ns_of[b.id]
            fan = max(len(by_ns[s]) for s in shared)
            conf = min(0.4, 0.15 * len(shared)) * (0.5 if fan > 5 else 1.0)
            names = ", ".join(sorted(graph.nodes[s].value for s in shared))
            _edge(graph, a, b, "shares_nameserver", conf,
                  f"domeny mają wspólny serwer nazw: {names} (do {fan} domen w grafie). Duży dostawca DNS obsługuje "
                  "wielu niepowiązanych klientów: bardzo słaby dowód", now, out, undirected=True)
    asn_of_ip: dict[str, set[str]] = defaultdict(set)
    for e in graph.edges.values():
        if e.relation == "announced_by" and e.src in graph.nodes and e.dst in graph.nodes:
            asn_of_ip[e.src].add(e.dst)
    asn_of: dict[str, set[str]] = {dom_id: {a for ip in ips for a in asn_of_ip.get(ip, ())}
                                   for dom_id, ips in ips_of.items()}
    by_asn: dict[str, set[str]] = defaultdict(set)
    for dom_id, asns in asn_of.items():
        for asn in asns:
            by_asn[asn].add(dom_id)
    for asn_id, ids in by_asn.items():
        if not 2 <= len(ids) <= MAX_FANOUT:
            continue
        for a, b in combinations(_domain_nodes(graph, ids), 2):
            if (a.id, b.id) in ip_pairs:
                continue
            _edge(graph, a, b, "shares_asn", 0.15,
                  f"adresy IP obu domen są ogłaszane przez ten sam ASN ({graph.nodes[asn_id].value}). "
                  "Ten sam operator sieci to najsłabszy z sygnałów infrastruktury", now, out, undirected=True)
    return out


def link_profiles_to_domains(graph: Graph, now: str) -> list[Edge]:
    out: list[Edge] = []
    domains = {n.key: n for n in graph.nodes_of_type(EntityType.DOMAIN)}
    for prof in graph.nodes_of_type(EntityType.URL):
        if not is_profile(prof):
            continue
        urls = [*(prof.attrs.get("links") or []), *([prof.attrs["website"]] if prof.attrs.get("website") else [])]
        account_conf = account_confidence(graph, prof)
        for raw in urls:
            host = _host(str(raw))
            if not host or any(host == p or host.endswith("." + p) for p in PLATFORM_HOSTS):
                continue
            dom = domains.get(host)
            if dom is None:
                continue
            base = 0.6 if account_conf is None else min(0.6, account_conf)
            _edge(graph, prof, dom, "links_to_domain", base,
                  f"profil {prof.attrs.get('site') or prof.value} wskazuje w linkach/bio stronę {host}. Link to deklaracja "
                  "właściciela konta; pewność nie przekracza pewności samego konta", now, out)
    return out


def link_bank_accounts(graph: Graph, now: str) -> list[Edge]:
    out: list[Edge] = []
    owners: dict[str, list[Node]] = defaultdict(list)
    for org in graph.nodes_of_type(EntityType.ORGANIZATION):
        for raw in org.attrs.get("bank_accounts") or []:
            iban = normalize_iban(raw)
            if iban and org not in owners[iban]:
                owners[iban].append(org)
    for iban, orgs in owners.items():
        if not 2 <= len(orgs) <= MAX_FANOUT:
            continue
        for a, b in combinations(sorted(orgs, key=lambda n: n.id), 2):
            _edge(graph, a, b, "shares_bank_account", 0.7,
                  f"ten sam rachunek bankowy (IBAN ...{iban[-6:]}) w danych obu organizacji. Rachunek może być wspólny "
                  "(księgowość, rachunek zbiorczy): nie dowodzi tożsamości podmiotów", now, out, undirected=True)
    return out


def connect(graph: Graph, now: str | None = None) -> list[Edge]:
    """Dodaje krawędzie powiązań (source=links) z jawnych sygnałów. Idempotentne."""
    now = now or utc_now()
    created = [*link_emails(graph, now), *link_infrastructure(graph, now), *link_profiles_to_domains(graph, now),
               *link_bank_accounts(graph, now)]
    graph.meta["links_summary"] = {"edges": sum(1 for e in graph.edges.values() if e.source == SOURCE),
                                   "merges": len(graph.meta.get("merges", []))}
    return created
