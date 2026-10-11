"""Import wyniku hibp-monitor (JSON): `breaches --domain --json` (monitor domen), `domain-search --json` (płatne API,
domena zweryfikowana przez właściciela) oraz lista wycieków (pola API HIBP albo ze skryptu). Węzły: Domain, Email
i Breach (Organization, kind=breach; ten sam klucz co transformacja `email_hibp`: tytuł wycieku, a bez niego nazwa).
Katalog wszystkich wycieków (`breaches --catalog`) nie dotyczy badanych celów: plik jest pomijany."""
from __future__ import annotations

from ..model import Node, Status
from ..normalize import EntityType
from .base import ImportCtx, Imported, failed, skipped

TOOL = "hibp-monitor"
MAX_BREACHES = 500
MAX_ADDRESSES = 2000


def kind_of(data) -> str | None:
    if isinstance(data, dict):
        if isinstance(data.get("domains"), list) and all(isinstance(d, dict) and "domain" in d for d in data["domains"]):
            return "monitor"
        if "per_breach" in data and "domain" in data:
            return "domain_search"
        if isinstance(data.get("breaches"), list) and "total" in data:
            return "catalog"
    if isinstance(data, list) and data and all(isinstance(x, dict) for x in data):
        if all(("Name" in x) or ("name" in x and "breach_date" in x) for x in data):
            return "breach_list"
    return None


def _pick(d: dict, *keys: str, default=""):
    for k in keys:
        if d.get(k) not in (None, ""):
            return d[k]
    return default


def breach_node(ctx: ImportCtx, b: dict) -> Node | None:
    name = str(_pick(b, "Name", "name"))
    title = str(_pick(b, "Title", "title")) or name
    if not (name or title):
        return None
    classes = _pick(b, "DataClasses", "data_classes", default=[])
    count = _pick(b, "PwnCount", "pwn_count", default=0)
    attrs = {
        "kind": "breach", "breach_name": name, "breach_date": str(_pick(b, "BreachDate", "breach_date")),
        "added_date": str(_pick(b, "AddedDate", "added_date")),
        "pwn_count": count if isinstance(count, int) and not isinstance(count, bool) else 0,
        "data_classes": [str(c)[:60] for c in classes][:30] if isinstance(classes, list) else [],
        "is_verified": bool(_pick(b, "IsVerified", "is_verified", default=False)),
        "is_sensitive": bool(_pick(b, "IsSensitive", "is_sensitive", default=False)),
    }
    try:
        return ctx.node(EntityType.ORGANIZATION, title, {k: v for k, v in attrs.items() if v not in ("", [], 0, False)})
    except ValueError:
        return None


def _domain(ctx: ImportCtx, raw) -> Node | None:
    try:
        return ctx.node(EntityType.DOMAIN, str(raw))
    except ValueError:
        return None


def _breach_edges(ctx: ImportCtx, imp: Imported, breaches: list, domain: Node | None, label: str) -> int:
    n = 0
    for b in breaches[:MAX_BREACHES]:
        if not isinstance(b, dict):
            continue
        node = breach_node(ctx, b)
        if node is None:
            continue
        imp.nodes.append(node)
        n += 1
        host = domain
        raw_domain = _pick(b, "Domain", "domain")
        own = _domain(ctx, raw_domain) if raw_domain else None
        if own is not None:
            imp.nodes.append(own)
            host = own
        if host is not None:
            imp.edges.append(ctx.edge("", node, host, "breached_service", 0.9,
                                      f"hibp-monitor: wyciek {node.attrs.get('breach_name') or node.value} dotyczy serwisu "
                                      f"na domenie {host.value} ({label})"))
    return n


def parse(data, ctx: ImportCtx) -> Imported:
    kind = kind_of(data)
    if kind == "catalog":
        return skipped(TOOL, "katalog wszystkich wycieków HIBP: nie dotyczy badanych celów (użyj wyniku dla domeny)")
    if kind is None:
        return failed(TOOL, "nierozpoznany układ pliku hibp-monitor")
    imp = Imported(TOOL)
    if kind == "breach_list":
        n = _breach_edges(ctx, imp, data, None, "lista wycieków")
        imp.runs.append(("breaches", Status.FOUND if n else Status.ERROR, "" if n else "żaden wyciek nie był czytelny"))
    elif kind == "monitor":
        for d in data["domains"]:
            dom = _domain(ctx, d.get("domain"))
            if dom is None:
                imp.runs.append((str(d.get("domain"))[:60], Status.ERROR, "nieprawidłowa domena"))
                continue
            total = d.get("total_breaches")
            if isinstance(total, int) and not isinstance(total, bool):
                dom.attrs["hibp_breach_total"] = total
            if d.get("first_run") is True:
                dom.attrs["hibp_baseline_run"] = True
            imp.nodes.append(dom)
            explicit_zero = (isinstance(total, int) and not isinstance(total, bool) and total == 0
                             and isinstance(d.get("new"), list))
            new = d.get("new") if isinstance(d.get("new"), list) else []
            n = _breach_edges(ctx, imp, new, dom, "wynik monitora domeny")
            has = bool(n or total)
            if has:
                imp.runs.append((dom.id, Status.FOUND, ""))
            elif explicit_zero:
                imp.runs.append((dom.id, Status.NOT_FOUND, "hibp-monitor: brak wycieków źródłowych dla domeny"))
            else:
                imp.runs.append((dom.id, Status.UNKNOWN, "hibp-monitor: wpis częściowy (brak total_breaches/new), brak rozstrzygnięcia"))
    else:  # domain_search
        dom = _domain(ctx, data.get("domain"))
        if dom is None:
            return failed(TOOL, "nieprawidłowa domena w wyniku domain-search")
        if isinstance(data.get("total_accounts"), int):
            dom.attrs["hibp_total_accounts"] = data["total_accounts"]
        imp.nodes.append(dom)
        per = data.get("per_breach") if isinstance(data.get("per_breach"), dict) else {}
        breach_nodes: dict[str, Node] = {}
        for name, count in list(per.items())[:MAX_BREACHES]:
            node = breach_node(ctx, {"Name": name})
            if node is None:
                continue
            breach_nodes[str(name)] = node
            imp.nodes.append(node)
            imp.edges.append(ctx.edge("", dom, node, "accounts_in_breach", 1.0,
                                      f"hibp-monitor domain-search: {count if isinstance(count, int) else '?'} kont z domeny "
                                      f"{dom.value} w wycieku {name}"))
        addresses = data.get("addresses") if isinstance(data.get("addresses"), dict) else {}
        for addr, names in list(addresses.items())[:MAX_ADDRESSES]:
            try:
                email = ctx.node(EntityType.EMAIL, str(addr))
            except ValueError:
                continue
            imp.nodes.append(email)
            for name in names if isinstance(names, list) else []:
                b = breach_nodes.get(str(name)) or breach_node(ctx, {"Name": name})
                if b is None:
                    continue
                imp.nodes.append(b)
                imp.edges.append(ctx.edge("", email, b, "appears_in_breach", 1.0,
                                          f"hibp-monitor domain-search: adres w wycieku {name}"))
        total_accounts = data.get("total_accounts")
        has = bool(per or total_accounts)
        if has:
            imp.runs.append((dom.id, Status.FOUND, ""))
        elif isinstance(total_accounts, int) and not isinstance(total_accounts, bool) and isinstance(data.get("per_breach"), dict):
            imp.runs.append((dom.id, Status.NOT_FOUND, "brak kont domeny w wyciekach"))
        else:
            imp.runs.append((dom.id, Status.UNKNOWN, "wynik domain-search niepełny (brak total_accounts/per_breach), brak rozstrzygnięcia"))
    return imp
