"""Transformacje domeny: dns-audit (podproces), RDAP (rejestrator), crt.sh (subdomeny z Certificate Transparency)."""
from __future__ import annotations

import json
from urllib.parse import quote, urlencode

from .. import siblings
from ..http import classify_http
from ..model import Node, Status
from ..normalize import EntityType, normalize_domain, normalize_ip
from .base import Context, TransformResult, register
from .ip import event_date, iter_entities, vcard_fields

_DATA_KEYS = ("a", "aaaa", "ns", "soa", "mx", "txt")


# ---------------------------------------------------------------- dns-audit

def parse_dns_audit(report: dict) -> dict | None:
    """Wyciąga z JSON-a dns-audit to, co trafia do grafu. None, gdy to nie jest raport dns-audit."""
    summary = report.get("summary") if isinstance(report, dict) else None
    if not isinstance(summary, dict) or not any(k in summary for k in _DATA_KEYS):
        return None
    spf, dmarc = summary.get("spf") or {}, summary.get("dmarc") or {}
    dnssec = summary.get("dnssec") or {}
    return {
        "a": [x for x in summary.get("a") or [] if isinstance(x, str)],
        "aaaa": [x for x in summary.get("aaaa") or [] if isinstance(x, str)],
        "ns": [x.rstrip(".") for x in summary.get("ns") or [] if isinstance(x, str)],
        "mx": [m["host"] for m in summary.get("mx") or [] if isinstance(m, dict) and m.get("host")],
        "has_data": any(summary.get(k) for k in _DATA_KEYS),
        "failed": dict(summary.get("failed") or {}),
        "attrs": {k: v for k, v in {
            "spf_all": spf.get("all"), "dmarc_policy": dmarc.get("p"),
            "dnssec_signed": bool(dnssec.get("dnskey") and dnssec.get("ds")) if dnssec else None,
            "mail_providers": sorted({m["provider"] for m in summary.get("mx") or [] if m.get("provider")}),
            "site_verifications": sorted({v["service"] for v in summary.get("verifications") or [] if v.get("service")}),
            "dns_audit_counts": report.get("counts"),
        }.items() if v not in (None, [], {})},
    }


@register("dns_audit", (EntityType.DOMAIN,), "dns-audit (siostrzane): A/AAAA/NS/MX/SPF/DMARC/DNSSEC", network=True)
def dns_audit(node: Node, ctx: Context) -> TransformResult:
    try:
        out = siblings.run_sibling("dns-audit", [node.key, "--json", "--timeout", "4"], ctx.tools_dir,
                                   ctx.settings.sibling_timeout, ctx.runner)
    except siblings.SiblingUnavailable as exc:
        return TransformResult.failed(Status.UNKNOWN, f"dns-audit niedostępny: {exc}")
    except TimeoutError as exc:
        return TransformResult.failed(Status.ERROR, f"dns-audit: {exc}")
    if out.returncode != 0:
        return TransformResult.failed(Status.ERROR, f"dns-audit zakończył się kodem {out.returncode}: {out.stderr.strip()[:200]}")
    try:
        parsed = parse_dns_audit(json.loads(out.stdout))
    except json.JSONDecodeError:
        parsed = None
    if parsed is None:
        return TransformResult.failed(Status.ERROR, "dns-audit: zły format raportu dns-audit")
    return dns_result(node, parsed, ctx)


def dns_result(node: Node, parsed: dict, ctx: Context) -> TransformResult:
    """Wynik transformacji z sparsowanego raportu dns-audit (parse_dns_audit). Używane też przez importer plików."""
    if not parsed["has_data"]:
        if parsed["failed"]:
            return TransformResult.failed(Status.ERROR, "dns-audit: żadne zapytanie nie powiodło się: "
                                          + ", ".join(sorted(parsed["failed"])))
        return TransformResult(Status.NOT_FOUND, note="dns-audit: brak rekordów (domena nie istnieje lub pusta strefa)")
    res = TransformResult(Status.FOUND, node_attrs=parsed["attrs"], stats={"failed_queries": len(parsed["failed"])})
    if parsed["failed"]:
        res.note = "wynik częściowy, nie udało się sprawdzić: " + ", ".join(sorted(parsed["failed"]))
    for kind, relation, label in (("a", "resolves_to", "A"), ("aaaa", "resolves_to", "AAAA")):
        for raw in parsed[kind]:
            try:
                ip = Node.make(EntityType.IP, normalize_ip(raw), {}, "dns_audit")
            except ValueError:
                continue
            res.nodes.append(ip)
            res.edges.append(ctx.edge("dns_audit", node, ip, relation, 0.95, f"rekord {label} {node.key} -> {ip.value}"))
    for kind, relation, label in (("ns", "nameserver", "NS"), ("mx", "mail_exchanger", "MX")):
        for raw in parsed[kind][:20]:
            try:
                host = Node.make(EntityType.DOMAIN, raw, {"kind": f"{kind}_host"}, "dns_audit")
            except ValueError:
                continue
            if host.id == node.id:
                continue
            res.nodes.append(host)
            res.edges.append(ctx.edge("dns_audit", node, host, relation, 0.95, f"rekord {label} {node.key} -> {host.value}"))
    return res


# ---------------------------------------------------------------- RDAP domeny

def registrar_of(data: dict) -> str | None:
    for ent in iter_entities(data):
        if "registrar" in [str(r) for r in ent.get("roles") or []]:
            fields = vcard_fields(ent)
            name = fields.get("fn")
            if isinstance(name, str) and name.strip() and str(fields.get("kind", "")).lower() != "individual":
                return name.strip()
    return None


def parse_rdap_domain(data: dict) -> dict:
    return {
        "registrar": registrar_of(data),
        "registered": event_date(data, "registration"),
        "expires": event_date(data, "expiration"),
        "changed": event_date(data, "last changed"),
        "status": [str(s) for s in data.get("status") or []],
    }


@register("domain_rdap", (EntityType.DOMAIN,), "RDAP: rejestrator, daty rejestracji i wygaśnięcia (bez danych rejestranta)")
def domain_rdap(node: Node, ctx: Context) -> TransformResult:
    resp = ctx.fetch.get(ctx.endpoints["rdap_domain"] + quote(node.key, safe=""), {"Accept": "application/rdap+json"})
    status, reason = classify_http(resp)
    if status is Status.NOT_FOUND:
        # rdap.org odpowiada 404 także wtedy, gdy dla końcówki nie ma serwera RDAP w bootstrapie IANA: to nie dowód braku domeny
        return TransformResult.failed(Status.UNKNOWN, "RDAP 404: brak rekordu LUB brak serwera RDAP dla tej końcówki")
    if status is not None:
        return TransformResult.failed(status, reason)
    try:
        data = json.loads(resp.text)
    except json.JSONDecodeError:
        data = None
    if not isinstance(data, dict):
        return TransformResult.failed(Status.ERROR, "odpowiedź RDAP nie jest obiektem JSON")
    p = parse_rdap_domain(data)
    attrs = {k: v for k, v in {"rdap_registered": p["registered"], "rdap_expires": p["expires"],
                               "rdap_changed": p["changed"], "rdap_status": p["status"]}.items() if v}
    res = TransformResult(Status.FOUND, node_attrs=attrs,
                          note="dane rejestranta nie są zbierane (zwykle zredagowane, RODO)")
    if p["registrar"]:
        org = Node.make(EntityType.ORGANIZATION, p["registrar"], {"kind": "registrar"}, "domain_rdap")
        res.nodes.append(org)
        res.edges.append(ctx.edge("domain_rdap", node, org, "registered_via", 0.95,
                                  f"RDAP: rejestrator domeny {node.key}, rejestracja {p['registered'] or 'n/d'}"))
    return res


# ---------------------------------------------------------------- crt.sh

def parse_crtsh(entries: list, domain: str) -> dict[str, dict]:
    """-> {nazwa: {id, not_before, issuer}} dla nazw będących subdomenami `domain` (bez samej domeny)."""
    found: dict[str, dict] = {}
    for entry in entries:
        if not isinstance(entry, dict):
            continue
        for raw in str(entry.get("name_value") or "").splitlines():
            name = raw.strip().lower().removeprefix("*.")
            if "@" in name or not name.endswith("." + domain):
                continue
            try:
                name = normalize_domain(name)
            except ValueError:
                continue
            old = found.get(name)
            nb = str(entry.get("not_before") or "")
            if old is None or (nb and nb < old["not_before"]):
                found[name] = {"id": entry.get("id"), "not_before": nb, "issuer": str(entry.get("issuer_name") or "")[:80]}
    return found


@register("domain_crtsh", (EntityType.DOMAIN,), "crt.sh: subdomeny z Certificate Transparency (dane pasywne)")
def domain_crtsh(node: Node, ctx: Context) -> TransformResult:
    url = ctx.endpoints["crtsh"] + "?" + urlencode({"q": f"%.{node.key}", "output": "json"})
    resp = ctx.fetch.get(url)
    status, reason = classify_http(resp, not_found_ok=False)
    if status is not None:
        return TransformResult.failed(status, "crt.sh: " + reason)
    try:
        entries = json.loads(resp.text)
    except json.JSONDecodeError:
        entries = None
    if not isinstance(entries, list):
        return TransformResult.failed(Status.ERROR, "crt.sh: odpowiedź nie jest listą JSON (serwis bywa przeciążony)")
    subs = parse_crtsh(entries, node.key)
    if not subs:
        return TransformResult(Status.NOT_FOUND, note="crt.sh: brak certyfikatów z subdomenami tej domeny")
    names = sorted(subs)
    cap = ctx.settings.max_subdomains
    res = TransformResult(Status.FOUND, stats={"subdomains": len(names), "kept": min(len(names), cap)},
                          node_attrs={"ct_subdomain_count": len(names)})
    if len(names) > cap:
        res.note = f"ucięto do {cap} z {len(names)} subdomen (--max-subdomains)"
    for name in names[:cap]:
        info = subs[name]
        sub = Node.make(EntityType.DOMAIN, name, {"kind": "subdomain"}, "domain_crtsh")
        res.nodes.append(sub)
        res.edges.append(ctx.edge("domain_crtsh", node, sub, "has_subdomain", 0.9,
                                  f"crt.sh: certyfikat #{info['id']} (od {info['not_before'][:10] or 'n/d'}) zawiera nazwę {name}; "
                                  "obecność w certyfikacie nie dowodzi, że host działa"))
    return res
