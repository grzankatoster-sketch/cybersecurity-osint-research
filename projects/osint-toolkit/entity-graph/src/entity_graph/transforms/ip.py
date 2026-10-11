"""Transformacje IP: RDAP (rdap.org, zapas RIPE), ASN i prefiks (RIPEstat), reverse DNS, Shodan InternetDB.

Lokalizacja: tylko to, co publicznie podaje RDAP/ASN (organizacja, kraj rejestru). Żadnej geolokalizacji osoby.
"""
from __future__ import annotations

import json
import socket
import threading
from urllib.parse import quote, urlencode

from ..http import classify_http
from ..model import Node, Status
from ..normalize import EntityType, is_public_ip, normalize_domain
from .base import Context, TransformResult, register

SKIP_NOTE_PRIVATE = "adres nie jest publiczny (prywatny/zarezerwowany): pominięto zapytania do baz publicznych"


# ---------------------------------------------------------------- RDAP (czyste parsowanie)

def vcard_fields(entity: dict) -> dict:
    arr = entity.get("vcardArray")
    out: dict = {}
    if isinstance(arr, list) and len(arr) > 1 and isinstance(arr[1], list):
        for item in arr[1]:
            if isinstance(item, list) and len(item) >= 4 and isinstance(item[0], str):
                out.setdefault(item[0], item[3])
    return out


def iter_entities(data: dict, depth: int = 3):
    for ent in data.get("entities") or []:
        if isinstance(ent, dict):
            yield ent
            if depth > 1:
                yield from iter_entities(ent, depth - 1)


def org_entities(data: dict, roles: tuple[str, ...] | None = None) -> list[tuple[str, list[str]]]:
    """(nazwa organizacji, role) tylko dla jednostek typu org/group. Osoby fizyczne (kind=individual) są
    pomijane celowo: minimalizacja danych, nie zbieramy danych kontaktowych osób."""
    out = []
    for ent in iter_entities(data):
        fields = vcard_fields(ent)
        name = fields.get("fn")
        kind = str(fields.get("kind", "")).lower()
        entity_roles = [str(r) for r in ent.get("roles") or []]
        if not isinstance(name, str) or not name.strip() or kind not in ("org", "group"):
            continue
        if roles and not set(roles) & set(entity_roles):
            continue
        out.append((name.strip(), entity_roles))
    return out


def event_date(data: dict, action: str) -> str | None:
    for ev in data.get("events") or []:
        if isinstance(ev, dict) and ev.get("eventAction") == action and ev.get("eventDate"):
            return str(ev["eventDate"])
    return None


def parse_rdap_ip(data: dict) -> dict:
    """-> {name, country, handle, start, end, cidrs, orgs, registered}"""
    cidrs = []
    for c in data.get("cidr0_cidrs") or []:
        if isinstance(c, dict):
            prefix = c.get("v4prefix") or c.get("v6prefix")
            if prefix and c.get("length") is not None:
                cidrs.append(f"{prefix}/{c['length']}")
    return {
        "name": data.get("name"), "country": data.get("country"), "handle": data.get("handle"),
        "start": data.get("startAddress"), "end": data.get("endAddress"), "cidrs": cidrs,
        "orgs": org_entities(data), "registered": event_date(data, "registration"),
    }


def _load_json(text: str):
    try:
        return json.loads(text)
    except (json.JSONDecodeError, ValueError):
        return None


@register("ip_rdap", (EntityType.IP,), "RDAP: sieć, kraj rejestru i organizacja (rdap.org, zapas RIPE)")
def ip_rdap(node: Node, ctx: Context) -> TransformResult:
    ip = node.key
    if not is_public_ip(ip):
        return TransformResult.failed(Status.UNKNOWN, SKIP_NOTE_PRIVATE)
    reasons = []
    for key in ("rdap_ip", "rdap_ip_ripe"):
        resp = ctx.fetch.get(ctx.endpoints[key] + quote(ip, safe=""), {"Accept": "application/rdap+json"})
        status, reason = classify_http(resp)
        if status is Status.NOT_FOUND:
            return TransformResult(Status.NOT_FOUND, note=f"RDAP: brak rekordu dla {ip}")
        if status is None:
            data = _load_json(resp.text)
            if isinstance(data, dict):
                return _rdap_ip_result(node, ctx, parse_rdap_ip(data), key)
            reason = "odpowiedź RDAP nie jest obiektem JSON"
            status = Status.ERROR
        reasons.append(f"{key}: {reason}")
    return TransformResult.failed(Status.ERROR, "; ".join(reasons))


def _rdap_ip_result(node: Node, ctx: Context, p: dict, endpoint: str) -> TransformResult:
    attrs = {k: v for k, v in {
        "rdap_netname": p["name"], "rdap_country": p["country"], "rdap_range": (
            f"{p['start']} - {p['end']}" if p["start"] and p["end"] else None),
        "rdap_cidrs": p["cidrs"], "rdap_registered": p["registered"],
    }.items() if v}
    res = TransformResult(Status.FOUND, node_attrs=attrs, note=f"RDAP ({endpoint})")
    for org_name, roles in p["orgs"][:5]:
        org = Node.make(EntityType.ORGANIZATION, org_name, {"kind": "rdap_org"}, "ip_rdap")
        res.nodes.append(org)
        owner = "registrant" in roles
        # tylko rejestrant to właściciel przydziału; techniczny/abuse/administracyjny to kontakt (słabszy dowód)
        res.edges.append(ctx.edge("ip_rdap", node, org, "allocated_to" if owner else "contact_org", 0.9 if owner else 0.6,
                                  f"RDAP: sieć {p['handle'] or p['name'] or '?'} ({', '.join(roles) or 'rola n/d'}), "
                                  f"kraj rejestru: {p['country'] or 'n/d'}"))
    if not p["orgs"]:
        res.note += "; brak organizacji w RDAP (dane ukryte lub tylko osoby)"
    return res


# ---------------------------------------------------------------- RIPEstat: ASN i prefiks

def parse_ripestat(data: dict) -> dict | None:
    """-> {announced, prefix, asns:[(asn, holder)], block} albo None gdy status != ok."""
    if not isinstance(data, dict) or data.get("status") != "ok" or not isinstance(data.get("data"), dict):
        return None
    d = data["data"]
    asns = []
    for a in d.get("asns") or []:
        if isinstance(a, dict) and a.get("asn") is not None:
            asns.append((f"AS{a['asn']}", str(a.get("holder") or "").strip()))
    block = d.get("block") if isinstance(d.get("block"), dict) else {}
    explicit_unannounced = d.get("announced") is False and isinstance(d.get("asns"), list) and not d["asns"]
    return {"announced": bool(d.get("announced")), "prefix": d.get("resource"), "asns": asns,
            "block": block.get("resource"), "explicit_unannounced": explicit_unannounced}


@register("ip_asn", (EntityType.IP,), "RIPEstat: numer ASN, operator ASN i prefiks BGP")
def ip_asn(node: Node, ctx: Context) -> TransformResult:
    ip = node.key
    if not is_public_ip(ip):
        return TransformResult.failed(Status.UNKNOWN, SKIP_NOTE_PRIVATE)
    url = ctx.endpoints["ripestat"] + "?" + urlencode({"resource": ip, "sourceapp": "entity-graph"})
    resp = ctx.fetch.get(url)
    status, reason = classify_http(resp, not_found_ok=False)
    if status is not None:
        return TransformResult.failed(status, reason)
    parsed = parse_ripestat(_load_json(resp.text))
    if parsed is None:
        return TransformResult.failed(Status.ERROR, "RIPEstat: status inny niż ok lub zły format odpowiedzi")
    if not parsed["asns"] and not parsed["explicit_unannounced"]:
        return TransformResult.failed(Status.ERROR, "RIPEstat: niepełna lub sprzeczna odpowiedź (asns/announced)")
    if not parsed["asns"]:
        # jawna odpowiedź: announced=false i pusta lista asns
        return TransformResult(Status.NOT_FOUND, note="RIPEstat: adres nie jest ogłaszany przez żaden ASN",
                               node_attrs={"announced": False})
    res = TransformResult(Status.FOUND, node_attrs={
        "bgp_prefix": parsed["prefix"], "asn": [a for a, _ in parsed["asns"]], "announced": parsed["announced"]})
    for asn, holder in parsed["asns"]:
        org = Node.make(EntityType.ORGANIZATION, holder or asn, {"kind": "asn_holder", "asn": [asn]}, "ip_asn")
        res.nodes.append(org)
        res.edges.append(ctx.edge("ip_asn", node, org, "announced_by", 0.95,
                                  f"RIPEstat prefix-overview: {asn} ogłasza {parsed['prefix']}"))
    return res


# ---------------------------------------------------------------- reverse DNS

def default_rdns(ip: str, timeout: float = 5.0) -> tuple[str | None, str | None]:
    """(nazwa, None) | (None, None) = jawny brak PTR | (None, błąd) = nie udało się sprawdzić."""
    box: dict = {}

    def work() -> None:
        try:
            box["name"] = socket.gethostbyaddr(ip)[0]
        except socket.herror as exc:
            # 1 = Unknown host, 11001/11004 = Windows: host nie znaleziony / brak danych (jawny brak PTR)
            code = exc.args[0] if exc.args else None
            if code in (1, 11001, 11004):
                box["missing"] = True
            else:
                box["err"] = f"herror {code}"
        except (socket.gaierror, OSError) as exc:
            box["err"] = f"{type(exc).__name__}"

    t = threading.Thread(target=work, daemon=True)
    t.start()
    t.join(timeout)
    if t.is_alive():
        return None, "timeout"
    if "name" in box:
        return box["name"], None
    return (None, None) if box.get("missing") else (None, box.get("err") or "błąd")


@register("ip_rdns", (EntityType.IP,), "Reverse DNS (PTR) systemowym resolverem")
def ip_rdns(node: Node, ctx: Context) -> TransformResult:
    ip = node.key
    if not is_public_ip(ip):
        return TransformResult.failed(Status.UNKNOWN, SKIP_NOTE_PRIVATE)
    name, err = (ctx.rdns or default_rdns)(ip)
    if err:
        return TransformResult.failed(Status.ERROR, f"reverse DNS: {err}")
    if not name:
        return TransformResult(Status.NOT_FOUND, note="brak rekordu PTR")
    try:
        host = Node.make(EntityType.DOMAIN, name, {"kind": "ptr_host"}, "ip_rdns")
    except ValueError:
        return TransformResult.failed(Status.ERROR, "PTR zwrócił nieprawidłową nazwę hosta")
    res = TransformResult(Status.FOUND, nodes=[host], node_attrs={"ptr": host.value})
    res.edges.append(ctx.edge("ip_rdns", node, host, "ptr", 0.9,
                              f"rekord PTR {ip} -> {host.value} (PTR bywa ustawiany dowolnie przez właściciela bloku)"))
    return res


# ---------------------------------------------------------------- Shodan InternetDB

def parse_internetdb(data: dict) -> dict | None:
    if not isinstance(data, dict) or "ip" not in data:
        return None

    def strs(key: str) -> list[str]:
        v = data.get(key)
        return [str(x) for x in v] if isinstance(v, list) else []

    return {"ports": sorted(int(p) for p in data.get("ports", []) if isinstance(p, int)),
            "cpes": strs("cpes"), "hostnames": strs("hostnames"), "tags": strs("tags"), "vulns": strs("vulns")}


@register("ip_internetdb", (EntityType.IP,), "Shodan InternetDB (bez klucza): otwarte porty, CPE, nazwy hostów")
def ip_internetdb(node: Node, ctx: Context) -> TransformResult:
    ip = node.key
    if not is_public_ip(ip):
        return TransformResult.failed(Status.UNKNOWN, SKIP_NOTE_PRIVATE)
    resp = ctx.fetch.get(ctx.endpoints["internetdb"] + quote(ip, safe=""))
    status, reason = classify_http(resp)
    if status is Status.NOT_FOUND:
        return TransformResult(Status.NOT_FOUND, note="InternetDB: brak danych o adresie (to nie dowód, że porty są zamknięte)")
    if status is not None:
        return TransformResult.failed(status, reason)
    parsed = parse_internetdb(_load_json(resp.text))
    if parsed is None:
        return TransformResult.failed(Status.ERROR, "InternetDB: zły format odpowiedzi")
    attrs = {"open_ports": parsed["ports"], "cpes": parsed["cpes"], "shodan_tags": parsed["tags"],
             "vulns_unverified": parsed["vulns"]}
    res = TransformResult(Status.FOUND, node_attrs={k: v for k, v in attrs.items() if v},
                          note="InternetDB to dane z cudzych skanów: bywają nieaktualne; CVE nie są weryfikowane",
                          stats={"ports": len(parsed["ports"]), "hostnames": len(parsed["hostnames"])})
    for hostname in parsed["hostnames"][:20]:
        try:
            host = Node.make(EntityType.DOMAIN, normalize_domain(hostname), {"kind": "shodan_hostname"}, "ip_internetdb")
        except ValueError:
            continue
        res.nodes.append(host)
        res.edges.append(ctx.edge("ip_internetdb", node, host, "hostname", 0.7,
                                  "InternetDB: nazwa hosta powiązana z adresem w danych Shodan"))
    return res
